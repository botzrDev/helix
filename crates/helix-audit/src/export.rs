//! `OTel` tail exporter (M3-03 / HLX-20, ADR-005).
//!
//! A separate task tails the audit log directory across rotations, groups
//! records by `request_id`, and emits **one `OTel` span per invocation** with
//! **one event per transition**. Export loss / backpressure never touches the
//! store; lag is reported as `helix_audit_export_lag_records`.
//!
//! ## Task ownership (ST-2)
//!
//! `helix-runtime::spawn_cancellable` is the sole `tokio::spawn` site (HLX-28).
//! This exporter remains owned via [`tokio::task::JoinSet`] (not bare
//! `tokio::spawn`) — `JoinSet` ownership satisfies ST-2 / ADR-003 without a
//! runtime→audit dependency edge.
//!
//! ## Witness hook (HLX-22 / M3-05)
//!
//! Witness spans named [`WITNESS_SPAN_NAME`] (`helix.audit.witness`) are emitted
//! by M3-05 through [`ExportSink::export_witness`]. This crate only defines the
//! hook; it does not produce witnesses.

use crate::frame::{decode_frame, FrameError};
use crate::header::FileHeader;
use crate::json_out::transition_name;
use crate::naming::{encode_ulid_bytes, hex_encode, parse_log_file_name};
use crate::record::{AuditRecord, Transition};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer, TracerProvider as _};
use opentelemetry::{KeyValue, Value};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, Notify, RwLock};
use tokio::task::JoinSet;

/// `OTel` span name for one invocation (all transitions as events).
pub const INVOCATION_SPAN_NAME: &str = "helix.audit.invocation";

/// Reserved span name for witness emission (HLX-22 / M3-05).
pub const WITNESS_SPAN_NAME: &str = "helix.audit.witness";

const LAG_GAUGE: &str = "helix_audit_export_lag_records";
const DEFAULT_POLL: Duration = Duration::from_millis(50);

/// One transition event attached to an invocation span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedEvent {
    pub transition: Transition,
    pub reason: String,
    pub wall_time_ns: u64,
    pub sequence: u64,
    pub caps_hash: Option<[u8; 32]>,
}

/// One invocation span ready for export (terminal transition observed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedInvocation {
    pub request_id: [u8; 16],
    pub parent: Option<[u8; 16]>,
    pub identity: [u8; 32],
    pub digest: [u8; 32],
    pub events: Vec<ExportedEvent>,
    pub start_time_ns: u64,
    pub end_time_ns: u64,
    pub terminal: Transition,
}

/// Attributes for a future `helix.audit.witness` span (HLX-22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessAttrs {
    pub gateway_id: String,
    pub file_ulid: [u8; 16],
    pub sequence: u64,
    pub head_hash: [u8; 32],
    pub wall_time_ns: u64,
}

/// Sink that receives grouped invocation spans (and optional witness hooks).
pub trait ExportSink: Send + Sync + 'static {
    fn export_invocation(
        &self,
        inv: ExportedInvocation,
    ) -> impl std::future::Future<Output = Result<(), ExportError>> + Send;

    /// Hook for M3-05 / HLX-22 witness spans. Default: no-op success.
    fn export_witness(
        &self,
        _attrs: WitnessAttrs,
    ) -> impl std::future::Future<Output = Result<(), ExportError>> + Send {
        async { Ok(()) }
    }
}

/// In-memory sink for tests; supports pause (AUD-4 blocking sink).
#[derive(Clone)]
pub struct RecordingSink {
    inner: Arc<RecordingInner>,
}

struct RecordingInner {
    paused: AtomicBool,
    resume: Notify,
    invocations: RwLock<Vec<ExportedInvocation>>,
    witnesses: RwLock<Vec<WitnessAttrs>>,
    /// Artificial delay applied while not paused (optional).
    export_delay: RwLock<Duration>,
}

impl Default for RecordingSink {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingSink {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RecordingInner {
                paused: AtomicBool::new(false),
                resume: Notify::new(),
                invocations: RwLock::new(Vec::new()),
                witnesses: RwLock::new(Vec::new()),
                export_delay: RwLock::new(Duration::ZERO),
            }),
        }
    }

    pub fn pause(&self) {
        self.inner.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.inner.paused.store(false, Ordering::SeqCst);
        self.inner.resume.notify_waiters();
    }

    pub async fn set_export_delay(&self, d: Duration) {
        *self.inner.export_delay.write().await = d;
    }

    pub async fn invocations(&self) -> Vec<ExportedInvocation> {
        self.inner.invocations.read().await.clone()
    }

    pub async fn invocation_count(&self) -> usize {
        self.inner.invocations.read().await.len()
    }

    pub async fn witnesses(&self) -> Vec<WitnessAttrs> {
        self.inner.witnesses.read().await.clone()
    }

    pub async fn witness_count(&self) -> usize {
        self.inner.witnesses.read().await.len()
    }

    pub async fn wait_until_invocations(&self, n: usize, timeout: Duration) -> bool {
        let start = tokio::time::Instant::now();
        loop {
            if self.invocation_count().await >= n {
                return true;
            }
            if start.elapsed() > timeout {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl ExportSink for RecordingSink {
    async fn export_invocation(&self, inv: ExportedInvocation) -> Result<(), ExportError> {
        while self.inner.paused.load(Ordering::SeqCst) {
            self.inner.resume.notified().await;
        }
        let delay = *self.inner.export_delay.read().await;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.inner.invocations.write().await.push(inv);
        Ok(())
    }

    async fn export_witness(&self, attrs: WitnessAttrs) -> Result<(), ExportError> {
        while self.inner.paused.load(Ordering::SeqCst) {
            self.inner.resume.notified().await;
        }
        self.inner.witnesses.write().await.push(attrs);
        Ok(())
    }
}

/// `OTel` SDK sink: one span per invocation, events per transition, via OTLP.
pub struct OtelExportSink {
    tracer: opentelemetry_sdk::trace::Tracer,
    /// Keep provider alive for the sink lifetime.
    _provider: SdkTracerProvider,
}

impl OtelExportSink {
    /// Install a gRPC OTLP exporter targeting `endpoint` (e.g. `http://collector:4317`).
    pub fn connect(endpoint: impl AsRef<str>) -> Result<Self, ExportError> {
        let endpoint = endpoint.as_ref().to_owned();
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| ExportError::Otlp(e.to_string()))?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .build();
        let tracer = provider.tracer("helix-audit");
        Ok(Self {
            tracer,
            _provider: provider,
        })
    }
}

impl ExportSink for OtelExportSink {
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn export_invocation(&self, inv: ExportedInvocation) -> Result<(), ExportError> {
        // SDK span start/end is sync; run on this task (exporter batch is async).
        let mut span = self
            .tracer
            .span_builder(INVOCATION_SPAN_NAME)
            .with_kind(SpanKind::Internal)
            .start(&self.tracer);
        span.set_attribute(KeyValue::new(
            "helix.request_id",
            Value::String(encode_ulid_bytes(&inv.request_id).into()),
        ));
        span.set_attribute(KeyValue::new(
            "helix.identity",
            Value::String(hex_encode(&inv.identity).into()),
        ));
        span.set_attribute(KeyValue::new(
            "helix.digest",
            Value::String(hex_encode(&inv.digest).into()),
        ));
        if let Some(p) = &inv.parent {
            span.set_attribute(KeyValue::new(
                "helix.parent_request_id",
                Value::String(encode_ulid_bytes(p).into()),
            ));
        }
        span.set_attribute(KeyValue::new(
            "helix.terminal",
            Value::String(transition_name(inv.terminal).into()),
        ));
        for ev in &inv.events {
            let mut attrs = vec![
                KeyValue::new(
                    "helix.transition",
                    Value::String(transition_name(ev.transition).into()),
                ),
                KeyValue::new(
                    "helix.sequence",
                    i64::try_from(ev.sequence).unwrap_or(i64::MAX),
                ),
                KeyValue::new(
                    "helix.wall_time_ns",
                    i64::try_from(ev.wall_time_ns).unwrap_or(i64::MAX),
                ),
            ];
            if !ev.reason.is_empty() {
                attrs.push(KeyValue::new(
                    "helix.reason",
                    Value::String(ev.reason.clone().into()),
                ));
            }
            if let Some(h) = &ev.caps_hash {
                attrs.push(KeyValue::new(
                    "helix.caps_hash",
                    Value::String(hex_encode(h).into()),
                ));
            }
            span.add_event(transition_name(ev.transition), attrs);
        }
        match inv.terminal {
            Transition::Completed | Transition::Described => span.set_status(Status::Ok),
            Transition::Failed
            | Transition::ToolError
            | Transition::Killed
            | Transition::AuthFailed
            | Transition::Rejected
            | Transition::Denied
            | Transition::DelegationRefused => {
                span.set_status(Status::error(transition_name(inv.terminal)));
            }
            _ => {}
        }
        span.end();
        Ok(())
    }

    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn export_witness(&self, attrs: WitnessAttrs) -> Result<(), ExportError> {
        // Hook only: M3-05 will call this. Emit the named span shape now so the
        // pipeline is ready; producers are HLX-22.
        let mut span = self
            .tracer
            .span_builder(WITNESS_SPAN_NAME)
            .with_kind(SpanKind::Internal)
            .start(&self.tracer);
        span.set_attribute(KeyValue::new(
            "helix.gateway_id",
            Value::String(attrs.gateway_id.into()),
        ));
        span.set_attribute(KeyValue::new(
            "helix.file_ulid",
            Value::String(encode_ulid_bytes(&attrs.file_ulid).into()),
        ));
        span.set_attribute(KeyValue::new(
            "helix.sequence",
            i64::try_from(attrs.sequence).unwrap_or(i64::MAX),
        ));
        span.set_attribute(KeyValue::new(
            "helix.head_hash",
            Value::String(hex_encode(&attrs.head_hash).into()),
        ));
        span.set_attribute(KeyValue::new(
            "helix.wall_time_ns",
            i64::try_from(attrs.wall_time_ns).unwrap_or(i64::MAX),
        ));
        span.end();
        Ok(())
    }
}

/// Shared lag counter / control for the exporter runtime.
#[derive(Clone, Debug, Default)]
pub struct ExportMetrics {
    /// Records observed by the tailer but not yet successfully exported.
    lag: Arc<AtomicU64>,
    seen: Arc<AtomicU64>,
    exported: Arc<AtomicU64>,
}

impl ExportMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn lag(&self) -> u64 {
        self.lag.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn seen(&self) -> u64 {
        self.seen.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn exported(&self) -> u64 {
        self.exported.load(Ordering::SeqCst)
    }

    fn record_seen(&self, n: u64) {
        self.seen.fetch_add(n, Ordering::SeqCst);
        self.refresh_lag();
    }

    fn record_exported(&self, n: u64) {
        self.exported.fetch_add(n, Ordering::SeqCst);
        self.refresh_lag();
    }

    fn refresh_lag(&self) {
        let seen = self.seen.load(Ordering::SeqCst);
        let exported = self.exported.load(Ordering::SeqCst);
        let lag = seen.saturating_sub(exported);
        self.lag.store(lag, Ordering::SeqCst);
        #[allow(clippy::cast_precision_loss)]
        metrics::gauge!(LAG_GAUGE).set(lag as f64);
    }
}

/// Owns the exporter tasks via [`JoinSet`] (not bare `tokio::spawn`).
///
/// Two tasks share the set: a **tailer** that only reads the store, and an
/// **emitter** that calls the sink. A stalled sink therefore never blocks the
/// tailer; lag grows while the store continues to accept writes.
#[derive(Debug)]
pub struct AuditExporterRuntime {
    join: JoinSet<Result<(), ExportError>>,
    metrics: ExportMetrics,
    stop: Arc<AtomicBool>,
}

impl AuditExporterRuntime {
    /// Start tailing `dir` and exporting through `sink`.
    pub fn start<S: ExportSink>(dir: impl Into<PathBuf>, sink: Arc<S>) -> Self {
        Self::start_with_poll(dir, sink, DEFAULT_POLL)
    }

    pub fn start_with_poll<S: ExportSink>(
        dir: impl Into<PathBuf>,
        sink: Arc<S>,
        poll: Duration,
    ) -> Self {
        let dir = dir.into();
        let metrics = ExportMetrics::new();
        let stop = Arc::new(AtomicBool::new(false));
        let mut join = JoinSet::new();
        // Unbounded: under backpressure we buffer in-process rather than apply
        // pressure to the durable store (ADR-005). Dropping is a sink concern.
        let (tx, rx) = mpsc::unbounded_channel::<(ExportedInvocation, u64)>();

        let metrics_tail = metrics.clone();
        let stop_tail = Arc::clone(&stop);
        join.spawn(async move { tail_loop(dir, tx, metrics_tail, stop_tail, poll).await });

        let metrics_emit = metrics.clone();
        let stop_emit = Arc::clone(&stop);
        join.spawn(async move { emit_loop(rx, sink, metrics_emit, stop_emit).await });

        Self {
            join,
            metrics,
            stop,
        }
    }

    #[must_use]
    pub fn metrics(&self) -> ExportMetrics {
        self.metrics.clone()
    }

    /// Signal both tasks to exit, then await them.
    pub async fn shutdown(mut self) -> Result<(), ExportError> {
        self.stop.store(true, Ordering::SeqCst);
        let mut first_err = None;
        while let Some(res) = self.join.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(ExportError::Join(e.to_string()));
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

async fn emit_loop<S: ExportSink>(
    mut rx: mpsc::UnboundedReceiver<(ExportedInvocation, u64)>,
    sink: Arc<S>,
    metrics: ExportMetrics,
    stop: Arc<AtomicBool>,
) -> Result<(), ExportError> {
    loop {
        if stop.load(Ordering::SeqCst) {
            while let Ok((inv, n_events)) = rx.try_recv() {
                sink.export_invocation(inv).await?;
                metrics.record_exported(n_events);
            }
            return Ok(());
        }
        match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Ok(Some((inv, n_events))) => {
                sink.export_invocation(inv).await?;
                metrics.record_exported(n_events);
            }
            Ok(None) => return Ok(()),
            Err(_) => {
                // Poll timeout: re-check stop.
            }
        }
    }
}

async fn tail_loop(
    dir: PathBuf,
    tx: mpsc::UnboundedSender<(ExportedInvocation, u64)>,
    metrics: ExportMetrics,
    stop: Arc<AtomicBool>,
    poll: Duration,
) -> Result<(), ExportError> {
    let mut open: HashMap<[u8; 16], OpenInvocation> = HashMap::new();
    let mut cursor: Option<FileCursor> = None;

    while !stop.load(Ordering::SeqCst) {
        let logs = list_log_files_sorted(&dir)?;
        if logs.is_empty() {
            tokio::time::sleep(poll).await;
            continue;
        }

        if cursor.is_none() {
            cursor = Some(FileCursor::open(&logs[0].0));
        }

        let Some(cur) = cursor.as_mut() else {
            unreachable!("cursor set above");
        };

        let progressed = cur.read_available(&mut open, &tx, &metrics)?;
        if !progressed {
            if let Some(next) = successor_path(&logs, &cur.path) {
                let len = tokio::fs::metadata(&cur.path).await.map_or(0, |m| m.len());
                if cur.offset >= len {
                    *cur = FileCursor::open(&next);
                    continue;
                }
            }
            tokio::time::sleep(poll).await;
        }
    }
    Ok(())
}

fn successor_path(logs: &[(PathBuf, String)], current: &Path) -> Option<PathBuf> {
    let idx = logs.iter().position(|(p, _)| p == current)?;
    logs.get(idx + 1).map(|(p, _)| p.clone())
}

fn list_log_files_sorted(dir: &Path) -> Result<Vec<(PathBuf, String)>, ExportError> {
    let mut out = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(ExportError::Io(e)),
    };
    for ent in read {
        let ent = ent.map_err(ExportError::Io)?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if parse_log_file_name(name).is_some() {
            out.push((ent.path(), name.to_owned()));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

struct OpenInvocation {
    parent: Option<[u8; 16]>,
    identity: [u8; 32],
    digest: [u8; 32],
    events: Vec<ExportedEvent>,
    start_time_ns: u64,
}

struct FileCursor {
    path: PathBuf,
    offset: u64,
    header_done: bool,
}

impl FileCursor {
    fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            offset: 0,
            header_done: false,
        }
    }

    /// Read newly appended bytes. Returns true if any frame was consumed.
    fn read_available(
        &mut self,
        open: &mut HashMap<[u8; 16], OpenInvocation>,
        tx: &mpsc::UnboundedSender<(ExportedInvocation, u64)>,
        metrics: &ExportMetrics,
    ) -> Result<bool, ExportError> {
        let bytes = std::fs::read(&self.path).map_err(ExportError::Io)?;
        if bytes.is_empty() {
            return Ok(false);
        }
        let mut offset = usize::try_from(self.offset).unwrap_or(usize::MAX);
        if offset > bytes.len() {
            offset = 0;
            self.header_done = false;
        }
        if !self.header_done {
            match FileHeader::decode_cbor(&bytes) {
                Ok((_hdr, hdr_len)) => {
                    offset = hdr_len;
                    self.header_done = true;
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }

        let mut progressed = false;
        while offset < bytes.len() {
            match decode_frame(&bytes[offset..]) {
                Ok((frame, consumed)) => {
                    offset += consumed;
                    progressed = true;
                    metrics.record_seen(1);
                    handle_record(&frame.record, open, tx)?;
                }
                Err(FrameError::Truncated) => break,
                Err(e) => return Err(ExportError::Frame(e)),
            }
        }
        self.offset = u64::try_from(offset).unwrap_or(u64::MAX);
        Ok(progressed)
    }
}

fn handle_record(
    rec: &AuditRecord,
    open: &mut HashMap<[u8; 16], OpenInvocation>,
    tx: &mpsc::UnboundedSender<(ExportedInvocation, u64)>,
) -> Result<(), ExportError> {
    let event = ExportedEvent {
        transition: rec.transition,
        reason: rec.reason.clone(),
        wall_time_ns: rec.wall_time_ns,
        sequence: rec.sequence,
        caps_hash: rec.caps_hash,
    };

    let entry = open
        .entry(rec.request_id)
        .or_insert_with(|| OpenInvocation {
            parent: rec.parent,
            identity: rec.identity,
            digest: rec.digest,
            events: Vec::new(),
            start_time_ns: rec.wall_time_ns,
        });
    if entry.events.is_empty() {
        entry.parent = rec.parent;
        entry.identity = rec.identity;
        entry.digest = rec.digest;
        entry.start_time_ns = rec.wall_time_ns;
    }
    entry.events.push(event);

    if is_terminal(rec.transition) {
        let inv_state = open.remove(&rec.request_id).expect("just inserted/updated");
        let n_events = u64::try_from(inv_state.events.len()).unwrap_or(u64::MAX);
        let inv = ExportedInvocation {
            request_id: rec.request_id,
            parent: inv_state.parent,
            identity: inv_state.identity,
            digest: inv_state.digest,
            start_time_ns: inv_state.start_time_ns,
            end_time_ns: rec.wall_time_ns,
            terminal: rec.transition,
            events: inv_state.events,
        };
        // Channel send is non-blocking (unbounded). Emitter may be stalled.
        tx.send((inv, n_events))
            .map_err(|_| ExportError::ChannelClosed)?;
    }
    Ok(())
}

fn is_terminal(t: Transition) -> bool {
    matches!(
        t,
        Transition::Completed
            | Transition::Failed
            | Transition::ToolError
            | Transition::Killed
            | Transition::AuthFailed
            | Transition::Rejected
            | Transition::Denied
            | Transition::DelegationRefused
            | Transition::Described
    )
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("otlp: {0}")]
    Otlp(String),
    #[error("exporter task join: {0}")]
    Join(String),
    #[error("exporter channel closed")]
    ChannelClosed,
}

#[cfg(test)]
mod grouping_tests {
    use super::is_terminal;
    use crate::record::Transition;

    #[test]
    fn terminal_set_covers_state_machine_exits() {
        assert!(is_terminal(Transition::Completed));
        assert!(is_terminal(Transition::Failed));
        assert!(!is_terminal(Transition::Granted));
        assert!(!is_terminal(Transition::Running));
    }
}
