//! Group-commit audit writer with optional size-based rotation (ADR-008 D.1).
//!
//! # Fail-closed sync contract (ADR-008 D.3 / HLX-23)
//!
//! [`AuditWriter::sync`] returns [`Result<(), AuditError>`] and **must** be
//! `await`ed by callers before component instantiation and before any terminal
//! response. On `Err`:
//! - do **not** instantiate (Authorized / audit write fails → gateway `-32030`);
//! - discard tool output on terminal sync failure (caller's duty).
//!
//! Gateway JSON-RPC `-32030` wiring is M5-05 / HLX-36; see [`AuditError::GATEWAY_CODE`].

use crate::fail_closed::{AuditHealth, FailClosedConfig};
use crate::frame::{encode_frame, HASH_LEN};
use crate::header::FileHeader;
use crate::hook::{NoopSyncHook, SyncHook};
use crate::naming::log_file_name;
use crate::record::AuditRecord;
use crate::tags::GENESIS_PREV_HASH;
use crate::witness::Witness;
use crate::witness_sink::WitnessHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

const DEFAULT_CHANNEL_CAP: usize = 1024;

struct WriteReq {
    /// Record fields excluding `sequence` (writer assigns it).
    record: AuditRecord,
    /// `Some` for synced transitions; `None` for fire-and-forget.
    waiter: Option<oneshot::Sender<Result<WriteReceipt, AuditError>>>,
}

/// Receipt after a synced (or observed) write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteReceipt {
    pub sequence: u64,
    /// Sync stamp from the injectable hook at the moment this batch completed.
    pub sync_stamp: u64,
}

/// Handle for submitting records to the single writer task.
#[derive(Clone, Debug)]
pub struct AuditWriter {
    tx: mpsc::Sender<WriteReq>,
    health: Arc<AtomicU8>,
}

/// Owns the writer task (`JoinSet`) so `tokio::spawn` is never used bare
/// (clippy.toml / ADR-003).
#[derive(Debug)]
pub struct AuditWriterRuntime {
    writer: AuditWriter,
    join: JoinSet<Result<(), AuditError>>,
}

/// How the writer chooses the next file ULID (tests inject a counter).
pub type UlidSource = Box<dyn FnMut() -> [u8; 16] + Send>;

/// Default ULID source: millisecond timestamp in the high 48 bits plus a
/// monotonic counter in the low bits. Sufficient for log file naming order.
#[must_use]
pub fn default_ulid_source() -> UlidSource {
    let mut counter: u64 = 0;
    Box::new(move || {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        counter = counter.wrapping_add(1);
        let mut bytes = [0u8; 16];
        // 48-bit timestamp (ms).
        bytes[0] = ((millis >> 40) & 0xff) as u8;
        bytes[1] = ((millis >> 32) & 0xff) as u8;
        bytes[2] = ((millis >> 24) & 0xff) as u8;
        bytes[3] = ((millis >> 16) & 0xff) as u8;
        bytes[4] = ((millis >> 8) & 0xff) as u8;
        bytes[5] = (millis & 0xff) as u8;
        // 80-bit counter / uniqueness (big-endian in remaining bytes).
        for i in 0..8 {
            bytes[8 + i] = ((counter >> (8 * (7 - i))) & 0xff) as u8;
        }
        // Fold high counter bits into bytes 6–7.
        bytes[6] = ((counter >> 56) & 0xff) as u8;
        bytes[7] = ((counter >> 48) & 0xff) as u8;
        bytes
    })
}

fn new_health() -> Arc<AtomicU8> {
    Arc::new(AtomicU8::new(AuditHealth::Ok.to_u8()))
}

impl AuditWriterRuntime {
    /// Open (create) `path`, write header, start the writer task on a `JoinSet`.
    pub async fn open(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        prev_hash: [u8; HASH_LEN],
    ) -> Result<Self, AuditError> {
        Self::open_with_hook(
            path,
            gateway_id,
            file_ulid,
            prev_hash,
            Arc::new(NoopSyncHook),
            DEFAULT_CHANNEL_CAP,
        )
        .await
    }

    /// Same as [`Self::open`] with an injectable [`SyncHook`] (AUD-8).
    pub async fn open_with_hook(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        prev_hash: [u8; HASH_LEN],
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
    ) -> Result<Self, AuditError> {
        Self::open_with_hook_fail_closed(
            path,
            gateway_id,
            file_ulid,
            prev_hash,
            hook,
            channel_cap,
            FailClosedConfig::default(),
        )
        .await
    }

    /// Single-file writer with fail-closed config (AUD-6).
    pub async fn open_with_hook_fail_closed(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        prev_hash: [u8; HASH_LEN],
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
        fail_closed: FailClosedConfig,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        let gateway_id = gateway_id.into();
        let (file, header_len) = create_log_file(&path, &gateway_id, file_ulid, prev_hash).await?;

        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let health = new_health();
        let health_task = Arc::clone(&health);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            WriterLoopConfig {
                mode: WriterMode::SingleFile,
                file,
                bytes_written: header_len,
                prev_hash,
                gateway_id,
                file_ulid,
                rotate_bytes: u64::MAX,
                ulid_source: Box::new(|| [0u8; 16]),
                witness: None,
                witness_interval_records: u64::MAX,
                witness_interval: Duration::from_secs(u64::MAX / 4),
                records_since_witness: 0,
                last_witness_at: Instant::now(),
                fail_closed,
                health: health_task,
            },
            rx,
            hook,
            stamp_view_task,
        ));

        Ok(Self {
            writer: AuditWriter { tx, health },
            join,
        })
    }

    /// Genesis file: `prev_hash` is 32 zero bytes.
    pub async fn open_genesis(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
    ) -> Result<Self, AuditError> {
        Self::open(path, gateway_id, file_ulid, GENESIS_PREV_HASH).await
    }

    pub async fn open_genesis_with_hook(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
    ) -> Result<Self, AuditError> {
        Self::open_with_hook(
            path,
            gateway_id,
            file_ulid,
            GENESIS_PREV_HASH,
            hook,
            channel_cap,
        )
        .await
    }

    /// Genesis + fail-closed (AUD-6 injectable full-disk).
    pub async fn open_genesis_with_hook_fail_closed(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
        fail_closed: FailClosedConfig,
    ) -> Result<Self, AuditError> {
        Self::open_with_hook_fail_closed(
            path,
            gateway_id,
            file_ulid,
            GENESIS_PREV_HASH,
            hook,
            channel_cap,
            fail_closed,
        )
        .await
    }

    /// Open a rotating writer under `dir`. Creates `dir` if missing. First file
    /// uses genesis `prev_hash`; subsequent files carry the prior head hash.
    /// Rotation runs in the writer task after a synced batch when
    /// `bytes_written >= rotate_bytes`.
    pub async fn open_dir(
        dir: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        rotate_bytes: u64,
    ) -> Result<Self, AuditError> {
        Self::open_dir_with(
            dir,
            gateway_id,
            rotate_bytes,
            Arc::new(NoopSyncHook),
            DEFAULT_CHANNEL_CAP,
            default_ulid_source(),
        )
        .await
    }

    /// Directory writer with hook + ULID source (AUD-3 tests).
    pub async fn open_dir_with(
        dir: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        rotate_bytes: u64,
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
        ulid_source: UlidSource,
    ) -> Result<Self, AuditError> {
        Self::open_dir_with_fail_closed(
            dir,
            gateway_id,
            rotate_bytes,
            hook,
            channel_cap,
            ulid_source,
            FailClosedConfig::default(),
        )
        .await
    }

    /// Directory writer with fail-closed config (AUD-7).
    pub async fn open_dir_with_fail_closed(
        dir: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        rotate_bytes: u64,
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
        mut ulid_source: UlidSource,
        fail_closed: FailClosedConfig,
    ) -> Result<Self, AuditError> {
        let dir = dir.into();
        let gateway_id = gateway_id.into();
        if rotate_bytes == 0 {
            return Err(AuditError::InvalidRotateBytes);
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(AuditError::classify_io)?;

        let file_ulid = ulid_source();
        let path = dir.join(log_file_name(&file_ulid));
        let (file, header_len) =
            create_log_file(&path, &gateway_id, file_ulid, GENESIS_PREV_HASH).await?;

        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let health = new_health();
        let health_task = Arc::clone(&health);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            WriterLoopConfig {
                mode: WriterMode::Directory { dir },
                file,
                bytes_written: header_len,
                prev_hash: GENESIS_PREV_HASH,
                gateway_id,
                file_ulid,
                rotate_bytes,
                ulid_source,
                witness: None,
                witness_interval_records: u64::MAX,
                witness_interval: Duration::from_secs(u64::MAX / 4),
                records_since_witness: 0,
                last_witness_at: Instant::now(),
                fail_closed,
                health: health_task,
            },
            rx,
            hook,
            stamp_view_task,
        ));

        Ok(Self {
            writer: AuditWriter { tx, health },
            join,
        })
    }

    /// Directory writer with witness emission (HLX-22).
    #[allow(clippy::too_many_arguments)]
    pub async fn open_dir_with_witness(
        dir: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        rotate_bytes: u64,
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
        mut ulid_source: UlidSource,
        witness: WitnessHandle,
        witness_interval_records: u64,
        witness_interval_s: u64,
    ) -> Result<Self, AuditError> {
        let dir = dir.into();
        let gateway_id = gateway_id.into();
        if rotate_bytes == 0 {
            return Err(AuditError::InvalidRotateBytes);
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(AuditError::classify_io)?;

        let file_ulid = ulid_source();
        let path = dir.join(log_file_name(&file_ulid));
        let (file, header_len) =
            create_log_file(&path, &gateway_id, file_ulid, GENESIS_PREV_HASH).await?;

        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let health = new_health();
        let health_task = Arc::clone(&health);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            WriterLoopConfig {
                mode: WriterMode::Directory { dir },
                file,
                bytes_written: header_len,
                prev_hash: GENESIS_PREV_HASH,
                gateway_id,
                file_ulid,
                rotate_bytes,
                ulid_source,
                witness: Some(witness),
                witness_interval_records: witness_interval_records.max(1),
                witness_interval: Duration::from_secs(witness_interval_s.max(1)),
                records_since_witness: 0,
                last_witness_at: Instant::now(),
                fail_closed: FailClosedConfig::default(),
                health: health_task,
            },
            rx,
            hook,
            stamp_view_task,
        ));

        Ok(Self {
            writer: AuditWriter { tx, health },
            join,
        })
    }

    /// Single-file writer with witness emission (tests / AUD-9).
    #[allow(clippy::too_many_arguments)]
    pub async fn open_genesis_with_witness(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
        witness: WitnessHandle,
        witness_interval_records: u64,
        witness_interval_s: u64,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        let gateway_id = gateway_id.into();
        let (file, header_len) =
            create_log_file(&path, &gateway_id, file_ulid, GENESIS_PREV_HASH).await?;
        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let health = new_health();
        let health_task = Arc::clone(&health);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            WriterLoopConfig {
                mode: WriterMode::SingleFile,
                file,
                bytes_written: header_len,
                prev_hash: GENESIS_PREV_HASH,
                gateway_id,
                file_ulid,
                rotate_bytes: u64::MAX,
                ulid_source: Box::new(|| [0u8; 16]),
                witness: Some(witness),
                witness_interval_records: witness_interval_records.max(1),
                witness_interval: Duration::from_secs(witness_interval_s.max(1)),
                records_since_witness: 0,
                last_witness_at: Instant::now(),
                fail_closed: FailClosedConfig::default(),
                health: health_task,
            },
            rx,
            hook,
            stamp_view_task,
        ));
        Ok(Self {
            writer: AuditWriter { tx, health },
            join,
        })
    }

    #[must_use]
    pub fn writer(&self) -> AuditWriter {
        self.writer.clone()
    }

    /// Current audit health for `helix.health` (`ok` / `degraded` / `failed`).
    #[must_use]
    pub fn health(&self) -> AuditHealth {
        self.writer.health()
    }

    /// Graceful shutdown: drop senders externally then await the task.
    pub async fn join(mut self) -> Result<(), AuditError> {
        drop(self.writer);
        match self.join.join_next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => Err(AuditError::Join(e.to_string())),
            None => Ok(()),
        }
    }
}

impl AuditWriter {
    /// Health for `helix.health` `audit` field (`gateway.health_detail = full`).
    #[must_use]
    pub fn health(&self) -> AuditHealth {
        AuditHealth::from_u8(self.health.load(Ordering::SeqCst))
    }

    /// Append a record. If `wait` is true, completes only after a sync covering it.
    pub async fn append(
        &self,
        mut record: AuditRecord,
        wait: bool,
    ) -> Result<Option<WriteReceipt>, AuditError> {
        // Sequence is assigned by the writer; clear any caller value.
        record.sequence = 0;
        if wait {
            let (tx, rx) = oneshot::channel();
            self.tx
                .send(WriteReq {
                    record,
                    waiter: Some(tx),
                })
                .await
                .map_err(|_| AuditError::ChannelClosed)?;
            let receipt = rx.await.map_err(|_| AuditError::ChannelClosed)??;
            Ok(Some(receipt))
        } else {
            self.tx
                .send(WriteReq {
                    record,
                    waiter: None,
                })
                .await
                .map_err(|_| AuditError::ChannelClosed)?;
            Ok(None)
        }
    }

    /// Synced durable write (canonical fail-closed API).
    ///
    /// Callers **must** `await` this before component instantiation and before
    /// any terminal HTTP/JSON-RPC response. On `Err`, do not instantiate; on
    /// terminal sync failure, discard tool output. Gateway maps errors to
    /// JSON-RPC `-32030` in M5-05 / HLX-36 ([`AuditError::GATEWAY_CODE`]).
    pub async fn sync(&self, record: AuditRecord) -> Result<(), AuditError> {
        self.append_synced(record).await.map(|_| ())
    }

    /// Convenience: synced append for transitions that require durability.
    pub async fn append_synced(&self, record: AuditRecord) -> Result<WriteReceipt, AuditError> {
        self.append(record, true)
            .await?
            .ok_or(AuditError::MissingReceipt)
    }

    /// Convenience: non-synced append (no waiter).
    pub async fn append_async(&self, record: AuditRecord) -> Result<(), AuditError> {
        self.append(record, false).await.map(|_| ())
    }
}

enum WriterMode {
    SingleFile,
    Directory { dir: PathBuf },
}

struct WriterLoopConfig {
    mode: WriterMode,
    file: tokio::fs::File,
    bytes_written: u64,
    prev_hash: [u8; HASH_LEN],
    gateway_id: String,
    file_ulid: [u8; 16],
    rotate_bytes: u64,
    ulid_source: UlidSource,
    witness: Option<WitnessHandle>,
    witness_interval_records: u64,
    witness_interval: Duration,
    records_since_witness: u64,
    last_witness_at: Instant,
    fail_closed: FailClosedConfig,
    health: Arc<AtomicU8>,
}

async fn create_log_file(
    path: &Path,
    gateway_id: &str,
    file_ulid: [u8; 16],
    prev_hash: [u8; HASH_LEN],
) -> Result<(tokio::fs::File, u64), AuditError> {
    let header = FileHeader::new(file_ulid, gateway_id, prev_hash);
    let header_bytes = header.encode_cbor().map_err(AuditError::Header)?;
    let header_len = header_bytes.len() as u64;

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .await
        .map_err(AuditError::classify_io)?;
    file.write_all(&header_bytes)
        .await
        .map_err(AuditError::classify_io)?;
    file.sync_data().await.map_err(AuditError::classify_io)?;
    Ok((file, header_len))
}

fn set_health(health: &AtomicU8, state: AuditHealth) {
    // Once Failed, stay Failed (fatal path / process exiting).
    let cur = AuditHealth::from_u8(health.load(Ordering::SeqCst));
    if cur == AuditHealth::Failed {
        return;
    }
    health.store(state.to_u8(), Ordering::SeqCst);
}

fn note_success(health: &AtomicU8, consecutive: &mut u32) {
    *consecutive = 0;
    set_health(health, AuditHealth::Ok);
}

/// Notify waiters, bump consecutive errors, update health; return whether fatal.
fn note_failure(
    cfg: &WriterLoopConfig,
    consecutive: &mut u32,
    err: &AuditError,
    waiters: Vec<(u64, oneshot::Sender<Result<WriteReceipt, AuditError>>)>,
) -> bool {
    for (_, w) in waiters {
        let _ = w.send(Err(err.clone()));
    }
    *consecutive = consecutive.saturating_add(1);
    let max = cfg.fail_closed.max_consecutive_errors.max(1);
    if *consecutive >= max {
        set_health(&cfg.health, AuditHealth::Failed);
        cfg.fail_closed.fatal.on_fatal(err);
        true
    } else {
        set_health(&cfg.health, AuditHealth::Degraded);
        false
    }
}

async fn writer_loop(
    mut cfg: WriterLoopConfig,
    mut rx: mpsc::Receiver<WriteReq>,
    hook: Arc<dyn SyncHook>,
    stamp_view: Arc<AtomicU64>,
) -> Result<(), AuditError> {
    let mut next_sequence: u64 = 0;
    let mut consecutive_errors: u32 = 0;

    loop {
        let Some(first) = rx.recv().await else {
            return Ok(());
        };
        let mut batch = vec![first];
        while let Ok(more) = rx.try_recv() {
            batch.push(more);
        }

        let batch_len = batch.len();
        let mut framed = Vec::new();
        let mut waiters = Vec::new();
        // Stage chain mutations; commit only after successful write+sync.
        let mut working_prev = cfg.prev_hash;
        let mut working_seq = next_sequence;
        let mut head_sequence = next_sequence;

        let mut frame_err: Option<AuditError> = None;
        for mut req in batch {
            let seq = working_seq;
            req.record.sequence = seq;
            head_sequence = seq;
            working_seq = working_seq.saturating_add(1);
            match encode_frame(&req.record, &working_prev) {
                Ok((bytes, new_hash)) => {
                    framed.extend_from_slice(&bytes);
                    working_prev = new_hash;
                    if let Some(w) = req.waiter {
                        waiters.push((seq, w));
                    }
                }
                Err(e) => {
                    frame_err = Some(AuditError::Frame(e));
                    if let Some(w) = req.waiter {
                        waiters.push((seq, w));
                    }
                    break;
                }
            }
        }

        if let Some(err) = frame_err {
            if note_failure(&cfg, &mut consecutive_errors, &err, waiters) {
                return Err(err);
            }
            continue;
        }

        let start = Instant::now();
        let write_result = async {
            cfg.fail_closed.fault.before_write()?;
            cfg.file.write_all(&framed).await?;
            cfg.fail_closed.fault.before_sync()?;
            cfg.file.sync_data().await?;
            Ok::<(), std::io::Error>(())
        }
        .await;

        if let Err(io_err) = write_result {
            let err = AuditError::classify_io(io_err);
            if note_failure(&cfg, &mut consecutive_errors, &err, waiters) {
                return Err(err);
            }
            // Do not commit prev_hash / sequence on failed write.
            continue;
        }

        let elapsed = start.elapsed().as_secs_f64();
        // Data is durable on the current file; commit chain state.
        cfg.prev_hash = working_prev;
        next_sequence = working_seq;
        cfg.bytes_written = cfg.bytes_written.saturating_add(framed.len() as u64);

        // Rotation is ordered with the batch stream: only after a synced batch.
        // If rotation cannot open the next file, waiters get the typed error
        // (fail-closed) even though the batch bytes landed on the prior file.
        let needs_rotate = matches!(cfg.mode, WriterMode::Directory { .. })
            && cfg.bytes_written >= cfg.rotate_bytes;
        if needs_rotate {
            if let Err(err) = rotate_file(&mut cfg, &mut next_sequence).await {
                metrics::histogram!("helix_audit_sync_seconds").record(elapsed);
                #[allow(clippy::cast_precision_loss)]
                metrics::histogram!("helix_audit_batch_size").record(batch_len as f64);
                if note_failure(&cfg, &mut consecutive_errors, &err, waiters) {
                    return Err(err);
                }
                continue;
            }
        }

        note_success(&cfg.health, &mut consecutive_errors);

        metrics::histogram!("helix_audit_sync_seconds").record(elapsed);
        #[allow(clippy::cast_precision_loss)]
        metrics::histogram!("helix_audit_batch_size").record(batch_len as f64);

        hook.on_sync(head_sequence, batch_len);
        let sync_stamp = stamp_view.fetch_add(1, Ordering::SeqCst) + 1;

        for (seq, w) in waiters {
            let _ = w.send(Ok(WriteReceipt {
                sequence: seq,
                sync_stamp,
            }));
        }

        cfg.records_since_witness = cfg.records_since_witness.saturating_add(batch_len as u64);
        maybe_emit_witness(&mut cfg, head_sequence);
    }
}

fn maybe_emit_witness(cfg: &mut WriterLoopConfig, head_sequence: u64) {
    let Some(handle) = cfg.witness.as_ref() else {
        return;
    };
    let by_records = cfg.records_since_witness >= cfg.witness_interval_records;
    let by_time = cfg.last_witness_at.elapsed() >= cfg.witness_interval;
    if !(by_records || by_time) {
        return;
    }
    let wall_time_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let w = Witness::new(
        cfg.gateway_id.clone(),
        cfg.file_ulid,
        head_sequence,
        cfg.prev_hash,
        wall_time_ns,
    );
    handle.submit_witness(w);
    cfg.records_since_witness = 0;
    cfg.last_witness_at = Instant::now();
}

async fn rotate_file(
    cfg: &mut WriterLoopConfig,
    next_sequence: &mut u64,
) -> Result<(), AuditError> {
    let WriterMode::Directory { dir } = &cfg.mode else {
        return Ok(());
    };
    let file_ulid = (cfg.ulid_source)();
    let path = dir.join(log_file_name(&file_ulid));
    let carry = cfg.prev_hash;
    if let Err(e) = cfg.fail_closed.fault.before_rotate_open() {
        return Err(AuditError::RotationOpen(e));
    }
    let (file, header_len) = match create_log_file(&path, &cfg.gateway_id, file_ulid, carry).await {
        Ok(v) => v,
        Err(AuditError::NoSpace(e) | AuditError::InputOutput(e) | AuditError::Io(e)) => {
            return Err(AuditError::RotationOpen(e));
        }
        Err(e) => return Err(e),
    };
    // Drop old file by replacement; OS closes on drop.
    cfg.file = file;
    cfg.bytes_written = header_len;
    cfg.file_ulid = file_ulid;
    // Sequence is per-file (witness key is file_ulid/sequence).
    *next_sequence = 0;
    cfg.records_since_witness = 0;
    cfg.last_witness_at = Instant::now();
    let _ = carry;
    Ok(())
}

/// Typed audit writer / sync errors (fail-closed surface for gateway `-32030`).
///
/// Stable gateway mapping code: [`Self::GATEWAY_CODE`] (`-32030`). Full JSON-RPC
/// wiring is M5-05 / HLX-36.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Disk full (`ENOSPC` / `ErrorKind::StorageFull`).
    #[error("audit storage full (ENOSPC): {0}")]
    NoSpace(#[source] std::io::Error),
    /// Low-level IO (`EIO`).
    #[error("audit IO error (EIO): {0}")]
    InputOutput(#[source] std::io::Error),
    /// Other IO failure during write/sync/open.
    #[error("audit IO error: {0}")]
    Io(#[source] std::io::Error),
    /// Rotation could not open the next log file.
    #[error("audit rotation cannot open new file: {0}")]
    RotationOpen(#[source] std::io::Error),
    #[error(transparent)]
    Frame(#[from] crate::frame::FrameError),
    #[error(transparent)]
    Header(#[from] crate::header::HeaderError),
    /// Writer task gone or channel dropped; waiters get this (not a timeout).
    #[error("audit writer channel closed")]
    ChannelClosed,
    #[error("expected sync receipt")]
    MissingReceipt,
    #[error("writer task join: {0}")]
    Join(String),
    #[error("audit.rotate_bytes must be > 0")]
    InvalidRotateBytes,
}

impl AuditError {
    /// JSON-RPC code the gateway must return for audit unavailability (M5-05).
    pub const GATEWAY_CODE: i32 = -32030;

    /// Classify an `io::Error` into a typed fail-closed variant.
    #[must_use]
    pub fn classify_io(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::StorageFull {
            return Self::NoSpace(err);
        }
        // Linux EIO = 5; also accept ErrorKind::Uncategorized with raw 5.
        if err.raw_os_error() == Some(5) {
            return Self::InputOutput(err);
        }
        Self::Io(err)
    }

    /// Gateway JSON-RPC code for this error (`-32030` for all fail-closed paths).
    #[must_use]
    pub const fn gateway_code(&self) -> i32 {
        Self::GATEWAY_CODE
    }

    /// Whether this error should map to fail-closed `-32030` (vs programming bugs).
    #[must_use]
    pub const fn is_fail_closed(&self) -> bool {
        matches!(
            self,
            Self::NoSpace(_)
                | Self::InputOutput(_)
                | Self::Io(_)
                | Self::RotationOpen(_)
                | Self::ChannelClosed
        )
    }
}

fn clone_io(err: &std::io::Error) -> std::io::Error {
    // `std::io::Error` is not `Clone` on current stable; reconstruct for waiters.
    if let Some(raw) = err.raw_os_error() {
        return std::io::Error::from_raw_os_error(raw);
    }
    std::io::Error::new(err.kind(), err.to_string())
}

impl Clone for AuditError {
    fn clone(&self) -> Self {
        match self {
            Self::NoSpace(e) => Self::NoSpace(clone_io(e)),
            Self::InputOutput(e) => Self::InputOutput(clone_io(e)),
            Self::Io(e) => Self::Io(clone_io(e)),
            Self::RotationOpen(e) => Self::RotationOpen(clone_io(e)),
            Self::Frame(e) => Self::Frame(e.clone()),
            Self::Header(e) => Self::Header(e.clone()),
            Self::ChannelClosed => Self::ChannelClosed,
            Self::MissingReceipt => Self::MissingReceipt,
            Self::Join(s) => Self::Join(s.clone()),
            Self::InvalidRotateBytes => Self::InvalidRotateBytes,
        }
    }
}

/// Backward-compatible alias (HLX-18–22 named this `WriterError`).
pub type WriterError = AuditError;
