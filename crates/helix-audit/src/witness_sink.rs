//! HTTP witness sink client + async emitter (ADR-009 D.2).
//!
//! PUT with `If-None-Match: *`. 412 → conflict metric, no retry. Other failures
//! retry with backoff up to `witness_interval_s`. In-memory queue bound 1024
//! (oldest dropped). Never blocks the audit writer.

use crate::export::{ExportError, ExportSink, WitnessAttrs};
use crate::witness::{SinkPayload, Witness, WitnessError};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Notify;
use tokio::task::JoinSet;

type HmacSha256 = Hmac<Sha256>;

const QUEUE_CAP: usize = 1024;
const CONFLICT_METRIC: &str = "helix_audit_witness_conflict_total";
const DROPPED_METRIC: &str = "helix_audit_witness_dropped_total";
const LAG_METRIC: &str = "helix_audit_witness_lag_s";

/// How the sink authenticates.
#[derive(Clone, Debug)]
pub enum WitnessAuth {
    /// Bearer token read from a file (0600 preferred; witness-receive).
    Bearer { token_file: PathBuf },
    /// AWS `SigV4` from a 0600 credential file (`audit.witness_auth = "sigv4"`).
    SigV4 { cred_file: PathBuf },
}

/// Configuration for the witness emitter.
#[derive(Clone, Debug)]
pub struct WitnessConfig {
    pub sink_base: String,
    pub auth: WitnessAuth,
    pub interval_records: u64,
    pub interval_s: u64,
}

impl WitnessConfig {
    #[must_use]
    pub fn defaults(sink_base: impl Into<String>, auth: WitnessAuth) -> Self {
        Self {
            sink_base: sink_base.into(),
            auth,
            interval_records: 10_000,
            interval_s: 60,
        }
    }
}

/// `SigV4` credentials (HOLE: ADR does not pin the credential file schema).
///
/// Accepted lines (any order, `#` comments, `KEY=VALUE` or `key = value`):
/// `access_key_id`, `secret_access_key`, optional `session_token`, optional
/// `region` (default `us-east-1`), optional `service` (default `s3`).
#[derive(Clone, Debug)]
pub struct SigV4Creds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: String,
    pub service: String,
}

impl SigV4Creds {
    pub fn load(path: &Path) -> Result<Self, SinkError> {
        check_mode_0600(path)?;
        let text = std::fs::read_to_string(path).map_err(SinkError::Io)?;
        let mut access_key_id = None;
        let mut secret_access_key = None;
        let mut session_token = None;
        let mut region = None;
        let mut service = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let k = k.trim().to_ascii_lowercase().replace('-', "_");
            let v = v.trim().trim_matches('"').to_owned();
            match k.as_str() {
                "access_key_id" | "aws_access_key_id" => access_key_id = Some(v),
                "secret_access_key" | "aws_secret_access_key" => secret_access_key = Some(v),
                "session_token" | "aws_session_token" => session_token = Some(v),
                "region" | "aws_region" => region = Some(v),
                "service" => service = Some(v),
                _ => {}
            }
        }
        Ok(Self {
            access_key_id: access_key_id
                .ok_or_else(|| SinkError::Creds("missing access_key_id".into()))?,
            secret_access_key: secret_access_key
                .ok_or_else(|| SinkError::Creds("missing secret_access_key".into()))?,
            session_token,
            region: region.unwrap_or_else(|| "us-east-1".into()),
            service: service.unwrap_or_else(|| "s3".into()),
        })
    }
}

fn check_mode_0600(path: &Path) -> Result<(), SinkError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(SinkError::Io)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SinkError::Creds(format!(
            "credential file {} mode {:03o} is not 0600 (group/other bits set)",
            path.display(),
            mode
        )));
    }
    Ok(())
}

fn load_bearer(path: &Path) -> Result<String, SinkError> {
    // Bearer files should also be 0600 when possible; warn-via-error if loose.
    let _ = check_mode_0600(path);
    let text = std::fs::read_to_string(path).map_err(SinkError::Io)?;
    Ok(text.trim().to_owned())
}

/// HTTP client for the S3-style witness sink.
#[derive(Clone, Debug)]
pub struct WitnessHttpClient {
    base: String,
    auth: WitnessAuth,
    http: reqwest::Client,
}

impl WitnessHttpClient {
    pub fn new(base: impl Into<String>, auth: WitnessAuth) -> Result<Self, SinkError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SinkError::Http(e.to_string()))?;
        Ok(Self {
            base: base.into().trim_end_matches('/').to_owned(),
            auth,
            http,
        })
    }

    fn url_for(&self, key: &str) -> String {
        format!("{}/{}", self.base, key.trim_start_matches('/'))
    }

    /// PUT object with `If-None-Match: *`. Returns `Conflict` on 412.
    pub async fn put_exclusive(&self, key: &str, body: &[u8]) -> Result<(), SinkError> {
        let url = self.url_for(key);
        let mut req = self
            .http
            .put(&url)
            .header("if-none-match", "*")
            .header("content-type", "application/cbor")
            .body(body.to_vec());
        req = self.authorize(req, "PUT", key, body)?;
        let resp = req
            .send()
            .await
            .map_err(|e| SinkError::Http(e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 412 {
            return Err(SinkError::Conflict);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SinkError::Http(format!("PUT {url} -> {status}: {text}")));
        }
        Ok(())
    }

    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>, SinkError> {
        let url = self.url_for(key);
        let mut req = self.http.get(&url);
        req = self.authorize(req, "GET", key, &[])?;
        let resp = req
            .send()
            .await
            .map_err(|e| SinkError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(SinkError::Http(format!("GET {url} -> {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| SinkError::Http(e.to_string()))
    }

    /// List keys under `prefix` (typically `gateway_id/`).
    ///
    /// Accepts JSON array of key strings, or S3 `ListObjectsV2` XML
    /// (`<Key>...</Key>`).
    pub async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, SinkError> {
        let prefix = prefix.trim_start_matches('/');
        let url = if prefix.is_empty() {
            format!("{}/", self.base)
        } else {
            format!("{}/{}/", self.base, prefix.trim_end_matches('/'))
        };
        // Also try query-style list for S3.
        let mut req = self.http.get(&url);
        req = self.authorize(req, "GET", prefix, &[])?;
        let resp = req
            .send()
            .await
            .map_err(|e| SinkError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            // Fallback: S3 ListObjectsV2 query on bucket root.
            return self.list_keys_s3_query(prefix).await;
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| SinkError::Http(e.to_string()))?;
        parse_listing(&bytes, prefix)
    }

    async fn list_keys_s3_query(&self, prefix: &str) -> Result<Vec<String>, SinkError> {
        let url = format!(
            "{}?list-type=2&prefix={}",
            self.base,
            urlencoding_lite(prefix)
        );
        let mut req = self.http.get(&url);
        req = self.authorize(req, "GET", "", &[])?;
        let resp = req
            .send()
            .await
            .map_err(|e| SinkError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(SinkError::Http(format!(
                "LIST {} -> {}",
                url,
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| SinkError::Http(e.to_string()))?;
        parse_listing(&bytes, prefix)
    }

    fn authorize(
        &self,
        mut req: reqwest::RequestBuilder,
        method: &str,
        key: &str,
        body: &[u8],
    ) -> Result<reqwest::RequestBuilder, SinkError> {
        match &self.auth {
            WitnessAuth::Bearer { token_file } => {
                let token = load_bearer(token_file)?;
                req = req.header("authorization", format!("Bearer {token}"));
                Ok(req)
            }
            WitnessAuth::SigV4 { cred_file } => {
                let creds = SigV4Creds::load(cred_file)?;
                let url = self.url_for(key);
                let parsed = url::Url::parse(&url)
                    .map_err(|e| SinkError::Http(format!("bad url {url}: {e}")))?;
                let host = parsed
                    .host_str()
                    .ok_or_else(|| SinkError::Http("missing host".into()))?
                    .to_owned();
                let path = if parsed.path().is_empty() {
                    "/".to_owned()
                } else {
                    parsed.path().to_owned()
                };
                let query = parsed.query().unwrap_or("");
                let headers = sign_sigv4(&creds, method, &host, &path, query, body)?;
                for (k, v) in headers {
                    req = req.header(k, v);
                }
                Ok(req)
            }
        }
    }
}

fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Parse JSON string array or S3 `ListObjectsV2` XML into object keys.
pub fn parse_listing(bytes: &[u8], prefix_filter: &str) -> Result<Vec<String>, SinkError> {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(arr) = v.as_array() {
            let mut keys = Vec::new();
            for item in arr {
                if let Some(s) = item.as_str() {
                    if prefix_filter.is_empty() || s.starts_with(prefix_filter) {
                        keys.push(s.to_owned());
                    }
                }
            }
            keys.sort();
            return Ok(keys);
        }
    }
    let text = String::from_utf8_lossy(bytes);
    let mut keys = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("<Key>") {
        rest = &rest[start + 5..];
        let Some(end) = rest.find("</Key>") else {
            break;
        };
        let key = rest[..end].to_owned();
        rest = &rest[end + 6..];
        if prefix_filter.is_empty() || key.starts_with(prefix_filter) {
            keys.push(key);
        }
    }
    keys.sort();
    Ok(keys)
}

fn sign_sigv4(
    creds: &SigV4Creds,
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, SinkError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SinkError::Http(e.to_string()))?;
    let secs = now.as_secs();
    // UTC timestamp YYYYMMDD'T'HHMMSS'Z'
    let datetime = utc_basic(secs);
    let date = &datetime[..8];
    let payload_hash = hex_sha256(body);
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{datetime}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let canonical_hash = hex_sha256(canonical_request.as_bytes());
    let scope = format!("{date}/{}/{}/aws4_request", creds.region, creds.service);
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{datetime}\n{scope}\n{canonical_hash}");
    let signing_key = aws4_signing_key(
        &creds.secret_access_key,
        date,
        &creds.region,
        &creds.service,
    )?;
    let signature = hex_hmac(&signing_key, string_to_sign.as_bytes())?;
    let mut headers = vec![
        ("x-amz-content-sha256".into(), payload_hash),
        ("x-amz-date".into(), datetime),
        (
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
                creds.access_key_id, scope
            ),
        ),
    ];
    if let Some(token) = &creds.session_token {
        headers.push(("x-amz-security-token".into(), token.clone()));
    }
    Ok(headers)
}

fn utc_basic(secs: u64) -> String {
    // Simple days-from-civil for UTC (no chrono dep).
    let (y, m, d, hh, mm, ss) = secs_to_utc(secs);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn secs_to_utc(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let ss = (secs % 60) as u32;
    let mins = secs / 60;
    let mm = (mins % 60) as u32;
    let hours = mins / 60;
    let hh = (hours % 24) as u32;
    let days = i64::try_from(hours / 24).unwrap_or(i64::MAX);
    let (y, m, d) = civil_from_days(days + 719_468); // 1970-01-01 offset
    (y, m, d, hh, mm, ss)
}

/// Howard Hinnant `civil_from_days` (proleptic Gregorian).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn hex_sha256(data: &[u8]) -> String {
    let dig = Sha256::digest(data);
    crate::naming::hex_encode(&dig)
}

fn hex_hmac(key: &[u8], data: &[u8]) -> Result<String, SinkError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| SinkError::Http(format!("hmac: {e}")))?;
    mac.update(data);
    Ok(crate::naming::hex_encode(&mac.finalize().into_bytes()))
}

fn aws4_signing_key(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, SinkError> {
    let k_date = hmac_raw(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let k_region = hmac_raw(&k_date, region.as_bytes())?;
    let k_service = hmac_raw(&k_region, service.as_bytes())?;
    hmac_raw(&k_service, b"aws4_request")
}

fn hmac_raw(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SinkError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| SinkError::Http(format!("hmac: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Non-blocking handle the writer uses to enqueue witnesses.
#[derive(Clone)]
pub struct WitnessHandle {
    inner: Arc<WitnessInner>,
}

impl std::fmt::Debug for WitnessHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHandle")
            .field("queue_len", &self.inner.queue.lock().map_or(0, |q| q.len()))
            .field("dropped", &self.inner.dropped.load(Ordering::SeqCst))
            .field("conflicts", &self.inner.conflicts.load(Ordering::SeqCst))
            .finish()
    }
}

struct WitnessInner {
    queue: Mutex<VecDeque<Queued>>,
    notify: Notify,
    stop: AtomicBool,
    /// Wall-time (unix secs) of last successful delivery; 0 = never.
    last_delivered_unix: AtomicU64,
    /// Instant of last successful delivery for lag gauge (ms since start).
    last_delivered_ms: AtomicU64,
    start: Instant,
    dropped: AtomicU64,
    conflicts: AtomicU64,
}

struct Queued {
    payload: SinkPayload,
    _enqueued_at: Instant, // lag diagnostics
}

impl WitnessHandle {
    /// Enqueue without blocking. Drops oldest when over capacity.
    pub fn submit(&self, payload: SinkPayload) {
        let mut q = self.inner.queue.lock().expect("witness queue lock");
        if q.len() >= QUEUE_CAP {
            q.pop_front();
            self.inner.dropped.fetch_add(1, Ordering::SeqCst);
            metrics::counter!(DROPPED_METRIC).increment(1);
        }
        q.push_back(Queued {
            payload,
            _enqueued_at: Instant::now(),
        });
        drop(q);
        self.inner.notify.notify_one();
    }

    pub fn submit_witness(&self, w: Witness) {
        self.submit(SinkPayload::Witness(w));
    }

    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn conflicts(&self) -> u64 {
        self.inner.conflicts.load(Ordering::SeqCst)
    }

    /// Approximate lag in seconds since last successful delivery (gauge source).
    #[must_use]
    pub fn lag_s(&self) -> f64 {
        let ms = self.inner.last_delivered_ms.load(Ordering::SeqCst);
        if ms == 0 {
            return self.inner.start.elapsed().as_secs_f64();
        }
        let delivered = self.inner.start + Duration::from_millis(ms);
        Instant::now()
            .saturating_duration_since(delivered)
            .as_secs_f64()
    }
}

/// Owns the witness delivery task via [`JoinSet`].
pub struct WitnessRuntime {
    handle: WitnessHandle,
    join: JoinSet<()>,
}

impl WitnessRuntime {
    /// Start the delivery loop. `otel` receives witness attrs (HLX-20 hook).
    #[allow(clippy::needless_pass_by_value)]
    pub fn start<S: ExportSink>(config: WitnessConfig, otel: Arc<S>) -> Result<Self, SinkError> {
        let client = WitnessHttpClient::new(&config.sink_base, config.auth.clone())?;
        let inner = Arc::new(WitnessInner {
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            stop: AtomicBool::new(false),
            last_delivered_unix: AtomicU64::new(0),
            last_delivered_ms: AtomicU64::new(0),
            start: Instant::now(),
            dropped: AtomicU64::new(0),
            conflicts: AtomicU64::new(0),
        });
        let handle = WitnessHandle {
            inner: Arc::clone(&inner),
        };
        let mut join = JoinSet::new();
        let interval_s = config.interval_s.max(1);
        join.spawn(async move {
            delivery_loop(inner, client, otel, interval_s).await;
        });
        Ok(Self { handle, join })
    }

    #[must_use]
    pub fn handle(&self) -> WitnessHandle {
        self.handle.clone()
    }

    pub async fn shutdown(mut self) {
        self.handle.inner.stop.store(true, Ordering::SeqCst);
        self.handle.inner.notify.notify_waiters();
        while self.join.join_next().await.is_some() {}
    }
}

async fn delivery_loop<S: ExportSink>(
    inner: Arc<WitnessInner>,
    client: WitnessHttpClient,
    otel: Arc<S>,
    interval_s: u64,
) {
    let max_backoff = Duration::from_secs(interval_s);
    while !inner.stop.load(Ordering::SeqCst) {
        let item = {
            let mut q = inner.queue.lock().expect("witness queue lock");
            q.pop_front()
        };
        let Some(item) = item else {
            tokio::select! {
                () = inner.notify.notified() => {}
                () = tokio::time::sleep(Duration::from_millis(200)) => {}
            }
            refresh_lag(&inner);
            continue;
        };

        // OTel hook (best-effort; never fails delivery path).
        if let Some(w) = item.payload.as_witness() {
            let attrs: WitnessAttrs = w.to_attrs();
            if let Err(e) = otel.export_witness(attrs).await {
                log::error!("helix.audit.witness otel export failed: {e}");
            }
        }

        let key = item.payload.object_key();
        let body = match item.payload.encode_cbor() {
            Ok(b) => b,
            Err(e) => {
                log::error!("witness encode failed for {key}: {e}");
                continue;
            }
        };

        let mut backoff = Duration::from_millis(50);
        let deadline = Instant::now() + max_backoff;
        loop {
            match client.put_exclusive(&key, &body).await {
                Ok(()) => {
                    let now_ms =
                        u64::try_from(inner.start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    inner.last_delivered_ms.store(now_ms, Ordering::SeqCst);
                    let unix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    inner.last_delivered_unix.store(unix, Ordering::SeqCst);
                    refresh_lag(&inner);
                    break;
                }
                Err(SinkError::Conflict) => {
                    log::error!("witness PUT conflict (412) for key {key}; not retrying");
                    inner.conflicts.fetch_add(1, Ordering::SeqCst);
                    metrics::counter!(CONFLICT_METRIC).increment(1);
                    break;
                }
                Err(e) => {
                    if Instant::now() >= deadline || inner.stop.load(Ordering::SeqCst) {
                        log::error!("witness PUT failed for {key} after retries: {e}; re-queue");
                        // Re-queue at front if room; else drop oldest then push.
                        let mut q = inner.queue.lock().expect("witness queue lock");
                        if q.len() >= QUEUE_CAP {
                            q.pop_front();
                            inner.dropped.fetch_add(1, Ordering::SeqCst);
                            metrics::counter!(DROPPED_METRIC).increment(1);
                        }
                        q.push_front(item);
                        break;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
        refresh_lag(&inner);
    }
}

fn refresh_lag(inner: &WitnessInner) {
    let ms = inner.last_delivered_ms.load(Ordering::SeqCst);
    let lag = if ms == 0 {
        inner.start.elapsed().as_secs_f64()
    } else {
        let delivered = inner.start + Duration::from_millis(ms);
        Instant::now()
            .saturating_duration_since(delivered)
            .as_secs_f64()
    };
    metrics::gauge!(LAG_METRIC).set(lag);
}

/// No-op export sink when `OTel` is not configured.
#[derive(Clone, Debug, Default)]
pub struct NoopExportSink;

impl ExportSink for NoopExportSink {
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    async fn export_invocation(
        &self,
        _inv: crate::export::ExportedInvocation,
    ) -> Result<(), ExportError> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("credentials: {0}")]
    Creds(String),
    #[error("412 precondition failed (key exists)")]
    Conflict,
    #[error(transparent)]
    Witness(#[from] WitnessError),
}
