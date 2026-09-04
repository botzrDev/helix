//! Group-commit audit writer with optional size-based rotation (ADR-008 D.1).

use crate::frame::{encode_frame, HASH_LEN};
use crate::header::FileHeader;
use crate::hook::{NoopSyncHook, SyncHook};
use crate::naming::log_file_name;
use crate::record::AuditRecord;
use crate::tags::GENESIS_PREV_HASH;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

const DEFAULT_CHANNEL_CAP: usize = 1024;

struct WriteReq {
    /// Record fields excluding `sequence` (writer assigns it).
    record: AuditRecord,
    /// `Some` for synced transitions; `None` for fire-and-forget.
    waiter: Option<oneshot::Sender<Result<WriteReceipt, WriterError>>>,
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
}

/// Owns the writer task (`JoinSet`) so `tokio::spawn` is never used bare
/// (clippy.toml / ADR-003).
#[derive(Debug)]
pub struct AuditWriterRuntime {
    writer: AuditWriter,
    join: JoinSet<Result<(), WriterError>>,
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

impl AuditWriterRuntime {
    /// Open (create) `path`, write header, start the writer task on a `JoinSet`.
    pub async fn open(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        prev_hash: [u8; HASH_LEN],
    ) -> Result<Self, WriterError> {
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
    ) -> Result<Self, WriterError> {
        let path = path.into();
        let gateway_id = gateway_id.into();
        let (file, header_len) = create_log_file(&path, &gateway_id, file_ulid, prev_hash).await?;

        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            WriterLoopConfig {
                mode: WriterMode::SingleFile,
                file,
                bytes_written: header_len,
                prev_hash,
                gateway_id,
                rotate_bytes: u64::MAX,
                ulid_source: Box::new(|| [0u8; 16]),
            },
            rx,
            hook,
            stamp_view_task,
        ));

        Ok(Self {
            writer: AuditWriter { tx },
            join,
        })
    }

    /// Genesis file: `prev_hash` is 32 zero bytes.
    pub async fn open_genesis(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
    ) -> Result<Self, WriterError> {
        Self::open(path, gateway_id, file_ulid, GENESIS_PREV_HASH).await
    }

    pub async fn open_genesis_with_hook(
        path: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        hook: Arc<dyn SyncHook>,
        channel_cap: usize,
    ) -> Result<Self, WriterError> {
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

    /// Open a rotating writer under `dir`. Creates `dir` if missing. First file
    /// uses genesis `prev_hash`; subsequent files carry the prior head hash.
    /// Rotation runs in the writer task after a synced batch when
    /// `bytes_written >= rotate_bytes`.
    pub async fn open_dir(
        dir: impl Into<PathBuf>,
        gateway_id: impl Into<String>,
        rotate_bytes: u64,
    ) -> Result<Self, WriterError> {
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
        mut ulid_source: UlidSource,
    ) -> Result<Self, WriterError> {
        let dir = dir.into();
        let gateway_id = gateway_id.into();
        if rotate_bytes == 0 {
            return Err(WriterError::InvalidRotateBytes);
        }
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(WriterError::Io)?;

        let file_ulid = ulid_source();
        let path = dir.join(log_file_name(&file_ulid));
        let (file, header_len) =
            create_log_file(&path, &gateway_id, file_ulid, GENESIS_PREV_HASH).await?;

        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            WriterLoopConfig {
                mode: WriterMode::Directory { dir },
                file,
                bytes_written: header_len,
                prev_hash: GENESIS_PREV_HASH,
                gateway_id,
                rotate_bytes,
                ulid_source,
            },
            rx,
            hook,
            stamp_view_task,
        ));

        Ok(Self {
            writer: AuditWriter { tx },
            join,
        })
    }

    #[must_use]
    pub fn writer(&self) -> AuditWriter {
        self.writer.clone()
    }

    /// Graceful shutdown: drop senders externally then await the task.
    pub async fn join(mut self) -> Result<(), WriterError> {
        drop(self.writer);
        match self.join.join_next().await {
            Some(Ok(r)) => r,
            Some(Err(e)) => Err(WriterError::Join(e.to_string())),
            None => Ok(()),
        }
    }
}

impl AuditWriter {
    /// Append a record. If `wait` is true, completes only after a sync covering it.
    pub async fn append(
        &self,
        mut record: AuditRecord,
        wait: bool,
    ) -> Result<Option<WriteReceipt>, WriterError> {
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
                .map_err(|_| WriterError::ChannelClosed)?;
            let receipt = rx.await.map_err(|_| WriterError::ChannelClosed)??;
            Ok(Some(receipt))
        } else {
            self.tx
                .send(WriteReq {
                    record,
                    waiter: None,
                })
                .await
                .map_err(|_| WriterError::ChannelClosed)?;
            Ok(None)
        }
    }

    /// Convenience: synced append for transitions that require durability.
    pub async fn append_synced(&self, record: AuditRecord) -> Result<WriteReceipt, WriterError> {
        self.append(record, true)
            .await?
            .ok_or(WriterError::MissingReceipt)
    }

    /// Convenience: non-synced append (no waiter).
    pub async fn append_async(&self, record: AuditRecord) -> Result<(), WriterError> {
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
    rotate_bytes: u64,
    ulid_source: UlidSource,
}

async fn create_log_file(
    path: &Path,
    gateway_id: &str,
    file_ulid: [u8; 16],
    prev_hash: [u8; HASH_LEN],
) -> Result<(tokio::fs::File, u64), WriterError> {
    let header = FileHeader::new(file_ulid, gateway_id, prev_hash);
    let header_bytes = header.encode_cbor().map_err(WriterError::Header)?;
    let header_len = header_bytes.len() as u64;

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .await
        .map_err(WriterError::Io)?;
    file.write_all(&header_bytes)
        .await
        .map_err(WriterError::Io)?;
    file.sync_data().await.map_err(WriterError::Io)?;
    Ok((file, header_len))
}

async fn writer_loop(
    mut cfg: WriterLoopConfig,
    mut rx: mpsc::Receiver<WriteReq>,
    hook: Arc<dyn SyncHook>,
    stamp_view: Arc<AtomicU64>,
) -> Result<(), WriterError> {
    let mut next_sequence: u64 = 0;

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
        let mut head_sequence = next_sequence;

        for mut req in batch {
            let seq = next_sequence;
            req.record.sequence = seq;
            head_sequence = seq;
            next_sequence = next_sequence.saturating_add(1);
            let (bytes, new_hash) = encode_frame(&req.record, &cfg.prev_hash)?;
            framed.extend_from_slice(&bytes);
            cfg.prev_hash = new_hash;
            if let Some(w) = req.waiter {
                waiters.push((seq, w));
            }
        }

        let start = std::time::Instant::now();
        cfg.file.write_all(&framed).await.map_err(WriterError::Io)?;
        cfg.file.sync_data().await.map_err(WriterError::Io)?;
        let elapsed = start.elapsed().as_secs_f64();

        cfg.bytes_written = cfg.bytes_written.saturating_add(framed.len() as u64);

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

        // Rotation is ordered with the batch stream: only after a synced batch.
        if matches!(cfg.mode, WriterMode::Directory { .. }) && cfg.bytes_written >= cfg.rotate_bytes
        {
            rotate_file(&mut cfg, &mut next_sequence).await?;
        }
    }
}

async fn rotate_file(
    cfg: &mut WriterLoopConfig,
    next_sequence: &mut u64,
) -> Result<(), WriterError> {
    let WriterMode::Directory { dir } = &cfg.mode else {
        return Ok(());
    };
    let file_ulid = (cfg.ulid_source)();
    let path = dir.join(log_file_name(&file_ulid));
    let carry = cfg.prev_hash;
    let (file, header_len) = create_log_file(&path, &cfg.gateway_id, file_ulid, carry).await?;
    // Drop old file by replacement; OS closes on drop.
    cfg.file = file;
    cfg.bytes_written = header_len;
    // Sequence is per-file (witness key is file_ulid/sequence).
    *next_sequence = 0;
    let _ = carry;
    Ok(())
}

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] crate::frame::FrameError),
    #[error(transparent)]
    Header(#[from] crate::header::HeaderError),
    #[error("audit writer channel closed")]
    ChannelClosed,
    #[error("expected sync receipt")]
    MissingReceipt,
    #[error("writer task join: {0}")]
    Join(String),
    #[error("audit.rotate_bytes must be > 0")]
    InvalidRotateBytes,
}
