//! Group-commit audit writer (ADR-008 D.1).

use crate::frame::{encode_frame, HASH_LEN};
use crate::header::FileHeader;
use crate::hook::{NoopSyncHook, SyncHook};
use crate::record::AuditRecord;
use crate::tags::GENESIS_PREV_HASH;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
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
        let header = FileHeader::new(file_ulid, gateway_id, prev_hash);
        let header_bytes = header.encode_cbor().map_err(WriterError::Header)?;

        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
            .map_err(WriterError::Io)?;
        file.write_all(&header_bytes)
            .await
            .map_err(WriterError::Io)?;
        file.sync_data().await.map_err(WriterError::Io)?;

        let (tx, rx) = mpsc::channel(channel_cap);
        let stamp_view = Arc::new(AtomicU64::new(0));
        let stamp_view_task = Arc::clone(&stamp_view);
        let mut join = JoinSet::new();
        join.spawn(writer_loop(
            path,
            file,
            prev_hash,
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

async fn writer_loop(
    path: PathBuf,
    mut file: tokio::fs::File,
    mut prev_hash: [u8; HASH_LEN],
    mut rx: mpsc::Receiver<WriteReq>,
    hook: Arc<dyn SyncHook>,
    stamp_view: Arc<AtomicU64>,
) -> Result<(), WriterError> {
    let mut next_sequence: u64 = 0;
    let _ = path;

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
            let (bytes, new_hash) = encode_frame(&req.record, &prev_hash)?;
            framed.extend_from_slice(&bytes);
            prev_hash = new_hash;
            if let Some(w) = req.waiter {
                waiters.push((seq, w));
            }
        }

        let start = Instant::now();
        file.write_all(&framed).await.map_err(WriterError::Io)?;
        file.sync_data().await.map_err(WriterError::Io)?;
        let elapsed = start.elapsed().as_secs_f64();

        metrics::histogram!("helix_audit_sync_seconds").record(elapsed);
        #[allow(clippy::cast_precision_loss)]
        metrics::histogram!("helix_audit_batch_size").record(batch_len as f64);

        hook.on_sync(head_sequence, batch_len);
        // Stamp view: hook implementations that use SequenceStampHook update
        // their own atomics; expose last covering sequence for waiters via
        // a process-local counter bumped here as sync_stamp identity.
        let sync_stamp = stamp_view.fetch_add(1, Ordering::SeqCst) + 1;

        for (seq, w) in waiters {
            let _ = w.send(Ok(WriteReceipt {
                sequence: seq,
                sync_stamp,
            }));
        }
    }
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
}
