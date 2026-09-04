//! Injectable sync hook for AUD-8 sequence-stamping.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Called once per successful group-commit `fdatasync`.
///
/// Tests inject a hook that stamps a monotonic sequence so callers can prove
/// every response was preceded by a covering sync.
pub trait SyncHook: Send + Sync + 'static {
    /// `batch_len` is the number of records in the synced batch; `head_sequence`
    /// is the highest record `sequence` in that batch (inclusive coverage).
    fn on_sync(&self, head_sequence: u64, batch_len: usize);
}

/// No-op default.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSyncHook;

impl SyncHook for NoopSyncHook {
    fn on_sync(&self, _head_sequence: u64, _batch_len: usize) {}
}

/// Test/production helper: stamps a monotonic sync id and tracks counts.
#[derive(Debug, Default)]
pub struct SequenceStampHook {
    sync_count: AtomicU64,
    last_stamp: AtomicU64,
    next_stamp: AtomicU64,
}

impl SequenceStampHook {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[must_use]
    pub fn sync_count(&self) -> u64 {
        self.sync_count.load(Ordering::SeqCst)
    }

    /// Stamp observed by the most recent completed sync.
    #[must_use]
    pub fn last_stamp(&self) -> u64 {
        self.last_stamp.load(Ordering::SeqCst)
    }
}

impl SyncHook for SequenceStampHook {
    fn on_sync(&self, _head_sequence: u64, _batch_len: usize) {
        let stamp = self.next_stamp.fetch_add(1, Ordering::SeqCst) + 1;
        self.last_stamp.store(stamp, Ordering::SeqCst);
        self.sync_count.fetch_add(1, Ordering::SeqCst);
    }
}

impl SyncHook for Arc<SequenceStampHook> {
    fn on_sync(&self, head_sequence: u64, batch_len: usize) {
        (**self).on_sync(head_sequence, batch_len);
    }
}
