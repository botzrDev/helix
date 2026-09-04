//! `InstancePre` pool keyed by [`ToolDigest`].

#![allow(clippy::cast_precision_loss)] // metrics gauges are f64

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use helix_caps::ToolDigest;
use wasmtime::component::InstancePre;

use crate::artifact::LoadedArtifact;
use crate::{METRIC_INSTANTIATE_SECONDS, METRIC_POOL_IN_USE};

/// Owned `InstancePre<()>` built against the M4-01 linker template.
///
/// Documented hole: imports are trapping stubs until HLX-25 `link(&CapabilitySet)`.
#[derive(Clone)]
pub struct PooledPre {
    inner: Arc<InstancePre<()>>,
}

impl std::fmt::Debug for PooledPre {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PooledPre(..)")
    }
}

impl PooledPre {
    /// Wrap a wasmtime `InstancePre`.
    #[must_use]
    pub fn new(pre: InstancePre<()>) -> Self {
        Self {
            inner: Arc::new(pre),
        }
    }

    /// Borrow the underlying pre-instance.
    #[must_use]
    pub fn inner(&self) -> &InstancePre<()> {
        &self.inner
    }
}

/// In-memory map of digest → `InstancePre`, plus pool-in-use gauge support.
#[derive(Debug, Default)]
pub struct InstancePool {
    by_digest: HashMap<[u8; 32], PooledPre>,
    in_use: AtomicUsize,
}

impl InstancePool {
    /// Empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate from artifacts loaded at startup.
    pub fn load_all(&mut self, artifacts: Vec<LoadedArtifact>) {
        for art in artifacts {
            self.by_digest.insert(*art.digest.as_bytes(), art.pre);
        }
        self.publish_gauge();
    }

    /// Insert or replace one digest's `InstancePre`.
    pub fn insert(&mut self, digest: ToolDigest, pre: PooledPre) {
        self.by_digest.insert(*digest.as_bytes(), pre);
    }

    /// Lookup by digest.
    #[must_use]
    pub fn get(&self, digest: &ToolDigest) -> Option<&PooledPre> {
        self.by_digest.get(digest.as_bytes())
    }

    /// Number of loaded digests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    /// True when no artifacts are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }

    /// Mark one pooled instance as in use (request path / tests).
    pub fn acquire(&self) -> PoolGuard<'_> {
        let n = self.in_use.fetch_add(1, Ordering::SeqCst) + 1;
        metrics::gauge!(METRIC_POOL_IN_USE).set(n as f64);
        PoolGuard { pool: self }
    }

    /// Current in-use count.
    #[must_use]
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::SeqCst)
    }

    fn publish_gauge(&self) {
        metrics::gauge!(METRIC_POOL_IN_USE).set(self.in_use.load(Ordering::SeqCst) as f64);
    }

    /// Record an instantiate duration sample.
    pub fn record_instantiate_seconds(seconds: f64) {
        metrics::histogram!(METRIC_INSTANTIATE_SECONDS).record(seconds);
    }
}

/// Decrements `helix_pool_in_use` on drop.
pub struct PoolGuard<'a> {
    pool: &'a InstancePool,
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        let n = self.pool.in_use.fetch_sub(1, Ordering::SeqCst) - 1;
        metrics::gauge!(METRIC_POOL_IN_USE).set(n as f64);
    }
}
