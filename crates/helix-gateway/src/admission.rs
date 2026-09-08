//! Per-identity semaphore map (ADR-009 B.1 / HLX-36).
//!
//! The semaphore **type** lives in `helix-runtime::admission`. This module holds
//! the per-identity instances, takes the root permit at Authenticated→Authorized,
//! and exposes a handle for children via `runtime::delegate`.

use std::collections::HashMap;
use std::sync::Arc;

use helix_caps::Identity;
use helix_runtime::{IdentityPermit, IdentitySemaphore};
use std::sync::Mutex;

use crate::error_map::METRIC_IDENTITY_IN_USE;

/// Gateway-owned map of per-identity [`IdentitySemaphore`]s.
#[derive(Clone, Default)]
pub struct IdentityAdmission {
    inner: Arc<Mutex<HashMap<Identity, Arc<IdentitySemaphore>>>>,
}

impl IdentityAdmission {
    /// Empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the semaphore for `identity` with `limit` permits.
    ///
    /// If an existing semaphore has a different limit (policy reload), a new
    /// one is installed for subsequent acquires; in-flight permits keep the old.
    #[must_use]
    pub fn semaphore_for(&self, identity: Identity, limit: u32) -> Arc<IdentitySemaphore> {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = g.get(&identity) {
            if existing.limit() == limit {
                return Arc::clone(existing);
            }
        }
        let sem = Arc::new(IdentitySemaphore::new(limit));
        g.insert(identity, Arc::clone(&sem));
        sem
    }

    /// Try to acquire a root permit. Updates `helix_identity_in_use`.
    #[must_use]
    pub fn try_acquire_root(
        &self,
        identity: Identity,
        limit: u32,
        identity_label: &str,
    ) -> Option<(IdentityPermit, Arc<IdentitySemaphore>)> {
        let sem = self.semaphore_for(identity, limit);
        let permit = sem.try_acquire()?;
        let in_use = sem
            .limit()
            .saturating_sub(u32::try_from(sem.available()).unwrap_or(0));
        metrics::gauge!(METRIC_IDENTITY_IN_USE, "identity" => identity_label.to_owned())
            .set(f64::from(in_use));
        Some((permit, sem))
    }

    /// Refresh the gauge after a permit is dropped (best-effort).
    pub fn refresh_gauge(&self, identity: Identity, identity_label: &str) {
        let g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(sem) = g.get(&identity) {
            let in_use = sem
                .limit()
                .saturating_sub(u32::try_from(sem.available()).unwrap_or(0));
            metrics::gauge!(METRIC_IDENTITY_IN_USE, "identity" => identity_label.to_owned())
                .set(f64::from(in_use));
        }
    }
}
