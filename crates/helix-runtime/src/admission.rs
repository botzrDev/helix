//! Per-identity concurrency semaphore (M4-08 / HLX-31 / ADR-009 B.1).
//!
//! The **type** lives in `helix-runtime` so M4 builds before M5 and dependencies
//! flow downward (PRD 5.1). The gateway (M5-05 / HLX-36) holds the per-identity
//! map of instances, takes the root permit at Authenticated → Authorized, and
//! passes a handle into the invocation context. Children acquire through
//! [`crate::delegate`]. RT-14 is testable here with a runtime-owned semaphore
//! and no gateway.
//!
//! Doc note (ADR-009 B.1 amendment): runtime owns the semaphore type; gateway
//! holds the per-identity instances.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-identity live-instance bound (`[budgets.*].max_concurrent_instances`).
///
/// One permit per live root or child instance attributable to the identity on
/// this gateway. Released when the permit (or this guard) is dropped.
#[derive(Debug, Clone)]
pub struct IdentitySemaphore {
    inner: Arc<Semaphore>,
    limit: u32,
}

impl IdentitySemaphore {
    /// Build a semaphore with `limit` permits (`0` means no acquire can succeed).
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            inner: Arc::new(Semaphore::new(usize::try_from(limit).unwrap_or(usize::MAX))),
            limit,
        }
    }

    /// Configured ceiling.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Available permits (best-effort; races with concurrent acquires).
    #[must_use]
    pub fn available(&self) -> usize {
        self.inner.available_permits()
    }

    /// Try to acquire one permit without waiting.
    ///
    /// Returns `None` when the cap is exhausted (`delegate-error::denied` /
    /// root `-32002` concurrency).
    #[must_use]
    pub fn try_acquire(&self) -> Option<IdentityPermit> {
        Arc::clone(&self.inner)
            .try_acquire_owned()
            .ok()
            .map(|permit| IdentityPermit { _permit: permit })
    }
}

/// RAII permit for one live instance. Drop releases the slot.
#[derive(Debug)]
pub struct IdentityPermit {
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limit_refuses_immediately() {
        let sem = IdentitySemaphore::new(0);
        assert!(sem.try_acquire().is_none());
    }

    #[test]
    fn acquire_and_release() {
        let sem = IdentitySemaphore::new(1);
        let p = sem.try_acquire().expect("first");
        assert!(sem.try_acquire().is_none());
        drop(p);
        assert!(sem.try_acquire().is_some());
    }
}
