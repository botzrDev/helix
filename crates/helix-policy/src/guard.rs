//! `ArcSwap` holder and per-request-tree [`PolicyGuard`] (M2-02 / HLX-15).
//!
//! Cites: `policy-format.md` §§3–4, ADR-008 C.3, ADR-009 A.1.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use helix_caps::{CapabilitySet, Identity, Interner, ResourceBudget, ToolDigest};

use crate::file::PolicyFile;
use crate::fs::Fs;
use crate::resolve::{resolve_host, PolicySnapshot};
use crate::store::ArtifactStore;
use crate::PolicyError;

/// Default `policy.max_snapshot_age_s` (runbook / ADR-008 C.3).
pub const DEFAULT_MAX_SNAPSHOT_AGE_S: u64 = 300;

/// Reason string for a stale-snapshot refusal (`delegate-error::stale-snapshot`).
pub const STALE_SNAPSHOT_REASON: &str = "stale_snapshot";

/// Alias vs digest disagreement (-32003 territory for the gateway).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasDigestError {
    /// Alias is not in the snapshot's `[tools]` table.
    UnknownAlias {
        /// Alias that was looked up.
        alias: String,
    },
    /// Alias resolves to a digest other than the one supplied.
    Disagreement {
        /// Tool alias.
        alias: String,
        /// Digest from the alias table.
        table: ToolDigest,
        /// Digest supplied by the caller.
        provided: ToolDigest,
    },
}

/// Live policy held in `arc_swap::ArcSwap`. Capture a [`PolicyGuard`] at admission.
pub struct PolicyHolder {
    swap: ArcSwap<PolicySnapshot>,
    next_version: AtomicU64,
    max_snapshot_age_s: u64,
}

impl PolicyHolder {
    /// Wrap an already-resolved snapshot. Stamps `version = 1` at `Instant::now()`.
    #[must_use]
    pub fn new(snapshot: PolicySnapshot, max_snapshot_age_s: u64) -> Self {
        let stamped = snapshot.stamp(1, Instant::now());
        Self {
            swap: ArcSwap::from_pointee(stamped),
            next_version: AtomicU64::new(2),
            max_snapshot_age_s,
        }
    }

    /// Parse + structural + host validation, then hold the snapshot.
    ///
    /// # Errors
    ///
    /// Returns every validation error; no holder is constructed on failure.
    pub fn load<S: ArtifactStore>(
        text: &str,
        artifacts: &S,
        fs: &dyn Fs,
        max_snapshot_age_s: u64,
    ) -> Result<Self, Vec<PolicyError>> {
        let file = PolicyFile::parse(text).map_err(|e| vec![e])?;
        let snapshot = resolve_host(&file, artifacts, fs)?;
        Ok(Self::new(snapshot, max_snapshot_age_s))
    }

    /// Configured `policy.max_snapshot_age_s`.
    #[must_use]
    pub fn max_snapshot_age_s(&self) -> u64 {
        self.max_snapshot_age_s
    }

    /// Current `policy_version` for `helix.health`.
    #[must_use]
    pub fn policy_version(&self) -> u64 {
        self.swap.load().version()
    }

    /// Capture the live snapshot for one request tree (ADR-008 C.3).
    #[must_use]
    pub fn guard(&self) -> PolicyGuard {
        PolicyGuard {
            snapshot: self.swap.load_full(),
            max_snapshot_age_s: self.max_snapshot_age_s,
        }
    }

    /// Reload from TOML text: full parse + structural + host validation.
    ///
    /// On success swaps atomically and returns the new version. On failure logs
    /// `policy.reload.failed` with the rule violated and keeps the prior snapshot.
    ///
    /// Intended for the SIGHUP handler; unit tests call this directly (no signals).
    ///
    /// # Errors
    ///
    /// Returns the validation errors after logging; the live snapshot is unchanged.
    pub fn reload<S: ArtifactStore>(
        &self,
        text: &str,
        artifacts: &S,
        fs: &dyn Fs,
    ) -> Result<u64, Vec<PolicyError>> {
        let result = (|| {
            let file = PolicyFile::parse(text).map_err(|e| vec![e])?;
            resolve_host(&file, artifacts, fs)
        })();

        match result {
            Ok(snapshot) => {
                let version = self.next_version.fetch_add(1, Ordering::Relaxed);
                let stamped = snapshot.stamp(version, Instant::now());
                self.swap.store(Arc::new(stamped));
                Ok(version)
            }
            Err(errors) => {
                log_reload_failed(&errors);
                Err(errors)
            }
        }
    }

    /// Swap in an already-resolved snapshot (tests / pre-validated path).
    pub fn reload_snapshot(&self, snapshot: PolicySnapshot) -> u64 {
        let version = self.next_version.fetch_add(1, Ordering::Relaxed);
        let stamped = snapshot.stamp(version, Instant::now());
        self.swap.store(Arc::new(stamped));
        version
    }
}

fn log_reload_failed(errors: &[PolicyError]) {
    for e in errors {
        match e.rule() {
            Some(rule) => log::error!(
                target: "policy.reload.failed",
                "policy.reload.failed rule={rule} error={e}"
            ),
            None => log::error!(
                target: "policy.reload.failed",
                "policy.reload.failed error={e}"
            ),
        }
    }
}

/// Arc-swap snapshot captured once at admission and inherited by delegated children.
///
/// Owns (via `Arc`) the interner and alias table for the request tree.
#[derive(Clone, Debug)]
pub struct PolicyGuard {
    snapshot: Arc<PolicySnapshot>,
    max_snapshot_age_s: u64,
}

impl PolicyGuard {
    /// Build a guard around an owned snapshot (tests; bypasses the holder).
    #[must_use]
    pub fn from_snapshot(snapshot: PolicySnapshot, max_snapshot_age_s: u64) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            max_snapshot_age_s,
        }
    }

    /// Borrow the underlying snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    /// Snapshot-scoped intern table.
    #[must_use]
    pub fn interner(&self) -> &Interner {
        self.snapshot.interner()
    }

    /// Alias table (`name -> ToolDigest`).
    #[must_use]
    pub fn tools(&self) -> &std::collections::HashMap<String, ToolDigest> {
        self.snapshot.tools()
    }

    /// `policy_version` of this captured snapshot.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.snapshot.version()
    }

    /// When this snapshot was loaded.
    #[must_use]
    pub fn loaded_at(&self) -> Instant {
        self.snapshot.loaded_at()
    }

    /// Configured max age used by [`Self::check_age`].
    #[must_use]
    pub fn max_snapshot_age_s(&self) -> u64 {
        self.max_snapshot_age_s
    }

    /// `policy(identity, digest) -> Option<(&CapabilitySet, &ResourceBudget)>`.
    #[must_use]
    pub fn policy(
        &self,
        identity: &Identity,
        digest: &ToolDigest,
    ) -> Option<(&CapabilitySet, &ResourceBudget)> {
        self.snapshot.policy(identity, digest)
    }

    /// Resolve `name` against this guard's alias table.
    #[must_use]
    pub fn resolve_alias(&self, name: &str) -> Option<ToolDigest> {
        self.snapshot.resolve_alias(name)
    }

    /// Check that `digest` matches the alias table entry.
    ///
    /// Gateway maps [`AliasDigestError::Disagreement`] to JSON-RPC `-32003`.
    ///
    /// # Errors
    ///
    /// [`AliasDigestError`] when the alias is missing or disagrees.
    pub fn check_alias_digest(
        &self,
        alias: &str,
        digest: &ToolDigest,
    ) -> Result<(), AliasDigestError> {
        match self.resolve_alias(alias) {
            None => Err(AliasDigestError::UnknownAlias {
                alias: alias.to_owned(),
            }),
            Some(table) if table == *digest => Ok(()),
            Some(table) => Err(AliasDigestError::Disagreement {
                alias: alias.to_owned(),
                table,
                provided: *digest,
            }),
        }
    }

    /// True when this guard is older than `max_snapshot_age_s` at `now`.
    #[must_use]
    pub fn is_stale_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.loaded_at())
            > Duration::from_secs(self.max_snapshot_age_s)
    }

    /// True when this guard is currently older than `max_snapshot_age_s`.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.is_stale_at(Instant::now())
    }

    /// Refuse a delegated child when the inherited guard is stale.
    ///
    /// # Errors
    ///
    /// Returns [`STALE_SNAPSHOT_REASON`] when the guard exceeds `max_snapshot_age_s`.
    pub fn check_age(&self) -> Result<(), &'static str> {
        self.check_age_at(Instant::now())
    }

    /// Age check with an injected clock (unit tests).
    ///
    /// # Errors
    ///
    /// Returns [`STALE_SNAPSHOT_REASON`] when stale at `now`.
    pub fn check_age_at(&self, now: Instant) -> Result<(), &'static str> {
        if self.is_stale_at(now) {
            Err(STALE_SNAPSHOT_REASON)
        } else {
            Ok(())
        }
    }
}
