//! Minimal artifact-store seam for the host resolve pass (rule 2).

use std::collections::HashSet;

use helix_caps::ToolDigest;

/// Artifact store used only by [`crate::resolve_host`] (rule 2).
///
/// Full store is a later milestone; this is the existence check plus the
/// optional runtime pool size used for the rule-12 host-pass warn.
pub trait ArtifactStore {
    /// True when `digest` is present in the store.
    fn contains(&self, digest: &ToolDigest) -> bool;

    /// `runtime.max_concurrent_instances` from host config, if known.
    ///
    /// `None` skips the ADR-009 B.1 warn. Default: `None`.
    fn runtime_max_concurrent_instances(&self) -> Option<u32> {
        None
    }
}

/// In-memory store for tests and `helix-ctl` later.
#[derive(Debug, Default, Clone)]
pub struct MemoryArtifactStore {
    digests: HashSet<[u8; 32]>,
    runtime_max_concurrent_instances: Option<u32>,
}

impl MemoryArtifactStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a digest.
    #[must_use]
    pub fn with_digest(mut self, digest: ToolDigest) -> Self {
        self.digests.insert(*digest.as_bytes());
        self
    }

    /// Set the runtime pool size used for the rule-12 warn.
    #[must_use]
    pub fn with_runtime_max(mut self, max: u32) -> Self {
        self.runtime_max_concurrent_instances = Some(max);
        self
    }
}

impl ArtifactStore for MemoryArtifactStore {
    fn contains(&self, digest: &ToolDigest) -> bool {
        self.digests.contains(digest.as_bytes())
    }

    fn runtime_max_concurrent_instances(&self) -> Option<u32> {
        self.runtime_max_concurrent_instances
    }
}
