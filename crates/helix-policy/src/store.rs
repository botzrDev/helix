//! Minimal artifact-store seam for the host resolve pass (rule 2).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

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

/// Directory-backed artifact store for `helix-ctl policy check --artifacts`.
///
/// A digest is present when any of these paths exists as a regular file:
/// - `<dir>/<64-hex>`
/// - `<dir>/<64-hex>.cwasm`
/// - `<dir>/sha256-<64-hex>`
///
/// Layout is provisional until `helix-ctl tool register` lands (M3+/M4); named
/// here so operators can stage empty files for host-pass dry-runs.
#[derive(Debug, Clone)]
pub struct DirArtifactStore {
    dir: PathBuf,
    runtime_max_concurrent_instances: Option<u32>,
}

impl DirArtifactStore {
    /// Point at an artifact directory (`runtime.artifact_dir`).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            runtime_max_concurrent_instances: None,
        }
    }

    /// Set the runtime pool size used for the rule-12 warn.
    #[must_use]
    pub fn with_runtime_max(mut self, max: u32) -> Self {
        self.runtime_max_concurrent_instances = Some(max);
        self
    }

    /// Root directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl ArtifactStore for DirArtifactStore {
    fn contains(&self, digest: &ToolDigest) -> bool {
        let hex = hex_lower(digest.as_bytes());
        [
            self.dir.join(&hex),
            self.dir.join(format!("{hex}.cwasm")),
            self.dir.join(format!("sha256-{hex}")),
        ]
        .into_iter()
        .any(|p| p.is_file())
    }

    fn runtime_max_concurrent_instances(&self) -> Option<u32> {
        self.runtime_max_concurrent_instances
    }
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
