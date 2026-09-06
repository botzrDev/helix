//! Runtime configuration (`[runtime]` from runbook §2).

use std::path::PathBuf;

/// Subset of `[runtime]` needed for M4-01 engine + artifact cache.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Directory of serialized artifacts (`runtime.artifact_dir`).
    pub artifact_dir: PathBuf,
    /// Pool size (`runtime.max_concurrent_instances`).
    pub max_concurrent_instances: u32,
    /// Per-instance linear-memory ceiling (`runtime.pool_max_memory_bytes`).
    pub pool_max_memory_bytes: usize,
}

impl RuntimeConfig {
    /// Construct with explicit values.
    #[must_use]
    pub fn new(
        artifact_dir: impl Into<PathBuf>,
        max_concurrent_instances: u32,
        pool_max_memory_bytes: usize,
    ) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            max_concurrent_instances,
            pool_max_memory_bytes,
        }
    }

    /// Small defaults suitable for unit tests (avoids huge virtual address use).
    #[must_use]
    pub fn for_test(artifact_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            max_concurrent_instances: 4,
            pool_max_memory_bytes: 16 * 1024 * 1024,
        }
    }
}
