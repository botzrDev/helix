//! Runtime errors for engine / artifact / pool.

use std::path::PathBuf;

use thiserror::Error;

/// Errors from engine configuration, artifact I/O, and deserialize.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Wasmtime engine or component error (includes version mismatch).
    #[error("{0}")]
    Wasmtime(String),

    /// Filesystem I/O.
    #[error("io error at {path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Artifact directory permission or layout problem.
    #[error("{0}")]
    Artifact(String),

    /// Policy-related helper failure (optional `--policy` for register).
    #[error("policy: {0}")]
    Policy(String),
}

impl RuntimeError {
    /// Wrap a wasmtime / anyhow-style error with a clear prefix for startup.
    #[must_use]
    pub fn from_wasmtime(err: impl std::fmt::Display) -> Self {
        Self::Wasmtime(err.to_string())
    }

    /// True when the message indicates a wasmtime version / tunables mismatch.
    #[must_use]
    pub fn is_artifact_version_mismatch(&self) -> bool {
        match self {
            Self::Wasmtime(msg) => {
                let lower = msg.to_ascii_lowercase();
                lower.contains("incompatible wasmtime version")
                    || lower.contains("compiled with")
                    || lower.contains("epoch interruption")
            }
            _ => false,
        }
    }
}

impl From<wasmtime::Error> for RuntimeError {
    fn from(value: wasmtime::Error) -> Self {
        Self::from_wasmtime(value)
    }
}
