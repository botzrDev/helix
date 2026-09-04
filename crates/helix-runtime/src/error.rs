//! Runtime errors for engine / artifact / pool / capability linking.

use std::path::PathBuf;

use thiserror::Error;

/// Errors from engine configuration, artifact I/O, deserialize, and provision.
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

    /// Capability projection / instantiation failed at `Provisioned`.
    ///
    /// Maps to JSON-RPC [`Self::GATEWAY_CODE`] (`-32004`). Gateway wiring is
    /// later; the stable code lives here like `AuditError::GATEWAY_CODE`.
    #[error("provision failed: {reason}")]
    Provision {
        /// Human-readable reason (unlinked import, type mismatch, …).
        reason: String,
    },
}

impl RuntimeError {
    /// JSON-RPC `-32004` (Provision failed). Full gateway mapping is M5.
    pub const GATEWAY_CODE: i32 = -32004;

    /// Wrap a wasmtime / anyhow-style error with a clear prefix for startup.
    #[must_use]
    pub fn from_wasmtime(err: impl std::fmt::Display) -> Self {
        Self::Wasmtime(err.to_string())
    }

    /// Fail-closed provision error (unlinked import or linker build failure).
    #[must_use]
    pub fn provision(reason: impl Into<String>) -> Self {
        Self::Provision {
            reason: reason.into(),
        }
    }

    /// Stable gateway mapping for this error class.
    #[must_use]
    pub const fn gateway_code(&self) -> Option<i32> {
        match self {
            Self::Provision { .. } => Some(Self::GATEWAY_CODE),
            _ => None,
        }
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
