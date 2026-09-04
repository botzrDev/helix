//! Runtime errors for engine / artifact / pool / capability linking / invoke.

use std::path::PathBuf;

use thiserror::Error;

/// Usage attached to every terminal record / JSON-RPC `usage` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Wall-clock milliseconds from invoke entry to terminal.
    pub wall_ms: u64,
    /// Epoch ticks consumed (1 tick = 1 ms wall under the pinned ticker).
    pub preempt_ticks: u64,
    /// Peak guest linear memory observed by the limiter (bytes).
    pub peak_memory_bytes: u64,
    /// Output bytes delivered to the caller (0 on kill / tool error with no body).
    pub output_bytes: u64,
}

/// Kill causes on the Running → Killed row (`-32010` … `-32014`, panic → `-32007`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillCause {
    /// Guest did not yield before `preempt_ticks` (`-32010`).
    Preempted,
    /// Wall-clock token cancelled host work (`-32011`); M4-05.
    WallClock,
    /// Linear memory past `memory_bytes` (`-32012`).
    Memory,
    /// Result past `output_bytes` (`-32013`).
    Output,
    /// Parent request dropped (`-32014`); M4-05 / M4-08.
    ParentDropped,
    /// Host panic caught by the invoke drop guard (`-32007`).
    Panic,
}

impl KillCause {
    /// JSON-RPC error code for this cause.
    #[must_use]
    pub const fn gateway_code(self) -> i32 {
        match self {
            Self::Preempted => -32010,
            Self::WallClock => -32011,
            Self::Memory => -32012,
            Self::Output => -32013,
            Self::ParentDropped => -32014,
            Self::Panic => -32007,
        }
    }

    /// Audit / wire reason string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preempted => "preempted",
            Self::WallClock => "wall-clock",
            Self::Memory => "memory",
            Self::Output => "output",
            Self::ParentDropped => "parent-dropped",
            Self::Panic => "panic",
        }
    }
}

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

/// Outcome of `runtime::invoke` / `run_limited` when not successfully completed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InvokeError {
    /// Sandbox killed.
    #[error("killed: {cause:?}")]
    Killed {
        /// Cause discriminant.
        cause: KillCause,
        /// Usage at kill.
        usage: Usage,
    },
    /// Tool returned `invoke-error`.
    #[error("tool error: {kind}: {message}")]
    ToolError {
        /// WIT variant name.
        kind: String,
        /// Message payload.
        message: String,
        /// Usage at terminal.
        usage: Usage,
    },
    /// Provision / instantiate failed.
    #[error("failed: {reason}")]
    Failed {
        /// Reason.
        reason: String,
        /// Usage (usually zeros).
        usage: Usage,
    },
}

impl InvokeError {
    /// Gateway JSON-RPC code.
    #[must_use]
    pub fn gateway_code(&self) -> i32 {
        match self {
            Self::Killed { cause, .. } => cause.gateway_code(),
            Self::ToolError { kind, .. } => match kind.as_str() {
                "invalid-input" => -32005,
                "capability-denied" => -32006,
                _ => -32007,
            },
            Self::Failed { .. } => RuntimeError::GATEWAY_CODE,
        }
    }

    /// Usage snapshot when present.
    #[must_use]
    pub fn usage(&self) -> Usage {
        match self {
            Self::Killed { usage, .. }
            | Self::ToolError { usage, .. }
            | Self::Failed { usage, .. } => *usage,
        }
    }
}
