//! Typed wrapper around `helix:delegate/invoke` (ADR-009 A.2).

use crate::types::{
    CapabilitySet, FileGrant, FileMode, HostGrant, KillCause, ResourceBudget, ResourceUsage,
    ToolRef,
};
use crate::ToolError;
use serde::de::DeserializeOwned;
use serde::Serialize;

use helix_sdk_wit::helix::tool::caps as wit_caps;
use helix_sdk_wit::helix::tool::delegate as wit_delegate;
use helix_sdk_wit::helix::tool::types::InvokeError as WitInvokeError;

/// Successful child invocation (typed over the child's output).
#[derive(Debug, Clone)]
pub struct DelegationResult<O> {
    /// Child request id.
    pub request_id: String,
    /// Resolved child digest.
    pub digest: Vec<u8>,
    /// Deserialized child output.
    pub output: O,
    /// Child resource usage.
    pub usage: ResourceUsage,
}

/// Errors from [`delegate`] / [`invoke`](self::invoke).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegateError {
    /// Child alias/digest does not resolve.
    #[error("unknown tool")]
    UnknownTool,
    /// Policy miss or per-identity concurrency exhausted.
    #[error("denied")]
    Denied,
    /// Requested set is not a subset of the parent effective set.
    #[error("escalation: {0}")]
    Escalation(String),
    /// `max_delegation_depth` exceeded.
    #[error("depth")]
    Depth,
    /// `max_children` exceeded.
    #[error("fanout")]
    Fanout,
    /// Parent policy guard older than `max_snapshot_age_s`.
    #[error("stale snapshot")]
    StaleSnapshot,
    /// Child input failed the child's `input-schema`.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Audit store could not make Granted/terminal durable.
    #[error("audit unavailable")]
    AuditUnavailable,
    /// Provision failure.
    #[error("child failed: {0}")]
    ChildFailed(String),
    /// Child hit its own budget / parent-dropped.
    #[error("child killed: {0:?}")]
    ChildKilled(KillCause),
    /// Child returned an `invoke-error`.
    #[error("child tool error: {0}")]
    ChildToolError(ToolError),
    /// Local serde failure before/after the host call.
    #[error("codec: {0}")]
    Codec(String),
}

/// Typed `helix:delegate/invoke` (ADR-009 A.2 / ticket HLX-38).
///
/// Serializes `input`, calls the host import, and deserializes the child output.
///
/// # Errors
///
/// Returns [`DelegateError`] for host refusals, child failures, or codec errors.
pub fn delegate<I, O>(
    tool: ToolRef,
    requested: CapabilitySet,
    budget: Option<ResourceBudget>,
    input: &I,
) -> Result<DelegationResult<O>, DelegateError>
where
    I: Serialize,
    O: DeserializeOwned,
{
    invoke(tool, requested, budget, input)
}

/// /// Same as [`crate::delegate`]; matches `tool-author-guide.md` §9 (`delegate::invoke`).
///
/// # Errors
///
/// See [`delegate`].
pub fn invoke<I, O>(
    tool: ToolRef,
    requested: CapabilitySet,
    budget: Option<ResourceBudget>,
    input: &I,
) -> Result<DelegationResult<O>, DelegateError>
where
    I: Serialize,
    O: DeserializeOwned,
{
    let input_bytes = serde_json::to_vec(input).map_err(|e| DelegateError::Codec(e.to_string()))?;
    let req = wit_delegate::DelegationRequest {
        tool: to_wit_tool(tool),
        requested: to_wit_caps(requested),
        budget: budget.map(to_wit_budget),
        input: input_bytes,
    };
    match wit_delegate::invoke(&req) {
        Ok(raw) => {
            let output: O = serde_json::from_slice(&raw.output)
                .map_err(|e| DelegateError::Codec(e.to_string()))?;
            Ok(DelegationResult {
                request_id: raw.request_id,
                digest: raw.digest,
                output,
                usage: from_wit_usage(raw.usage),
            })
        }
        Err(e) => Err(from_wit_error(e)),
    }
}

fn to_wit_tool(tool: ToolRef) -> wit_delegate::ToolRef {
    match tool {
        ToolRef::Alias(a) => wit_delegate::ToolRef::Alias(a),
        ToolRef::Digest(d) => wit_delegate::ToolRef::Digest(d),
    }
}

fn to_wit_mode(mode: FileMode) -> wit_caps::FileMode {
    match mode {
        FileMode::Read => wit_caps::FileMode::Read,
        FileMode::ReadWrite => wit_caps::FileMode::ReadWrite,
    }
}

fn to_wit_caps(set: CapabilitySet) -> wit_caps::CapabilitySet {
    wit_caps::CapabilitySet {
        interfaces: set.interfaces,
        files: set
            .files
            .into_iter()
            .map(
                |FileGrant {
                     canonical_path,
                     mode,
                 }| wit_caps::FileGrant {
                    canonical_path,
                    mode: to_wit_mode(mode),
                },
            )
            .collect(),
        hosts: set
            .hosts
            .into_iter()
            .map(|HostGrant { authority, methods }| wit_caps::HostGrant { authority, methods })
            .collect(),
    }
}

fn to_wit_budget(b: ResourceBudget) -> wit_caps::ResourceBudget {
    wit_caps::ResourceBudget {
        preempt_ticks: b.preempt_ticks,
        wall_clock_ms: b.wall_clock_ms,
        memory_bytes: b.memory_bytes,
        output_bytes: b.output_bytes,
        max_delegation_depth: b.max_delegation_depth,
        max_children: b.max_children,
        max_concurrent_instances: b.max_concurrent_instances,
    }
}

fn from_wit_usage(u: wit_caps::ResourceUsage) -> ResourceUsage {
    ResourceUsage {
        preempt_ticks: u.preempt_ticks,
        wall_clock_ms: u.wall_clock_ms,
        memory_bytes: u.memory_bytes,
        output_bytes: u.output_bytes,
    }
}

fn from_wit_kill(k: wit_delegate::KillCause) -> KillCause {
    match k {
        wit_delegate::KillCause::Preempted => KillCause::Preempted,
        wit_delegate::KillCause::WallClock => KillCause::WallClock,
        wit_delegate::KillCause::Memory => KillCause::Memory,
        wit_delegate::KillCause::Output => KillCause::Output,
        wit_delegate::KillCause::ParentDropped => KillCause::ParentDropped,
    }
}

fn from_wit_tool_error(e: WitInvokeError) -> ToolError {
    match e {
        WitInvokeError::InvalidInput(m) => ToolError::InvalidInput(m),
        WitInvokeError::CapabilityDenied(m) => ToolError::CapabilityDenied(m),
        WitInvokeError::Internal(m) => ToolError::Internal(m),
    }
}

fn from_wit_error(e: wit_delegate::DelegateError) -> DelegateError {
    use wit_delegate::DelegateError as E;
    match e {
        E::UnknownTool => DelegateError::UnknownTool,
        E::Denied => DelegateError::Denied,
        E::Escalation(s) => DelegateError::Escalation(s),
        E::Depth => DelegateError::Depth,
        E::Fanout => DelegateError::Fanout,
        E::StaleSnapshot => DelegateError::StaleSnapshot,
        E::InvalidInput(s) => DelegateError::InvalidInput(s),
        E::AuditUnavailable => DelegateError::AuditUnavailable,
        E::ChildFailed(s) => DelegateError::ChildFailed(s),
        E::ChildKilled(k) => DelegateError::ChildKilled(from_wit_kill(k)),
        E::ChildToolError(t) => DelegateError::ChildToolError(from_wit_tool_error(t)),
    }
}
