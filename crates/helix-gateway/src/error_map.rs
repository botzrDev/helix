//! JSON-RPC error map from `interfaces/state-machine.md` / gateway-protocol §4.
//!
//! Cites: ADR-008 D.3 (`-32030`), F.4 (`verbose_denials`); ADR-009 B.1 / B.2.

use helix_audit::{capability_set_to_json, AuditError};
use helix_caps::{CapabilitySet, ResourceBudget};
use helix_runtime::{InvokeError, KillCause, Usage};
use serde_json::{json, Value};

use crate::rpc::{self, RpcCode, RpcId};

/// Metric: invocations by terminal label.
pub const METRIC_INVOCATIONS_TOTAL: &str = "helix_invocations_total";
/// Metric: policy denials by identity+digest.
pub const METRIC_POLICY_DENIED: &str = "helix_policy_denied_total";
/// Gauge: live instances per identity.
pub const METRIC_IDENTITY_IN_USE: &str = "helix_identity_in_use";

/// Build error envelope with optional `request_id` merged into `data`.
#[must_use]
pub fn error_with_request_id(
    id: Option<&RpcId>,
    code: RpcCode,
    mut data: Value,
    request_id: Option<&str>,
) -> Value {
    if let Some(rid) = request_id {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("request_id".to_owned(), Value::String(rid.to_owned()));
        } else if data.is_null() {
            data = json!({ "request_id": rid });
        } else {
            data = json!({ "detail": data, "request_id": rid });
        }
    }
    rpc::error(id, code, Some(data))
}

/// `-32030 Audit unavailable` — `request_id` only.
#[must_use]
pub fn audit_unavailable(id: Option<&RpcId>, request_id: &str) -> Value {
    let _ = AuditError::GATEWAY_CODE;
    rpc::error(
        id,
        RpcCode::AuditUnavailable,
        Some(json!({ "request_id": request_id })),
    )
}

/// `-32001` with closed reason set.
#[must_use]
pub fn unauthenticated(id: Option<&RpcId>, reason: &str, request_id: Option<&str>) -> Value {
    error_with_request_id(
        id,
        RpcCode::Unauthenticated,
        json!({ "reason": reason }),
        request_id,
    )
}

/// `-32002` policy miss or concurrency.
#[must_use]
pub fn denied(
    id: Option<&RpcId>,
    reason: &str,
    request_id: &str,
    verbose: bool,
    requested: Option<(&CapabilitySet, &ResourceBudget)>,
    available: Option<(&CapabilitySet, &ResourceBudget)>,
) -> Value {
    let mut data = json!({ "reason": reason, "request_id": request_id });
    if verbose {
        if let Some((caps, budget)) = requested {
            data["requested"] = caps_budget_json(caps, budget);
        }
        if let Some((caps, budget)) = available {
            data["available"] = caps_budget_json(caps, budget);
        }
    }
    rpc::error(id, RpcCode::Denied, Some(data))
}

/// `-32003` unknown / ungranted tool.
#[must_use]
pub fn unknown_tool(id: Option<&RpcId>, key: &str, value: &str, request_id: &str) -> Value {
    rpc::error(
        id,
        RpcCode::UnknownTool,
        Some(json!({ key: value, "request_id": request_id })),
    )
}

/// `-32004` provision failed.
#[must_use]
pub fn provision_failed(id: Option<&RpcId>, reason: &str, request_id: &str) -> Value {
    rpc::error(
        id,
        RpcCode::ProvisionFailed,
        Some(json!({ "reason": reason, "request_id": request_id })),
    )
}

/// `-32020` root admission delegation refused.
#[must_use]
pub fn delegation_refused(id: Option<&RpcId>, reason: &str, request_id: &str) -> Value {
    rpc::error(
        id,
        RpcCode::DelegationRefused,
        Some(json!({ "reason": reason, "request_id": request_id })),
    )
}

/// `-32602` with path.
#[must_use]
pub fn invalid_params_path(
    id: Option<&RpcId>,
    path: &str,
    reason: &str,
    request_id: Option<&str>,
) -> Value {
    let mut data = json!({ "path": path, "reason": reason });
    if let Some(rid) = request_id {
        data["request_id"] = Value::String(rid.to_owned());
    }
    rpc::error(id, RpcCode::InvalidParams, Some(data))
}

fn caps_budget_json(caps: &CapabilitySet, budget: &ResourceBudget) -> Value {
    let mut v = capability_set_to_json(caps);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "budget".to_owned(),
            serde_json::to_value(budget).unwrap_or(Value::Null),
        );
    }
    v
}

/// Map runtime [`Usage`] to JSON.
#[must_use]
pub fn usage_json(u: Usage) -> Value {
    json!({
        "wall_ms": u.wall_ms,
        "preempt_ticks": u.preempt_ticks,
        "peak_memory_bytes": u.peak_memory_bytes,
        "output_bytes": u.output_bytes,
    })
}

/// Map invoke failure to `(RpcCode, data, terminal_label)`.
#[must_use]
pub fn from_invoke_error(err: &InvokeError, request_id: &str) -> (RpcCode, Value, &'static str) {
    match err {
        InvokeError::Failed { reason, .. } => (
            RpcCode::ProvisionFailed,
            json!({ "reason": reason, "request_id": request_id }),
            "Failed",
        ),
        InvokeError::ToolError { kind, message, .. } => match kind.as_str() {
            "invalid-input" => (
                RpcCode::ToolInvalidInput,
                json!({ "message": message, "request_id": request_id }),
                "ToolError",
            ),
            "capability-denied" => (
                RpcCode::ToolCapabilityDenied,
                json!({ "message": message, "request_id": request_id }),
                "ToolError",
            ),
            _ => (
                RpcCode::ToolInternal,
                json!({ "request_id": request_id }),
                "ToolError",
            ),
        },
        InvokeError::Killed { cause, usage } => {
            let (code, label) = kill_code(*cause);
            let data = match cause {
                KillCause::ParentDropped | KillCause::Panic => {
                    json!({ "request_id": request_id })
                }
                _ => json!({ "usage": usage_json(*usage), "request_id": request_id }),
            };
            (code, data, label)
        }
    }
}

fn kill_code(cause: KillCause) -> (RpcCode, &'static str) {
    match cause {
        KillCause::Preempted => (RpcCode::KilledPreempted, "Killed"),
        KillCause::WallClock => (RpcCode::KilledWallClock, "Killed"),
        KillCause::Memory => (RpcCode::KilledMemory, "Killed"),
        KillCause::Output => (RpcCode::KilledOutput, "Killed"),
        KillCause::ParentDropped => (RpcCode::KilledParentDropped, "Killed"),
        KillCause::Panic => (RpcCode::ToolInternal, "Killed"),
    }
}

/// Record `helix_invocations_total{terminal}`.
pub fn record_terminal(terminal: &str) {
    metrics::counter!(METRIC_INVOCATIONS_TOTAL, "terminal" => terminal.to_owned()).increment(1);
}

/// Record policy denial metric.
pub fn record_policy_denied(identity_hex: &str, digest_hex: &str) {
    metrics::counter!(
        METRIC_POLICY_DENIED,
        "identity" => identity_hex.to_owned(),
        "digest" => digest_hex.to_owned()
    )
    .increment(1);
}
