//! Full gateway invocation pipeline (HLX-36 / M5-05).
//!
//! State machine: `interfaces/state-machine.md`. Audit via M3 writer; admission
//! via `IdentitySemaphore`; invoke via `helix-runtime` when a tool is registered.

#![allow(
    clippy::too_many_arguments,
    clippy::ref_option,
    clippy::needless_pass_by_value,
    clippy::map_unwrap_or,
    clippy::option_if_let_else,
    clippy::redundant_closure_for_method_calls,
    clippy::must_use_candidate,
    clippy::doc_markdown
)]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use helix_audit::{AuditRecord, AuditWriter, CapsStore, ResourceUsage, Transition, RECORD_VERSION};
use helix_caps::{Identity, RequestId, ResourceBudget, ToolDigest};
use helix_runtime::{invoke, IdentityPermit, IdentitySemaphore, NopHook, Usage};
use serde_json::{json, Value};

use crate::admission::IdentityAdmission;
use crate::config::GatewayConfig;
use crate::envelope::ParsedRequest;
use crate::error_map::{
    self, audit_unavailable, delegation_refused, denied, from_invoke_error, provision_failed,
    record_policy_denied, record_terminal, unknown_tool, usage_json,
};
use crate::request::{Request, RequestBuildError};
use crate::rpc::{self, RpcId};
use crate::tools::ToolRuntime;
use crate::validate::{self, SchemaRegistry};

/// Dependencies for one pipeline run (cloned cheaply via Arc fields).
pub struct PipelineCtx {
    /// Gateway config.
    pub config: Arc<GatewayConfig>,
    /// Audit writer (optional in unit-only tests).
    pub audit: Option<AuditWriter>,
    /// Caps side-file store.
    pub caps: Option<Arc<Mutex<CapsStore>>>,
    /// Per-identity admission map.
    pub admission: IdentityAdmission,
    /// Optional tool runtime.
    pub tools: Option<Arc<ToolRuntime>>,
    /// Input schemas.
    pub schemas: arc_swap::Guard<Arc<SchemaRegistry>>,
}

/// Outcome of alias echo for -32003.
enum ToolKey {
    Alias(String),
    Digest(String),
}

fn wall_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn request_id_bytes(id: RequestId) -> [u8; 16] {
    id.as_u128().to_be_bytes()
}

fn request_id_string(id: RequestId) -> String {
    serde_json::to_value(id)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{}", id.as_u128()))
}

fn identity_label(id: &Identity) -> String {
    data_encoding_base64url(id.as_bytes())
}

fn digest_label(d: &ToolDigest) -> String {
    format!("sha256:{}", helix_runtime::digest_hex(d))
}

fn data_encoding_base64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn budget_usage(b: &ResourceBudget) -> ResourceUsage {
    ResourceUsage::new(
        u64::from(b.preempt_ticks()),
        u64::from(b.wall_clock_ms()),
        b.memory_bytes(),
        u64::from(b.output_bytes()),
    )
}

fn runtime_usage_to_audit(u: Usage) -> ResourceUsage {
    ResourceUsage::new(
        u.preempt_ticks,
        u.wall_ms,
        u.peak_memory_bytes,
        u.output_bytes,
    )
}

fn make_record(
    request_id: RequestId,
    identity: Option<&Identity>,
    digest: Option<&ToolDigest>,
    transition: Transition,
    reason: impl Into<String>,
    caps_hash: Option<[u8; 32]>,
    budget: Option<ResourceUsage>,
    usage: Option<ResourceUsage>,
) -> AuditRecord {
    AuditRecord {
        version: RECORD_VERSION,
        request_id: request_id_bytes(request_id),
        parent: None,
        identity: identity.map(|i| *i.as_bytes()).unwrap_or([0u8; 32]),
        digest: digest.map(|d| *d.as_bytes()).unwrap_or([0u8; 32]),
        transition,
        reason: {
            let mut r = reason.into();
            if r.len() > 256 {
                r.truncate(256);
            }
            r
        },
        caps_hash,
        budget,
        usage,
        wall_time_ns: wall_time_ns(),
        sequence: 0,
    }
}

async fn audit_async(writer: &Option<AuditWriter>, record: AuditRecord) {
    if let Some(w) = writer {
        let _ = w.append_async(record).await;
    }
}

async fn audit_sync(writer: &Option<AuditWriter>, record: AuditRecord) -> Result<(), ()> {
    match writer {
        Some(w) => w.sync(record).await.map_err(|_| ()),
        None => Ok(()),
    }
}

fn ok_json(id: Option<&RpcId>, body: Value) -> Response {
    (StatusCode::OK, Json(rpc::success(id, &body))).into_response()
}

fn err_json(body: Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

fn tool_key_from_params(params: &Value) -> ToolKey {
    if let Some(alias) = params.get("tool").and_then(Value::as_str) {
        ToolKey::Alias(alias.to_owned())
    } else if let Some(d) = params.get("digest").and_then(Value::as_str) {
        ToolKey::Digest(d.to_owned())
    } else {
        ToolKey::Alias(String::new())
    }
}

fn echo_unknown(id: Option<&RpcId>, key: &ToolKey, rid: &str) -> Value {
    match key {
        ToolKey::Alias(a) => unknown_tool(id, "tool", a, rid),
        ToolKey::Digest(d) => unknown_tool(id, "digest", d, rid),
    }
}

/// Run `helix.describe` after authentication.
pub async fn run_describe(
    ctx: &PipelineCtx,
    parsed: &ParsedRequest,
    identity: Identity,
    request_id: RequestId,
    snapshot: helix_policy::PolicyGuard,
) -> Response {
    let rid = request_id_string(request_id);
    let key = tool_key_from_params(&parsed.params);

    // Resolve digest like invoke (alias / digest / both).
    let tool_alias = parsed.params.get("tool").and_then(Value::as_str);
    let digest_str = parsed.params.get("digest").and_then(Value::as_str);
    let resolved = match (tool_alias, digest_str) {
        (None, None) => None,
        (Some(alias), None) => snapshot.resolve_alias(alias),
        (None, Some(d)) => helix_policy::parse_tool_digest("digest", d).ok(),
        (Some(alias), Some(d)) => {
            let provided = helix_policy::parse_tool_digest("digest", d).ok();
            match provided {
                Some(p) => match snapshot.check_alias_digest(alias, &p) {
                    Ok(()) => Some(p),
                    Err(_) => None,
                },
                None => None,
            }
        }
    };

    let Some(digest) = resolved else {
        log::debug!(target: "helix_gateway::describe", "describe miss: unresolved tool");
        audit_async(
            &ctx.audit,
            make_record(
                request_id,
                Some(&identity),
                None,
                Transition::Rejected,
                "unknown_tool",
                None,
                None,
                None,
            ),
        )
        .await;
        return err_json(echo_unknown(parsed.id.as_ref(), &key, &rid));
    };

    let grant = snapshot.policy(&identity, &digest);
    if grant.is_none() {
        log::debug!(
            target: "helix_gateway::describe",
            "describe miss: no grant for identity (treated as unknown_tool)"
        );
        audit_async(
            &ctx.audit,
            make_record(
                request_id,
                Some(&identity),
                Some(&digest),
                Transition::Rejected,
                "unknown_tool",
                None,
                None,
                None,
            ),
        )
        .await;
        return err_json(echo_unknown(parsed.id.as_ref(), &key, &rid));
    }

    // Success → Described (never Authorized/Granted).
    audit_async(
        &ctx.audit,
        make_record(
            request_id,
            Some(&identity),
            Some(&digest),
            Transition::Described,
            "",
            None,
            None,
            None,
        ),
    )
    .await;

    let sig = ctx.tools.as_ref().and_then(|t| t.signature(&digest));

    let Some(sig) = sig else {
        // Granted in policy but no signature loaded — still treat as unknown to caller.
        log::debug!(target: "helix_gateway::describe", "describe miss: no signature bytes");
        return err_json(echo_unknown(parsed.id.as_ref(), &key, &rid));
    };

    ok_json(
        parsed.id.as_ref(),
        json!({
            "name": sig.name,
            "version": sig.version,
            "input-schema": sig.input_schema,
            "output-schema": sig.output_schema,
            "request_id": rid,
        }),
    )
}

/// Run `helix.invoke` after authentication (Received/Parsed/Authenticated done).
#[allow(clippy::too_many_lines)]
pub async fn run_invoke(
    ctx: &PipelineCtx,
    parsed: &ParsedRequest,
    identity: Identity,
    request_id: RequestId,
    snapshot: helix_policy::PolicyGuard,
) -> Response {
    let rid = request_id_string(request_id);
    let rpc_id = parsed.id.as_ref();

    audit_async(
        &ctx.audit,
        make_record(
            request_id,
            Some(&identity),
            None,
            Transition::Received,
            "",
            None,
            None,
            None,
        ),
    )
    .await;

    // Authenticated already verified by caller; write transition.
    audit_async(
        &ctx.audit,
        make_record(
            request_id,
            Some(&identity),
            None,
            Transition::Authenticated,
            "",
            None,
            None,
            None,
        ),
    )
    .await;

    let req = match Request::from_invoke(parsed, identity, snapshot.clone(), request_id) {
        Ok(r) => r,
        Err(RequestBuildError::InvalidParams(reason)) => {
            return err_json(error_map::invalid_params_path(
                rpc_id,
                "/params",
                reason,
                Some(&rid),
            ));
        }
        Err(RequestBuildError::BadInput) => {
            return err_json(error_map::invalid_params_path(
                rpc_id,
                "/input",
                "input_must_be_object",
                Some(&rid),
            ));
        }
        Err(RequestBuildError::UnknownTool(e)) => {
            let key = match &e {
                helix_policy::AliasDigestError::UnknownAlias { alias }
                | helix_policy::AliasDigestError::Disagreement { alias, .. } => {
                    ToolKey::Alias(alias.clone())
                }
            };
            audit_async(
                &ctx.audit,
                make_record(
                    request_id,
                    Some(&identity),
                    None,
                    Transition::Rejected,
                    "unknown_tool",
                    None,
                    None,
                    None,
                ),
            )
            .await;
            return err_json(echo_unknown(rpc_id, &key, &rid));
        }
    };

    let digest = req.tool;
    let id_label = identity_label(&identity);
    let dig_label = digest_label(&digest);

    // Policy hit?
    let Some((caps, budget)) = req
        .snapshot
        .policy(&identity, &digest)
        .map(|(c, b)| (c.clone(), *b))
    else {
        record_policy_denied(&id_label, &dig_label);
        audit_async(
            &ctx.audit,
            make_record(
                request_id,
                Some(&identity),
                Some(&digest),
                Transition::Denied,
                "",
                None,
                None,
                None,
            ),
        )
        .await;
        return err_json(denied(
            rpc_id,
            "policy",
            &rid,
            ctx.config.verbose_denials,
            None,
            None,
        ));
    };

    // Payload validation (Authenticated → Authorized gate).
    if let Some(schema) = ctx.schemas.get(&digest) {
        if let Err(err) = validate::payload(schema.as_ref(), &req.payload) {
            audit_async(
                &ctx.audit,
                make_record(
                    request_id,
                    Some(&identity),
                    Some(&digest),
                    Transition::Rejected,
                    "invalid_params",
                    None,
                    None,
                    None,
                ),
            )
            .await;
            return err_json(validate::invalid_params(rpc_id, &err, Some(&rid)));
        }
    }

    // Per-identity concurrency.
    let limit = budget.max_concurrent_instances();
    let Some((permit, _sem)) = ctx.admission.try_acquire_root(identity, limit, &id_label) else {
        audit_async(
            &ctx.audit,
            make_record(
                request_id,
                Some(&identity),
                Some(&digest),
                Transition::Denied,
                "concurrency",
                None,
                None,
                None,
            ),
        )
        .await;
        return err_json(denied(
            rpc_id,
            "concurrency",
            &rid,
            ctx.config.verbose_denials,
            Some((&caps, &budget)),
            None,
        ));
    };
    // Hold permit until end of function.
    let _permit: IdentityPermit = permit;

    audit_async(
        &ctx.audit,
        make_record(
            request_id,
            Some(&identity),
            Some(&digest),
            Transition::Authorized,
            "",
            None,
            None,
            None,
        ),
    )
    .await;

    // Caps hash for Granted.
    let caps_hash = if let Some(store) = &ctx.caps {
        match store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ensure(&caps)
        {
            Ok(h) => Some(h),
            Err(e) => {
                log::error!(target: "helix_gateway::pipeline", "caps store error: {e}");
                None
            }
        }
    } else {
        helix_audit::CapsStore::hash(&caps).ok()
    };

    let granted = make_record(
        request_id,
        Some(&identity),
        Some(&digest),
        Transition::Granted,
        "",
        caps_hash,
        Some(budget_usage(&budget)),
        None,
    );
    if audit_sync(&ctx.audit, granted).await.is_err() {
        return err_json(audit_unavailable(rpc_id, &rid));
    }

    // Optional test hold (GW-15): block after Granted, still holding permit.
    if let Some(tools) = &ctx.tools {
        if let Some(hold) = &tools.hold {
            hold.notified().await;
        }
    }

    let Some(tools) = ctx.tools.as_ref() else {
        let failed = make_record(
            request_id,
            Some(&identity),
            Some(&digest),
            Transition::Failed,
            "provision",
            None,
            None,
            None,
        );
        if audit_sync(&ctx.audit, failed).await.is_err() {
            return err_json(audit_unavailable(rpc_id, &rid));
        }
        record_terminal("Failed");
        return err_json(provision_failed(rpc_id, "no_runtime", &rid));
    };

    let Some(loaded) = tools.get(&digest) else {
        let failed = make_record(
            request_id,
            Some(&identity),
            Some(&digest),
            Transition::Failed,
            "provision",
            None,
            None,
            None,
        );
        if audit_sync(&ctx.audit, failed).await.is_err() {
            return err_json(audit_unavailable(rpc_id, &rid));
        }
        record_terminal("Failed");
        return err_json(provision_failed(rpc_id, "artifact_missing", &rid));
    };

    // Provisioned + Running (async audit).
    tools.note_instantiate();
    audit_async(
        &ctx.audit,
        make_record(
            request_id,
            Some(&identity),
            Some(&digest),
            Transition::Provisioned,
            "",
            None,
            None,
            None,
        ),
    )
    .await;
    audit_async(
        &ctx.audit,
        make_record(
            request_id,
            Some(&identity),
            Some(&digest),
            Transition::Running,
            "",
            None,
            None,
            None,
        ),
    )
    .await;

    let mut hook = NopHook;
    let result = invoke(
        tools.engine(),
        &loaded.component,
        &caps,
        &budget,
        &req.payload,
        &mut hook,
    );

    match result {
        Ok(success) => {
            let terminal = make_record(
                request_id,
                Some(&identity),
                Some(&digest),
                Transition::Completed,
                "",
                None,
                None,
                Some(runtime_usage_to_audit(success.usage)),
            );
            if audit_sync(&ctx.audit, terminal).await.is_err() {
                return err_json(audit_unavailable(rpc_id, &rid));
            }
            record_terminal("Completed");
            let output: Value =
                serde_json::from_slice(&success.output).unwrap_or_else(|_| json!({}));
            ok_json(
                rpc_id,
                json!({
                    "output": output,
                    "usage": usage_json(success.usage),
                    "request_id": rid,
                }),
            )
        }
        Err(err) => {
            let (transition, reason, usage) = match &err {
                helix_runtime::InvokeError::Failed { usage, .. } => {
                    (Transition::Failed, "provision".to_owned(), *usage)
                }
                helix_runtime::InvokeError::ToolError { kind, usage, .. } => {
                    (Transition::ToolError, kind.clone(), *usage)
                }
                helix_runtime::InvokeError::Killed { cause, usage } => {
                    (Transition::Killed, cause.as_str().to_owned(), *usage)
                }
            };
            let terminal = make_record(
                request_id,
                Some(&identity),
                Some(&digest),
                transition,
                reason,
                None,
                None,
                Some(runtime_usage_to_audit(usage)),
            );
            if audit_sync(&ctx.audit, terminal).await.is_err() {
                return err_json(audit_unavailable(rpc_id, &rid));
            }
            let (code, data, label) = from_invoke_error(&err, &rid);
            record_terminal(label);
            err_json(rpc::error(rpc_id, code, Some(data)))
        }
    }
}

/// Auth-fail path: write AuthFailed and return -32001.
pub async fn auth_failed(
    audit: &Option<AuditWriter>,
    request_id: RequestId,
    reason: &str,
    rpc_id: Option<&RpcId>,
) -> Response {
    let rid = request_id_string(request_id);
    audit_async(
        audit,
        make_record(
            request_id,
            None,
            None,
            Transition::AuthFailed,
            reason,
            None,
            None,
            None,
        ),
    )
    .await;
    err_json(error_map::unauthenticated(rpc_id, reason, Some(&rid)))
}

/// Root -32020 helper (when params cannot be admitted).
#[allow(dead_code)]
pub fn refuse_root_delegation(rpc_id: Option<&RpcId>, reason: &str, rid: &str) -> Response {
    err_json(delegation_refused(rpc_id, reason, rid))
}

/// Expose IdentitySemaphore type for children (re-export path).
pub type SharedIdentitySemaphore = Arc<IdentitySemaphore>;
