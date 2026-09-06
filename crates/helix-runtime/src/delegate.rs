//! Host implementation of `helix:delegate/invoke` (M4-08 / HLX-31).
//!
//! This is the **only** path that creates a child invocation (ADR-009 A.1).
//! Composition uses [`helix_policy::effective`]; bounds use depth +
//! [`JoinSet::len`]; per-identity concurrency uses
//! [`crate::admission::IdentitySemaphore`].
//!
//! Parent blocks in the host call; the parent's wall clock keeps running.
//! Child terminals map to `delegate-error` variants and are **error values**
//! to the parent, not a kill of the parent (except when the parent's own
//! token fires mid-wait → trap → `Killed(WallClock)`, RT-16).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use helix_audit::{sha256_32, CapsStore};
use helix_caps::{
    CapabilitySet, FileMode, HostGrant, Identity, Interface, Method, MethodMask, RequestId,
    ResourceBudget, ToolDigest,
};
use helix_policy::{
    check_depth, check_fanout, effective_budget, effective_caps, intern_against_guard,
    DelegationRefuse, PolicyGuard,
};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use wasmtime::component::{Component, ComponentType, Lift, Lower};
use wasmtime::{Engine, Store};

use crate::admission::{IdentityPermit, IdentitySemaphore};
use crate::cancel;
use crate::error::{InvokeError, KillCause, RuntimeError, Usage};
use crate::http::WALL_CLOCK_TRAP_MSG;
use crate::invoke::{
    deliver_output, preempt_deadline_ticks, InvokeHost, RecordingHook, TerminalGuard, TerminalHook,
    TerminalKind,
};
use crate::link;

/// Metric: child Stores provisioned (tests assert zero on refusal).
pub const METRIC_CHILD_STORE_CREATED: &str = "helix_delegate_child_store_created_total";

/// How tools are resolved for a child digest (tests / gateway wiring).
pub trait ToolResolver: Send + Sync {
    /// Resolve `digest` to a compiled [`Component`] and its input JSON Schema.
    fn resolve(&self, digest: &ToolDigest) -> Option<(Component, String)>;
}

/// In-memory digest → (component, input-schema) map for RT fixtures.
#[derive(Default)]
pub struct MapToolResolver {
    inner: Mutex<HashMap<[u8; 32], (Component, String)>>,
}

impl MapToolResolver {
    /// Empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a component under `digest`.
    pub fn insert(
        &self,
        digest: ToolDigest,
        component: Component,
        input_schema: impl Into<String>,
    ) {
        self.inner
            .lock()
            .expect("resolver")
            .insert(*digest.as_bytes(), (component, input_schema.into()));
    }
}

impl ToolResolver for MapToolResolver {
    fn resolve(&self, digest: &ToolDigest) -> Option<(Component, String)> {
        self.inner
            .lock()
            .expect("resolver")
            .get(digest.as_bytes())
            .map(|(c, s)| (c.clone(), s.clone()))
    }
}

impl ToolResolver for Arc<MapToolResolver> {
    fn resolve(&self, digest: &ToolDigest) -> Option<(Component, String)> {
        (**self).resolve(digest)
    }
}

/// Audit sink for delegation refusals and dual `caps_hash` (RT-13).
pub trait DelegationAudit: Send + Sync {
    /// Record `DelegationRefused{reason}` under the **parent** request id.
    fn delegation_refused(
        &self,
        parent_request_id: RequestId,
        identity: Identity,
        digest: ToolDigest,
        reason: &str,
        requested_caps_hash: Option<[u8; 32]>,
        available_caps_hash: Option<[u8; 32]>,
    );

    /// Record a child terminal (Granted…terminal chain is gateway-owned; tests
    /// collect Killed/Completed here).
    fn child_terminal(&self, record: ChildAuditRecord);
}

/// Minimal child audit row for RT-15 / RT-16.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildAuditRecord {
    /// Child request id.
    pub request_id: RequestId,
    /// Parent request id.
    pub parent: RequestId,
    /// Terminal kind.
    pub kind: TerminalKind,
    /// Usage.
    pub usage: Usage,
}

/// Collecting audit double for RT-13…RT-16.
#[derive(Debug, Default)]
pub struct RecordingDelegationAudit {
    /// Refusal rows (parent id).
    pub refusals: Mutex<Vec<RefusalRecord>>,
    /// Child terminals.
    pub children: Mutex<Vec<ChildAuditRecord>>,
}

/// One `DelegationRefused` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalRecord {
    /// Parent request id.
    pub parent_request_id: RequestId,
    /// Reason (`escalation`, `depth`, `fanout`, …).
    pub reason: String,
    /// Requested set hash (side file).
    pub requested_caps_hash: Option<[u8; 32]>,
    /// Available (parent effective) hash (side file).
    pub available_caps_hash: Option<[u8; 32]>,
}

impl DelegationAudit for RecordingDelegationAudit {
    fn delegation_refused(
        &self,
        parent_request_id: RequestId,
        _identity: Identity,
        _digest: ToolDigest,
        reason: &str,
        requested_caps_hash: Option<[u8; 32]>,
        available_caps_hash: Option<[u8; 32]>,
    ) {
        self.refusals.lock().expect("refusals").push(RefusalRecord {
            parent_request_id,
            reason: reason.to_owned(),
            requested_caps_hash,
            available_caps_hash,
        });
    }

    fn child_terminal(&self, record: ChildAuditRecord) {
        self.children.lock().expect("children").push(record);
    }
}

impl DelegationAudit for Arc<RecordingDelegationAudit> {
    fn delegation_refused(
        &self,
        parent_request_id: RequestId,
        identity: Identity,
        digest: ToolDigest,
        reason: &str,
        requested_caps_hash: Option<[u8; 32]>,
        available_caps_hash: Option<[u8; 32]>,
    ) {
        (**self).delegation_refused(
            parent_request_id,
            identity,
            digest,
            reason,
            requested_caps_hash,
            available_caps_hash,
        );
    }

    fn child_terminal(&self, record: ChildAuditRecord) {
        (**self).child_terminal(record);
    }
}

/// No-op audit.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopDelegationAudit;

impl DelegationAudit for NopDelegationAudit {
    fn delegation_refused(
        &self,
        _parent_request_id: RequestId,
        _identity: Identity,
        _digest: ToolDigest,
        _reason: &str,
        _requested_caps_hash: Option<[u8; 32]>,
        _available_caps_hash: Option<[u8; 32]>,
    ) {
    }

    fn child_terminal(&self, _record: ChildAuditRecord) {}
}

/// Per-request delegation / admission context carried on [`InvokeHost`].
pub struct DelegationCtx {
    /// This invocation's request id.
    pub request_id: RequestId,
    /// Parent request id (`None` for roots).
    pub parent: Option<RequestId>,
    /// Caller identity (child inherits).
    pub identity: Identity,
    /// Tool digest of this invocation.
    pub digest: ToolDigest,
    /// Depth from root (root = 0).
    pub depth: u32,
    /// Inherited policy guard.
    pub guard: PolicyGuard,
    /// This invocation's effective caps.
    pub effective: CapabilitySet,
    /// This invocation's budget.
    pub budget: ResourceBudget,
    /// Per-identity semaphore handle (gateway- or test-owned instance).
    pub semaphore: Arc<IdentitySemaphore>,
    /// Root / parent cancellation token.
    pub token: CancellationToken,
    /// Child tasks (fan-out counted via `JoinSet::len` at call time).
    pub children: JoinSet<ChildTaskResult>,
    /// Tool resolver.
    pub tools: Arc<dyn ToolResolver>,
    /// Audit sink.
    pub audit: Arc<dyn DelegationAudit>,
    /// Optional caps side-file store for RT-13 dual hashes.
    pub caps_store: Option<Mutex<CapsStore>>,
    /// Test counter: child Stores created.
    pub store_creations: Arc<AtomicUsize>,
    /// Engine for child provision.
    pub engine: Engine,
}

impl std::fmt::Debug for DelegationCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationCtx")
            .field("request_id", &self.request_id)
            .field("depth", &self.depth)
            .field("child_count", &self.children.len())
            .finish_non_exhaustive()
    }
}

/// Result of a `JoinSet` child task.
#[derive(Debug)]
pub struct ChildTaskResult {
    /// Child request id.
    pub request_id: RequestId,
    /// Outcome.
    pub outcome: Result<DelegationSuccess, DelegateError>,
}

/// Successful child result (host-memory output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationSuccess {
    /// Child request id (ULID string form for WIT).
    pub request_id: RequestId,
    /// Child tool digest.
    pub digest: ToolDigest,
    /// Bounded output bytes.
    pub output: Vec<u8>,
    /// Usage.
    pub usage: Usage,
}

/// WIT / host `delegate-error` (mirrors `wit/helix-tool.wit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegateError {
    /// Unknown tool alias/digest.
    UnknownTool,
    /// Policy miss or concurrency denied.
    Denied,
    /// Escalation with message.
    Escalation(String),
    /// Depth bound.
    Depth,
    /// Fan-out bound.
    Fanout,
    /// Stale parent guard.
    StaleSnapshot,
    /// Input failed child schema.
    InvalidInput(String),
    /// Audit unavailable.
    AuditUnavailable,
    /// Provision failure.
    ChildFailed(String),
    /// Child killed.
    ChildKilled(KillCause),
    /// Child returned invoke-error.
    ChildToolError {
        /// Kind.
        kind: String,
        /// Message.
        message: String,
    },
}

impl DelegateError {
    /// WIT-ish discriminant name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::UnknownTool => "unknown-tool",
            Self::Denied => "denied",
            Self::Escalation(_) => "escalation",
            Self::Depth => "depth",
            Self::Fanout => "fanout",
            Self::StaleSnapshot => "stale-snapshot",
            Self::InvalidInput(_) => "invalid-input",
            Self::AuditUnavailable => "audit-unavailable",
            Self::ChildFailed(_) => "child-failed",
            Self::ChildKilled(_) => "child-killed",
            Self::ChildToolError { .. } => "child-tool-error",
        }
    }
}

// --- WIT wire shapes (helix:tool/caps + delegate) --------------------------------

#[derive(Debug, Clone, Copy, ComponentType, Lift, Lower)]
#[component(enum)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum WitFileMode {
    #[component(name = "read")]
    Read,
    #[component(name = "read-write")]
    ReadWrite,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitFileGrant {
    #[component(name = "canonical-path")]
    canonical_path: String,
    mode: WitFileMode,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitHostGrant {
    authority: String,
    methods: u8,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitCapabilitySet {
    interfaces: u64,
    files: Vec<WitFileGrant>,
    hosts: Vec<WitHostGrant>,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitResourceBudget {
    #[component(name = "preempt-ticks")]
    preempt_ticks: u32,
    #[component(name = "wall-clock-ms")]
    wall_clock_ms: u32,
    #[component(name = "memory-bytes")]
    memory_bytes: u64,
    #[component(name = "output-bytes")]
    output_bytes: u32,
    #[component(name = "max-delegation-depth")]
    max_delegation_depth: u32,
    #[component(name = "max-children")]
    max_children: u32,
    #[component(name = "max-concurrent-instances")]
    max_concurrent_instances: u32,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitResourceUsage {
    #[component(name = "preempt-ticks")]
    preempt_ticks: u32,
    #[component(name = "wall-clock-ms")]
    wall_clock_ms: u32,
    #[component(name = "memory-bytes")]
    memory_bytes: u64,
    #[component(name = "output-bytes")]
    output_bytes: u32,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(variant)]
pub(crate) enum WitToolRef {
    #[component(name = "alias")]
    Alias(String),
    #[component(name = "digest")]
    Digest(Vec<u8>),
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitDelegationRequest {
    tool: WitToolRef,
    requested: WitCapabilitySet,
    budget: Option<WitResourceBudget>,
    input: Vec<u8>,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub(crate) struct WitDelegationResult {
    #[component(name = "request-id")]
    request_id: String,
    digest: Vec<u8>,
    output: Vec<u8>,
    usage: WitResourceUsage,
}

#[derive(Debug, Clone, Copy, ComponentType, Lift, Lower)]
#[component(enum)]
#[repr(u8)]
pub(crate) enum WitKillCause {
    #[component(name = "preempted")]
    Preempted,
    #[component(name = "wall-clock")]
    WallClock,
    #[component(name = "memory")]
    Memory,
    #[component(name = "output")]
    Output,
    #[component(name = "parent-dropped")]
    ParentDropped,
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(variant)]
pub(crate) enum WitInvokeError {
    #[component(name = "invalid-input")]
    InvalidInput(String),
    #[component(name = "capability-denied")]
    CapabilityDenied(String),
    #[component(name = "internal")]
    Internal(String),
}

#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(variant)]
pub(crate) enum WitDelegateError {
    #[component(name = "unknown-tool")]
    UnknownTool,
    #[component(name = "denied")]
    Denied,
    #[component(name = "escalation")]
    Escalation(String),
    #[component(name = "depth")]
    Depth,
    #[component(name = "fanout")]
    Fanout,
    #[component(name = "stale-snapshot")]
    StaleSnapshot,
    #[component(name = "invalid-input")]
    InvalidInput(String),
    #[component(name = "audit-unavailable")]
    AuditUnavailable,
    #[component(name = "child-failed")]
    ChildFailed(String),
    #[component(name = "child-killed")]
    ChildKilled(WitKillCause),
    #[component(name = "child-tool-error")]
    ChildToolError(WitInvokeError),
}

fn wit_kill(cause: KillCause) -> WitKillCause {
    match cause {
        KillCause::Preempted | KillCause::Panic => WitKillCause::Preempted,
        KillCause::WallClock => WitKillCause::WallClock,
        KillCause::Memory => WitKillCause::Memory,
        KillCause::Output => WitKillCause::Output,
        KillCause::ParentDropped => WitKillCause::ParentDropped,
    }
}

fn to_wit_error(err: DelegateError) -> WitDelegateError {
    match err {
        DelegateError::UnknownTool => WitDelegateError::UnknownTool,
        DelegateError::Denied => WitDelegateError::Denied,
        DelegateError::Escalation(s) => WitDelegateError::Escalation(s),
        DelegateError::Depth => WitDelegateError::Depth,
        DelegateError::Fanout => WitDelegateError::Fanout,
        DelegateError::StaleSnapshot => WitDelegateError::StaleSnapshot,
        DelegateError::InvalidInput(s) => WitDelegateError::InvalidInput(s),
        DelegateError::AuditUnavailable => WitDelegateError::AuditUnavailable,
        DelegateError::ChildFailed(s) => WitDelegateError::ChildFailed(s),
        DelegateError::ChildKilled(c) => WitDelegateError::ChildKilled(wit_kill(c)),
        DelegateError::ChildToolError { kind, message } => {
            let ie = match kind.as_str() {
                "invalid-input" => WitInvokeError::InvalidInput(message),
                "capability-denied" => WitInvokeError::CapabilityDenied(message),
                _ => WitInvokeError::Internal(message),
            };
            WitDelegateError::ChildToolError(ie)
        }
    }
}

fn usage_to_wit(u: Usage) -> WitResourceUsage {
    WitResourceUsage {
        preempt_ticks: u32::try_from(u.preempt_ticks).unwrap_or(u32::MAX),
        wall_clock_ms: u32::try_from(u.wall_ms).unwrap_or(u32::MAX),
        memory_bytes: u.peak_memory_bytes,
        output_bytes: u32::try_from(u.output_bytes).unwrap_or(u32::MAX),
    }
}

fn request_id_string(id: RequestId) -> String {
    // Crockford ULID via helix-audit naming (26 chars).
    helix_audit::encode_ulid_bytes(&id.as_u128().to_be_bytes())
}

fn next_request_id() -> RequestId {
    // Monotonic-ish ULID substitute: timestamp millis in high bits + counter.
    use std::sync::atomic::{AtomicU64, Ordering as Ord};
    static CTR: AtomicU64 = AtomicU64::new(1);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let n = u128::from(CTR.fetch_add(1, Ord::SeqCst));
    RequestId::from_u128((ms << 16) | (n & 0xffff))
}

fn method_mask_from_bits(bits: u8) -> MethodMask {
    let all = [
        Method::Get,
        Method::Head,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
    ];
    let mut methods = Vec::new();
    for m in all {
        // Method bit positions match WIT MethodMask comment (GET=0 .. DELETE=5).
        let bit = match m {
            Method::Get => 1 << 0,
            Method::Head => 1 << 1,
            Method::Post => 1 << 2,
            Method::Put => 1 << 3,
            Method::Patch => 1 << 4,
            Method::Delete => 1 << 5,
        };
        if bits & bit != 0 {
            methods.push(m);
        }
    }
    MethodMask::new(&methods)
}

fn wire_caps_to_set(wire: &WitCapabilitySet) -> Result<CapabilitySet, DelegateError> {
    let mut interfaces = Vec::new();
    for bit in [
        Interface::Stdio,
        Interface::Clocks,
        Interface::Random,
        Interface::Filesystem,
        Interface::HttpOutbound,
    ] {
        if wire.interfaces & bit.bit() != 0 {
            interfaces.push(bit);
        }
    }
    let mut intern = helix_caps::Interner::new();
    let mut files = Vec::new();
    for f in &wire.files {
        let id = intern.intern_path(std::path::Path::new(&f.canonical_path));
        let mode = match f.mode {
            WitFileMode::Read => FileMode::Read,
            WitFileMode::ReadWrite => FileMode::ReadWrite,
        };
        files.push(helix_caps::FileGrant::new(id, mode));
    }
    let mut hosts = Vec::new();
    for h in &wire.hosts {
        let id = intern.intern_authority(&h.authority);
        let methods = method_mask_from_bits(h.methods);
        hosts.push(HostGrant::new(id, methods));
    }
    CapabilitySet::new(&interfaces, files, vec![], hosts)
        .map(|s| s.with_interner(intern))
        .map_err(|e| DelegateError::Escalation(e.to_string()))
}

fn wit_budget(b: &WitResourceBudget) -> ResourceBudget {
    ResourceBudget::new(
        b.preempt_ticks,
        b.wall_clock_ms,
        b.memory_bytes,
        b.output_bytes,
        b.max_delegation_depth,
        b.max_children,
        b.max_concurrent_instances,
    )
}

fn validate_input(schema: &str, input: &[u8]) -> Result<(), DelegateError> {
    // Lightweight gate before provision: input must be JSON; when the schema
    // declares a top-level `"type"`, require a matching JSON value kind.
    // Full draft 2020-12 validation is a HOLE (avoid new license surface in M4).
    let schema_v: serde_json::Value = serde_json::from_str(schema)
        .map_err(|e| DelegateError::InvalidInput(format!("child input-schema is not JSON: {e}")))?;
    let instance: serde_json::Value = serde_json::from_slice(input)
        .map_err(|e| DelegateError::InvalidInput(format!("input is not JSON: {e}")))?;
    if let Some(ty) = schema_v.get("type").and_then(serde_json::Value::as_str) {
        let ok = match ty {
            "object" => instance.is_object(),
            "array" => instance.is_array(),
            "string" => instance.is_string(),
            "number" | "integer" => instance.is_number(),
            "boolean" => instance.is_boolean(),
            "null" => instance.is_null(),
            _ => true,
        };
        if !ok {
            return Err(DelegateError::InvalidInput(format!(
                "input failed child input-schema: expected type {ty}"
            )));
        }
    }
    Ok(())
}

fn refuse_to_delegate_error(r: DelegationRefuse) -> DelegateError {
    match r {
        DelegationRefuse::Escalation(s) => DelegateError::Escalation(s),
        DelegationRefuse::Depth => DelegateError::Depth,
        DelegationRefuse::Fanout => DelegateError::Fanout,
    }
}

fn hash_caps(set: &CapabilitySet) -> Option<[u8; 32]> {
    helix_audit::encode_capability_set(set)
        .ok()
        .map(|bytes| sha256_32(&bytes))
}

/// Core admission + child run (also the body of the WIT host import).
///
/// Returns `Err(trap_msg)` when the parent token fires mid-wait (RT-16): the
/// linker maps that to a guest trap so `invoke` records `Killed(WallClock)`.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub(crate) fn invoke_delegation(
    ctx: &mut DelegationCtx,
    tool: WitToolRef,
    requested_wire: WitCapabilitySet,
    budget_wire: Option<WitResourceBudget>,
    input: Vec<u8>,
) -> Result<Result<DelegationSuccess, DelegateError>, String> {
    // Stale guard.
    if ctx.guard.check_age().is_err() {
        ctx.audit.delegation_refused(
            ctx.request_id,
            ctx.identity,
            ctx.digest,
            "stale-snapshot",
            None,
            None,
        );
        return Ok(Err(DelegateError::StaleSnapshot));
    }

    // Depth / fan-out before any child Store (RT-14).
    if let Err(r) = check_depth(ctx.depth, ctx.budget.max_delegation_depth()) {
        ctx.audit.delegation_refused(
            ctx.request_id,
            ctx.identity,
            ctx.digest,
            r.reason(),
            None,
            None,
        );
        return Ok(Err(refuse_to_delegate_error(r)));
    }
    if let Err(r) = check_fanout(ctx.children.len(), ctx.budget.max_children()) {
        ctx.audit.delegation_refused(
            ctx.request_id,
            ctx.identity,
            ctx.digest,
            r.reason(),
            None,
            None,
        );
        return Ok(Err(refuse_to_delegate_error(r)));
    }

    // Resolve tool-ref against parent guard.
    let child_digest = match tool {
        WitToolRef::Alias(name) => match ctx.guard.resolve_alias(&name) {
            Some(d) => d,
            None => return Ok(Err(DelegateError::UnknownTool)),
        },
        WitToolRef::Digest(bytes) => {
            let arr: [u8; 32] = match bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => return Ok(Err(DelegateError::UnknownTool)),
            };
            ToolDigest::from_bytes(arr)
        }
    };

    let Some((child_policy, child_policy_budget)) = ctx
        .guard
        .policy(&ctx.identity, &child_digest)
        .map(|(c, b)| (c.clone(), *b))
    else {
        return Ok(Err(DelegateError::Denied));
    };

    // Intern requested against guard (unknown path/authority → escalation).
    let requested_raw = match wire_caps_to_set(&requested_wire) {
        Ok(s) => s,
        Err(e) => return Ok(Err(e)),
    };
    let requested = match intern_against_guard(&requested_raw, &ctx.guard) {
        Ok(s) => s,
        Err(r) => {
            let req_h = hash_caps(&requested_raw);
            let avail_h = hash_caps(&ctx.effective);
            if let (Some(store), Some(a), Some(b)) = (&ctx.caps_store, req_h, avail_h) {
                let _ = store
                    .lock()
                    .expect("caps")
                    .ensure_pair(&requested_raw, &ctx.effective);
                let _ = (a, b);
            }
            let reason = format!(
                "escalation requested={} available={}",
                req_h.map(hex::encode).unwrap_or_default(),
                avail_h.map(hex::encode).unwrap_or_default()
            );
            // Prefer stable reason token for audit + dual hashes on the record.
            ctx.audit.delegation_refused(
                ctx.request_id,
                ctx.identity,
                ctx.digest,
                "escalation",
                req_h,
                avail_h,
            );
            let _ = reason;
            return Ok(Err(refuse_to_delegate_error(r)));
        }
    };

    // WIT / delegate.md: `requested` must be a subset of the parent effective set.
    if !requested.is_subset_of(&ctx.effective) {
        let req_h = hash_caps(&requested);
        let avail_h = hash_caps(&ctx.effective);
        if let Some(store) = &ctx.caps_store {
            let _ = store
                .lock()
                .expect("caps")
                .ensure_pair(&requested, &ctx.effective);
        }
        ctx.audit.delegation_refused(
            ctx.request_id,
            ctx.identity,
            ctx.digest,
            "escalation",
            req_h,
            avail_h,
        );
        return Ok(Err(DelegateError::Escalation(
            "requested is not a subset of parent effective set".to_owned(),
        )));
    }

    let effective = match effective_caps(&ctx.effective, &child_policy, &requested) {
        Ok(c) => c,
        Err(r) => {
            let req_h = hash_caps(&requested);
            let avail_h = hash_caps(&ctx.effective);
            if let Some(store) = &ctx.caps_store {
                let _ = store
                    .lock()
                    .expect("caps")
                    .ensure_pair(&requested, &ctx.effective);
            }
            ctx.audit.delegation_refused(
                ctx.request_id,
                ctx.identity,
                ctx.digest,
                "escalation",
                req_h,
                avail_h,
            );
            return Ok(Err(refuse_to_delegate_error(r)));
        }
    };

    let child_budget = match effective_budget(
        &ctx.budget,
        &child_policy_budget,
        budget_wire.as_ref().map(wit_budget).as_ref(),
    ) {
        Ok(b) => b,
        Err(r) => {
            ctx.audit.delegation_refused(
                ctx.request_id,
                ctx.identity,
                ctx.digest,
                r.reason(),
                None,
                None,
            );
            return Ok(Err(refuse_to_delegate_error(r)));
        }
    };

    let Some((component, input_schema)) = ctx.tools.resolve(&child_digest) else {
        return Ok(Err(DelegateError::UnknownTool));
    };

    if let Err(e) = validate_input(&input_schema, &input) {
        return Ok(Err(e));
    }

    // Per-identity permit (child acquires one more).
    let Some(permit) = ctx.semaphore.try_acquire() else {
        return Ok(Err(DelegateError::Denied));
    };

    let child_id = next_request_id();
    let child_token = ctx.token.child_token();
    let parent_id = ctx.request_id;
    let identity = ctx.identity;
    let depth = ctx.depth + 1;
    let guard = ctx.guard.clone();
    let semaphore = Arc::clone(&ctx.semaphore);
    let audit = Arc::clone(&ctx.audit);
    let store_creations = Arc::clone(&ctx.store_creations);
    let engine = ctx.engine.clone();
    let tools = Arc::clone(&ctx.tools);

    let (tx, rx) = oneshot::channel::<Result<DelegationSuccess, DelegateError>>();

    // Fan-out accounting: occupy a JoinSet slot for the life of the child.
    ctx.children.spawn(async {
        ChildTaskResult {
            request_id: RequestId::from_u128(0),
            outcome: Err(DelegateError::ChildFailed("slot".into())),
        }
    });
    // Run the child on the process runtime via the sole tokio::spawn site.
    let child_token2 = child_token.clone();
    cancel::spawn_cancellable(child_token2.clone(), move |_t| async move {
        let outcome = run_child_invocation(
            engine,
            component,
            effective,
            child_budget,
            input,
            child_id,
            parent_id,
            identity,
            child_digest,
            depth,
            guard,
            semaphore,
            child_token2,
            tools,
            audit,
            store_creations,
            permit,
        )
        .await;
        let _ = tx.send(outcome);
    });

    // Parent blocks; race child completion against parent cancel (RT-16).
    let parent_token = ctx.token.clone();
    drive_parent_wait(parent_token, rx)
}

fn drive_parent_wait(
    parent_token: CancellationToken,
    rx: oneshot::Receiver<Result<DelegationSuccess, DelegateError>>,
) -> Result<Result<DelegationSuccess, DelegateError>, String> {
    let wait = async move {
        tokio::select! {
            biased;
            () = parent_token.cancelled() => Err(WALL_CLOCK_TRAP_MSG.to_string()),
            msg = rx => {
                match msg {
                    Ok(r) => Ok(r),
                    Err(_) => Ok(Err(DelegateError::ChildFailed(
                        "child task dropped".into(),
                    ))),
                }
            }
        }
    };

    // Prefer polling on a dedicated thread so we never nest `block_on` on the
    // caller's runtime (avoids JoinSet / timer deadlocks under `#[tokio::test]`).
    let (tx, rx_done) = std::sync::mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("helix-delegate-wait".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("delegate wait runtime");
            let _ = tx.send(rt.block_on(wait));
        })
        .map_err(|e| e.to_string())?;
    let out = tokio::task::block_in_place(|| rx_done.recv()).map_err(|e| e.to_string())?;
    let _ = handle.join();
    out
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_child_invocation(
    engine: Engine,
    component: Component,
    caps: CapabilitySet,
    budget: ResourceBudget,
    input: Vec<u8>,
    child_id: RequestId,
    parent_id: RequestId,
    identity: Identity,
    digest: ToolDigest,
    depth: u32,
    guard: PolicyGuard,
    semaphore: Arc<IdentitySemaphore>,
    token: CancellationToken,
    tools: Arc<dyn ToolResolver>,
    audit: Arc<dyn DelegationAudit>,
    store_creations: Arc<AtomicUsize>,
    _permit: IdentityPermit,
) -> Result<DelegationSuccess, DelegateError> {
    let mut hook = RecordingHook::default();
    // Cooperative ParentDropped: if already cancelled, record and exit.
    if token.is_cancelled() {
        let usage = Usage::default();
        cancel::record_parent_dropped_kill();
        audit.child_terminal(ChildAuditRecord {
            request_id: child_id,
            parent: parent_id,
            kind: TerminalKind::Killed {
                cause: KillCause::ParentDropped,
            },
            usage,
        });
        return Err(DelegateError::ChildKilled(KillCause::ParentDropped));
    }

    store_creations.fetch_add(1, Ordering::SeqCst);
    metrics::counter!(METRIC_CHILD_STORE_CREATED).increment(1);

    let token_race = token.clone();
    let audit_race = Arc::clone(&audit);
    let engine_for_kill = engine.clone();
    let mut blocking = tokio::task::spawn_blocking({
        let token = token.clone();
        let caps = caps.clone();
        move || {
            run_child_sync(
                &engine, &component, &caps, &budget, &input, token, child_id, parent_id, identity,
                digest, depth, guard, semaphore, tools, &mut hook,
            )
        }
    });

    // Prefer ParentDropped when the parent token fires mid-child (RT-16).
    // Advance the engine epoch so the busy-loop guest traps and the blocking
    // worker exits (JoinHandle::abort alone leaves a zombie thread).
    let result = tokio::select! {
        biased;
        () = token_race.cancelled() => {
            for _ in 0..50_000 {
                engine_for_kill.increment_epoch();
            }
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), &mut blocking).await;
            cancel::record_parent_dropped_kill();
            let usage = Usage::default();
            audit_race.child_terminal(ChildAuditRecord {
                request_id: child_id,
                parent: parent_id,
                kind: TerminalKind::Killed {
                    cause: KillCause::ParentDropped,
                },
                usage,
            });
            return Err(DelegateError::ChildKilled(KillCause::ParentDropped));
        }
        joined = &mut blocking => {
            joined.map_err(|e| DelegateError::ChildFailed(format!("child join: {e}")))?
        }
    };

    match result {
        Ok(success) => {
            audit.child_terminal(ChildAuditRecord {
                request_id: child_id,
                parent: parent_id,
                kind: TerminalKind::Completed {
                    output: success.output.clone(),
                },
                usage: success.usage,
            });
            Ok(DelegationSuccess {
                request_id: child_id,
                digest,
                output: success.output,
                usage: success.usage,
            })
        }
        Err(InvokeError::Killed { cause, usage }) => {
            if cause == KillCause::WallClock {
                cancel::record_wall_clock_kill();
            }
            audit.child_terminal(ChildAuditRecord {
                request_id: child_id,
                parent: parent_id,
                kind: TerminalKind::Killed { cause },
                usage,
            });
            Err(DelegateError::ChildKilled(cause))
        }
        Err(InvokeError::ToolError {
            kind,
            message,
            usage,
        }) => {
            audit.child_terminal(ChildAuditRecord {
                request_id: child_id,
                parent: parent_id,
                kind: TerminalKind::ToolError {
                    kind: kind.clone(),
                    message: message.clone(),
                },
                usage,
            });
            Err(DelegateError::ChildToolError { kind, message })
        }
        Err(InvokeError::Failed { reason, usage }) => {
            audit.child_terminal(ChildAuditRecord {
                request_id: child_id,
                parent: parent_id,
                kind: TerminalKind::Failed {
                    reason: reason.clone(),
                },
                usage,
            });
            Err(DelegateError::ChildFailed(reason))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::items_after_statements
)]
fn run_child_sync<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    token: CancellationToken,
    child_id: RequestId,
    parent_id: RequestId,
    identity: Identity,
    digest: ToolDigest,
    depth: u32,
    guard: PolicyGuard,
    semaphore: Arc<IdentitySemaphore>,
    tools: Arc<dyn ToolResolver>,
    hook: &mut H,
) -> Result<crate::invoke::InvokeSuccess, InvokeError> {
    let started = Instant::now();
    let mut guard_term = TerminalGuard::new(hook);

    let pre = match link::provision_pre_with_delegate::<InvokeHost>(engine, component, caps) {
        Ok(p) => p,
        Err(err) => {
            let usage = Usage::default();
            guard_term.set_usage(usage);
            guard_term.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    let mut host = match InvokeHost::new_with_token(caps, budget.memory_bytes(), token.clone()) {
        Ok(h) => h,
        Err(err) => {
            let usage = Usage::default();
            guard_term.set_usage(usage);
            guard_term.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    host.set_delegation(DelegationCtx {
        request_id: child_id,
        parent: Some(parent_id),
        identity,
        digest,
        depth,
        guard,
        effective: caps.clone(),
        budget: *budget,
        semaphore,
        token: token.clone(),
        children: JoinSet::new(),
        tools,
        audit: Arc::new(NopDelegationAudit),
        caps_store: None,
        store_creations: Arc::new(AtomicUsize::new(0)),
        engine: engine.clone(),
    });

    let mut store = Store::new(engine, host);
    store.limiter(|h| &mut h.limiter);
    store.epoch_deadline_trap();
    store.set_epoch_deadline(preempt_deadline_ticks(budget));

    // Arm a local wall-clock for the child budget.
    let life = cancel::RequestLifecycle::new();
    // Replace root with our child token? Simpler: select on token + sync call via
    // spawn_blocking already; wall clock on parent of child token must be armed
    // by the caller. For child-owned wall clock, cancel after budget.
    let wall = budget.wall_clock_ms();
    let cancel_tok = token.clone();
    let timer = cancel::spawn_cancellable(cancel_tok.clone(), move |t| async move {
        tokio::select! {
            biased;
            () = t.cancelled() => {}
            () = tokio::time::sleep(std::time::Duration::from_millis(u64::from(wall))) => {
                t.cancel();
            }
        }
    });
    let _ = life; // child uses token tree from parent; timer cancels child token.

    let instance = match pre.instantiate(&mut store) {
        Ok(i) => i,
        Err(err) => {
            timer.abort();
            let usage = Usage {
                wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(0),
                ..Usage::default()
            };
            guard_term.set_usage(usage);
            guard_term.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    // Reuse invoke typed call path by importing payload type from invoke module...
    // Inline minimal typed call:
    #[derive(Debug, Clone, ComponentType, Lift)]
    #[component(variant)]
    enum InvokeErrorPayload {
        #[component(name = "invalid-input")]
        InvalidInput(String),
        #[component(name = "capability-denied")]
        CapabilityDenied(String),
        #[component(name = "internal")]
        Internal(String),
    }
    impl InvokeErrorPayload {
        fn kind(&self) -> String {
            match self {
                Self::InvalidInput(_) => "invalid-input",
                Self::CapabilityDenied(_) => "capability-denied",
                Self::Internal(_) => "internal",
            }
            .to_string()
        }
        fn message(&self) -> String {
            match self {
                Self::InvalidInput(s) | Self::CapabilityDenied(s) | Self::Internal(s) => s.clone(),
            }
        }
    }

    let typed = match instance
        .get_typed_func::<(Vec<u8>,), (Result<Vec<u8>, InvokeErrorPayload>,)>(&mut store, "invoke")
    {
        Ok(f) => f,
        Err(err) => {
            timer.abort();
            let usage = Usage::default();
            guard_term.set_usage(usage);
            guard_term.record(TerminalKind::Failed {
                reason: format!("missing invoke export: {err}"),
            });
            return Err(InvokeError::Failed {
                reason: format!("missing invoke export: {err}"),
                usage,
            });
        }
    };

    let call = typed.call(&mut store, (input.to_vec(),));
    timer.abort();
    let peak = store.data().limiter().peak_memory_bytes();
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(0);

    match call {
        Ok((Ok(bytes),)) => {
            let _ = typed.post_return(&mut store);
            let usage_base = Usage {
                wall_ms,
                preempt_ticks: wall_ms,
                peak_memory_bytes: u64::try_from(peak).unwrap_or(0),
                output_bytes: 0,
            };
            deliver_output(bytes, budget.output_bytes(), usage_base, &mut guard_term)
        }
        Ok((Err(payload),)) => {
            let _ = typed.post_return(&mut store);
            let usage = Usage {
                wall_ms,
                preempt_ticks: wall_ms,
                peak_memory_bytes: u64::try_from(peak).unwrap_or(0),
                output_bytes: 0,
            };
            guard_term.set_usage(usage);
            guard_term.record(TerminalKind::ToolError {
                kind: payload.kind(),
                message: payload.message(),
            });
            Err(InvokeError::ToolError {
                kind: payload.kind(),
                message: payload.message(),
                usage,
            })
        }
        Err(err) => {
            let cause = if token.is_cancelled() {
                // Distinguish parent-drop vs own wall clock: parent-drop is set
                // when parent token cancelled the child token without the child
                // timer being the source. Heuristic: if wall elapsed >= budget,
                // WallClock; else ParentDropped.
                if wall_ms >= u64::from(budget.wall_clock_ms().saturating_sub(1)) {
                    KillCause::WallClock
                } else {
                    KillCause::ParentDropped
                }
            } else {
                let msg = format!("{err}").to_ascii_lowercase();
                if msg.contains("epoch") || msg.contains("interrupt") {
                    KillCause::Preempted
                } else if store.data().limiter().memory_kill() {
                    KillCause::Memory
                } else {
                    KillCause::Preempted
                }
            };
            let usage = Usage {
                wall_ms,
                preempt_ticks: wall_ms,
                peak_memory_bytes: u64::try_from(peak).unwrap_or(0),
                output_bytes: 0,
            };
            guard_term.set_usage(usage);
            guard_term.record(TerminalKind::Killed { cause });
            Err(InvokeError::Killed { cause, usage })
        }
    }
}

/// Add `helix:tool/delegate@1.0.0` (and type/caps stubs) to a linker.
pub fn add_delegate_to_linker<T>(
    linker: &mut wasmtime::component::Linker<T>,
) -> Result<(), RuntimeError>
where
    T: DelegateHostView + Send + 'static,
{
    // Type-only interfaces: export the type names guests import.
    {
        let mut inst = linker
            .instance("helix:tool/types@1.0.0")
            .map_err(|e| RuntimeError::provision(e.to_string()))?;
        // Types are structural via ComponentType on the function; empty instance ok
        // when guests only import type aliases. Some components need no funcs.
        let _ = &mut inst;
    }
    {
        let mut inst = linker
            .instance("helix:tool/caps@1.0.0")
            .map_err(|e| RuntimeError::provision(e.to_string()))?;
        let _ = &mut inst;
    }

    let mut inst = linker
        .instance("helix:tool/delegate@1.0.0")
        .map_err(|e| RuntimeError::provision(e.to_string()))?;

    inst.func_wrap(
        "invoke",
        |mut caller: wasmtime::StoreContextMut<'_, T>,
         (req,): (WitDelegationRequest,)|
         -> anyhow::Result<(Result<WitDelegationResult, WitDelegateError>,)> {
            let Some(ctx) = caller.data_mut().delegation_ctx_mut() else {
                return Ok((Err(WitDelegateError::Denied),));
            };
            match invoke_delegation(ctx, req.tool, req.requested, req.budget, req.input) {
                Ok(Ok(success)) => Ok((Ok(WitDelegationResult {
                    request_id: request_id_string(success.request_id),
                    digest: success.digest.as_bytes().to_vec(),
                    output: success.output,
                    usage: usage_to_wit(success.usage),
                }),)),
                Ok(Err(e)) => Ok((Err(to_wit_error(e)),)),
                Err(trap) => Err(anyhow::anyhow!(trap)),
            }
        },
    )
    .map_err(|e| RuntimeError::provision(e.to_string()))?;

    Ok(())
}

/// Store data that can host `helix:delegate`.
pub trait DelegateHostView {
    /// Mutable access to delegation context (None → denied).
    fn delegation_ctx_mut(&mut self) -> Option<&mut DelegationCtx>;
}

impl DelegateHostView for InvokeHost {
    fn delegation_ctx_mut(&mut self) -> Option<&mut DelegationCtx> {
        self.delegation_mut()
    }
}

/// Hex encode 32 bytes (local; avoid extra dep if hex crate missing).
mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }
}

/// Public request shape for host-side tests (RT-13…RT-16) without WIT lifts.
#[derive(Debug, Clone)]
pub struct HostDelegationRequest {
    /// Alias or digest.
    pub tool: HostToolRef,
    /// Requested capability interfaces bitset (WIT `interfaces` field).
    pub requested_interfaces: u64,
    /// Optional budget override.
    pub budget: Option<ResourceBudget>,
    /// Input bytes (JSON matching child schema).
    pub input: Vec<u8>,
}

/// Tool reference for [`HostDelegationRequest`].
#[derive(Debug, Clone)]
pub enum HostToolRef {
    /// Policy alias.
    Alias(String),
    /// Raw digest.
    Digest(ToolDigest),
}

/// Invoke delegation from host/tests (same path as the WIT import).
///
/// # Errors
///
/// `Err(String)` is a trap message (parent cancelled mid-wait / RT-16).
pub fn host_delegate(
    ctx: &mut DelegationCtx,
    req: HostDelegationRequest,
) -> Result<Result<DelegationSuccess, DelegateError>, String> {
    let tool = match req.tool {
        HostToolRef::Alias(a) => WitToolRef::Alias(a),
        HostToolRef::Digest(d) => WitToolRef::Digest(d.as_bytes().to_vec()),
    };
    let requested = WitCapabilitySet {
        interfaces: req.requested_interfaces,
        files: vec![],
        hosts: vec![],
    };
    let budget = req.budget.map(|b| WitResourceBudget {
        preempt_ticks: b.preempt_ticks(),
        wall_clock_ms: b.wall_clock_ms(),
        memory_bytes: b.memory_bytes(),
        output_bytes: b.output_bytes(),
        max_delegation_depth: b.max_delegation_depth(),
        max_children: b.max_children(),
        max_concurrent_instances: b.max_concurrent_instances(),
    });
    invoke_delegation(ctx, tool, requested, budget, req.input)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn zero_max_children_is_fanout() {
        assert!(check_fanout(0, 0).is_err());
    }
}
