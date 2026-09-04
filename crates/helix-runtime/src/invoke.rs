//! Per-invocation Store + limits + terminal-record drop guard (M4-04 / HLX-27).
//!
//! Fresh [`Store`] per call with [`HelixLimiter`], epoch deadline from
//! `preempt_ticks`, [`BoundedWriter`] on the result channel, and a drop guard
//! that emits exactly one terminal record (including host panic →
//! `Killed{panic}`, `-32007`).

use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;

use helix_caps::{CapabilitySet, ResourceBudget};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use tokio_util::sync::CancellationToken;

use crate::bounded::{BoundedWriter, BoundedWriterError};
use crate::cancel::{self, RequestLifecycle};
use crate::error::{InvokeError, KillCause, RuntimeError, Usage};
use crate::host::WasiHost;
use crate::limits::HelixLimiter;
use crate::link;
use crate::pool::InstancePool;
use crate::preempt::{self, default_preempt_ticks};

/// Metric: memory-ceiling kills.
pub const METRIC_KILL_MEMORY: &str = "helix_kill_memory_total";

/// Metric: output-ceiling kills.
pub const METRIC_KILL_OUTPUT: &str = "helix_kill_output_total";

/// Terminal transition kinds the drop guard may emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalKind {
    /// Tool returned `ok` with bounded output.
    Completed {
        /// Result bytes (already bounded).
        output: Vec<u8>,
    },
    /// Tool returned `invoke-error` (gateway maps kind → `-32005`/`-32006`/`-32007`).
    ToolError {
        /// Discriminant name (`invalid-input`, `capability-denied`, `internal`).
        kind: String,
        /// Message (logged only for `internal`).
        message: String,
    },
    /// Sandbox killed (`Preempted` / `Memory` / `Output` / …).
    Killed {
        /// Kill cause.
        cause: KillCause,
    },
    /// Provision / link failure before Running (synced `Failed{provision}`).
    Failed {
        /// Reason string.
        reason: String,
    },
}

/// One terminal audit/hook record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRecord {
    /// Transition kind.
    pub kind: TerminalKind,
    /// Resource usage snapshot.
    pub usage: Usage,
}

impl TerminalRecord {
    /// Stable gateway JSON-RPC code for this terminal, when applicable.
    #[must_use]
    pub fn gateway_code(&self) -> Option<i32> {
        match &self.kind {
            TerminalKind::Completed { .. } => None,
            TerminalKind::ToolError { kind, .. } => Some(match kind.as_str() {
                "invalid-input" => -32005,
                "capability-denied" => -32006,
                _ => -32007,
            }),
            TerminalKind::Killed { cause } => Some(cause.gateway_code()),
            TerminalKind::Failed { .. } => Some(RuntimeError::GATEWAY_CODE),
        }
    }
}

/// Hook for terminal records (audit writer or test double).
pub trait TerminalHook {
    /// Called exactly once per invocation (drop guard guarantees this).
    fn on_terminal(&mut self, record: TerminalRecord);
}

/// Collecting hook for tests.
#[derive(Debug, Default)]
pub struct RecordingHook {
    /// Records received (length ≤ 1 under correct guard use).
    pub records: Vec<TerminalRecord>,
}

impl TerminalHook for RecordingHook {
    fn on_terminal(&mut self, record: TerminalRecord) {
        self.records.push(record);
    }
}

/// No-op hook when the caller ignores terminals.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopHook;

impl TerminalHook for NopHook {
    fn on_terminal(&mut self, _record: TerminalRecord) {}
}

/// Drop guard: if no terminal was recorded before drop (panic / early exit),
/// emits `Killed{panic}` (`-32007`).
pub struct TerminalGuard<'a, H: TerminalHook + ?Sized> {
    hook: &'a mut H,
    usage: Usage,
    recorded: bool,
}

impl<'a, H: TerminalHook + ?Sized> TerminalGuard<'a, H> {
    /// Begin guarding; `usage` is updated before [`Self::record`].
    #[must_use]
    pub fn new(hook: &'a mut H) -> Self {
        Self {
            hook,
            usage: Usage::default(),
            recorded: false,
        }
    }

    /// Update usage snapshot carried into the terminal record.
    pub fn set_usage(&mut self, usage: Usage) {
        self.usage = usage;
    }

    /// Emit the terminal record (idempotent: second call is a no-op).
    pub fn record(&mut self, kind: TerminalKind) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        self.hook.on_terminal(TerminalRecord {
            kind,
            usage: self.usage,
        });
    }

    /// Whether a terminal was already recorded.
    #[must_use]
    pub fn recorded(&self) -> bool {
        self.recorded
    }
}

impl<H: TerminalHook + ?Sized> Drop for TerminalGuard<'_, H> {
    fn drop(&mut self) {
        if !self.recorded {
            self.recorded = true;
            self.hook.on_terminal(TerminalRecord {
                kind: TerminalKind::Killed {
                    cause: KillCause::Panic,
                },
                usage: self.usage,
            });
        }
    }
}

/// Store data for a capability-linked invoke: WASI host + limiter + cancel token.
pub struct InvokeHost {
    wasi: WasiHost,
    limiter: HelixLimiter,
}

impl std::fmt::Debug for InvokeHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvokeHost")
            .field("peak_memory_bytes", &self.limiter.peak_memory_bytes())
            .field("memory_kill", &self.limiter.memory_kill())
            .finish_non_exhaustive()
    }
}

impl InvokeHost {
    fn new(caps: &CapabilitySet, memory_bytes: u64) -> Result<Self, RuntimeError> {
        Self::new_with_token(caps, memory_bytes, CancellationToken::new())
    }

    fn new_with_token(
        caps: &CapabilitySet,
        memory_bytes: u64,
        token: CancellationToken,
    ) -> Result<Self, RuntimeError> {
        let wasi = WasiHost::from_capability_set_with_token(caps, token)
            .map_err(|e| RuntimeError::provision(format!("filesystem grant open failed: {e}")))?;
        Ok(Self {
            wasi,
            limiter: HelixLimiter::new(memory_bytes),
        })
    }

    /// Borrow the limiter.
    #[must_use]
    pub fn limiter(&self) -> &HelixLimiter {
        &self.limiter
    }

    /// Request [`CancellationToken`] cloned into every host function (HLX-28).
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.wasi.cancellation_token()
    }
}

impl wasmtime_wasi::WasiView for InvokeHost {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        self.wasi.ctx()
    }
}

/// Successful invoke with bounded output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeSuccess {
    /// Guest result bytes.
    pub output: Vec<u8>,
    /// Usage snapshot.
    pub usage: Usage,
}

/// Resolve preempt deadline ticks from budget (default = `wall_clock_ms`).
#[must_use]
pub fn preempt_deadline_ticks(budget: &ResourceBudget) -> u64 {
    let ticks = if budget.preempt_ticks() == 0 {
        default_preempt_ticks(budget.wall_clock_ms())
    } else {
        budget.preempt_ticks()
    };
    u64::from(ticks.max(1))
}

fn build_usage(started: Instant, peak_memory_bytes: usize, output_bytes: usize) -> Usage {
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Usage {
        wall_ms,
        // Tick pinned at 1 ms ⇒ elapsed ms ≈ ticks consumed.
        preempt_ticks: wall_ms,
        peak_memory_bytes: u64::try_from(peak_memory_bytes).unwrap_or(u64::MAX),
        output_bytes: u64::try_from(output_bytes).unwrap_or(u64::MAX),
    }
}

fn map_trap_to_kill(err: &wasmtime::Error, host: &InvokeHost) -> KillCause {
    if host.limiter.memory_kill() {
        return KillCause::Memory;
    }
    let msg = format!("{err}").to_ascii_lowercase();
    if msg.contains("epoch") || msg.contains("interrupt") {
        KillCause::Preempted
    } else if msg.contains("memory ceiling") || msg.contains("out of memory") {
        KillCause::Memory
    } else {
        // Default guest trap during Running → treat as internal kill surface;
        // epoch is the common case for spin.wasm.
        KillCause::Preempted
    }
}

/// Run a no-arg exported `run` under limits (adversarial spin / membomb fixtures).
///
/// Used by RT-5 / RT-6. Full helix `invoke` export lands alongside tool WIT wiring;
/// this path exercises Store + limiter + epoch + terminal guard.
///
/// # Errors
///
/// [`InvokeError`] for kill / provision failures (also recorded on `hook`).
pub fn run_limited<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    budget: &ResourceBudget,
    hook: &mut H,
) -> Result<Usage, InvokeError> {
    let started = Instant::now();
    let mut guard = TerminalGuard::new(hook);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        run_limited_inner(engine, component, budget, started, &mut guard)
    }));

    match result {
        Ok(inner) => inner,
        Err(_panic) => {
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            // Drop will record Killed{panic} if we do not; record explicitly for clarity.
            guard.record(TerminalKind::Killed {
                cause: KillCause::Panic,
            });
            Err(InvokeError::Killed {
                cause: KillCause::Panic,
                usage,
            })
        }
    }
}

fn run_limited_inner<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    budget: &ResourceBudget,
    started: Instant,
    guard: &mut TerminalGuard<'_, H>,
) -> Result<Usage, InvokeError> {
    let caps = CapabilitySet::EMPTY;
    let host = InvokeHost::new(&caps, budget.memory_bytes()).map_err(|e| {
        let usage = build_usage(started, 0, 0);
        guard.set_usage(usage);
        guard.record(TerminalKind::Failed {
            reason: e.to_string(),
        });
        InvokeError::Failed {
            reason: e.to_string(),
            usage,
        }
    })?;

    let mut store = Store::new(engine, host);
    store.limiter(|h| &mut h.limiter);
    store.epoch_deadline_trap();
    store.set_epoch_deadline(preempt_deadline_ticks(budget));

    // Adversarial fixtures export `run` with no imports.
    let linker = Linker::<InvokeHost>::new(engine);
    let instance = match linker.instantiate(&mut store, component) {
        Ok(i) => i,
        Err(err) => {
            let usage = build_usage(started, store.data().limiter.peak_memory_bytes(), 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    let run = match instance.get_typed_func::<(), ()>(&mut store, "run") {
        Ok(f) => f,
        Err(err) => {
            let usage = build_usage(started, store.data().limiter.peak_memory_bytes(), 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: format!("missing run export: {err}"),
            });
            return Err(InvokeError::Failed {
                reason: format!("missing run export: {err}"),
                usage,
            });
        }
    };

    match run.call(&mut store, ()) {
        Ok(()) => {
            let peak = store.data().limiter.peak_memory_bytes();
            let usage = build_usage(started, peak, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Completed { output: Vec::new() });
            Ok(usage)
        }
        Err(err) => {
            let cause = map_trap_to_kill(&err, store.data());
            match cause {
                KillCause::Preempted => preempt::record_preempt_kill(),
                KillCause::Memory => {
                    metrics::counter!(METRIC_KILL_MEMORY).increment(1);
                }
                _ => {}
            }
            let peak = store.data().limiter.peak_memory_bytes();
            let usage = build_usage(started, peak, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Killed { cause });
            Err(InvokeError::Killed { cause, usage })
        }
    }
}

/// Bound guest output for the result channel (S4). Records kill on exceed.
///
/// # Errors
///
/// [`InvokeError::Killed`] with [`KillCause::Output`] when over limit.
pub fn deliver_output<H: TerminalHook>(
    bytes: Vec<u8>,
    output_limit: u32,
    usage_base: Usage,
    guard: &mut TerminalGuard<'_, H>,
) -> Result<InvokeSuccess, InvokeError> {
    match BoundedWriter::bound(bytes, output_limit) {
        Ok(output) => {
            let usage = Usage {
                output_bytes: u64::try_from(output.len()).unwrap_or(u64::MAX),
                ..usage_base
            };
            guard.set_usage(usage);
            guard.record(TerminalKind::Completed {
                output: output.clone(),
            });
            Ok(InvokeSuccess { output, usage })
        }
        Err(BoundedWriterError::Exceeded) => {
            metrics::counter!(METRIC_KILL_OUTPUT).increment(1);
            let usage = Usage {
                output_bytes: 0,
                ..usage_base
            };
            guard.set_usage(usage);
            guard.record(TerminalKind::Killed {
                cause: KillCause::Output,
            });
            Err(InvokeError::Killed {
                cause: KillCause::Output,
                usage,
            })
        }
    }
}

/// Full capability-linked invoke of the helix `invoke` export.
///
/// Instantiates via [`link::provision_pre`], sets limiter + epoch deadline,
/// calls `invoke`, bounds output, and records a terminal via `hook`.
///
/// # Errors
///
/// Provision, kill, or tool-error outcomes as [`InvokeError`].
pub fn invoke<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    hook: &mut H,
) -> Result<InvokeSuccess, InvokeError> {
    let started = Instant::now();
    let mut guard = TerminalGuard::new(hook);

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        invoke_inner(engine, component, caps, budget, input, started, &mut guard)
    }));

    match result {
        Ok(inner) => inner,
        Err(_panic) => {
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Killed {
                cause: KillCause::Panic,
            });
            Err(InvokeError::Killed {
                cause: KillCause::Panic,
                usage,
            })
        }
    }
}

fn invoke_inner<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    started: Instant,
    guard: &mut TerminalGuard<'_, H>,
) -> Result<InvokeSuccess, InvokeError> {
    let pre = match link::provision_pre::<InvokeHost>(engine, component, caps) {
        Ok(p) => p,
        Err(err) => {
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    let host = match InvokeHost::new(caps, budget.memory_bytes()) {
        Ok(h) => h,
        Err(err) => {
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    let mut store = Store::new(engine, host);
    store.limiter(|h| &mut h.limiter);
    store.epoch_deadline_trap();
    store.set_epoch_deadline(preempt_deadline_ticks(budget));

    let instance = match pre.instantiate(&mut store) {
        Ok(i) => i,
        Err(err) => {
            let usage = build_usage(started, store.data().limiter.peak_memory_bytes(), 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    // Helix tool `invoke: func(list<u8>) -> result<list<u8>, invoke-error>`.
    // Represented as a typed func returning a Result-like enum via ComponentType.
    let typed = match instance
        .get_typed_func::<(Vec<u8>,), (Result<Vec<u8>, InvokeErrorPayload>,)>(&mut store, "invoke")
    {
        Ok(f) => f,
        Err(err) => {
            let usage = build_usage(started, store.data().limiter.peak_memory_bytes(), 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: format!("missing invoke export: {err}"),
            });
            return Err(InvokeError::Failed {
                reason: format!("missing invoke export: {err}"),
                usage,
            });
        }
    };

    let call = typed.call(&mut store, (input.to_vec(),));
    let peak = store.data().limiter.peak_memory_bytes();

    match call {
        Ok((Ok(bytes),)) => {
            let _ = typed.post_return(&mut store);
            let usage_base = build_usage(started, peak, 0);
            deliver_output(bytes, budget.output_bytes(), usage_base, guard)
        }
        Ok((Err(payload),)) => {
            let _ = typed.post_return(&mut store);
            let usage = build_usage(started, peak, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::ToolError {
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
            let cause = map_trap_to_kill(&err, store.data());
            match cause {
                KillCause::Preempted => preempt::record_preempt_kill(),
                KillCause::Memory => {
                    metrics::counter!(METRIC_KILL_MEMORY).increment(1);
                }
                _ => {}
            }
            let usage = build_usage(started, peak, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Killed { cause });
            Err(InvokeError::Killed { cause, usage })
        }
    }
}

/// Lifted `invoke-error` variant for typed calls.
#[derive(Debug, Clone, wasmtime::component::ComponentType, wasmtime::component::Lift)]
#[component(variant)]
enum InvokeErrorPayload {
    /// `invalid-input(string)`
    #[component(name = "invalid-input")]
    InvalidInput(String),
    /// `capability-denied(string)`
    #[component(name = "capability-denied")]
    CapabilityDenied(String),
    /// `internal(string)`
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

/// Async invoke under wall-clock cancellation (HLX-28 / L1).
///
/// Owns the Store inside the request future (S3). Arms `budget.wall_clock_ms`
/// via [`RequestLifecycle`]; host functions must `select!` on the cloned token.
/// A cancelled token while blocked in a host stub yields [`KillCause::WallClock`].
///
/// Child `JoinSet` scaffolding lives on [`crate::cancel::RequestLifecycle`]
/// (filled by `helix:delegate` in HLX-31). This helper covers wall-clock on the
/// request path; RT-8 exercises the stub host via [`crate::cancel::run_with_wall_clock`].
pub async fn invoke_with_cancel<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    hook: &mut H,
) -> Result<InvokeSuccess, InvokeError> {
    let started = Instant::now();
    let mut guard = TerminalGuard::new(hook);

    let mut life = RequestLifecycle::new();
    life.arm_wall_clock(budget.wall_clock_ms());
    let token = life.token();
    let cancel_wait = token.clone();

    // Store is a local of this future (S3).
    let result = tokio::select! {
        biased;
        () = cancel_wait.cancelled() => {
            let cause = life.kill_cause().unwrap_or(KillCause::WallClock);
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Killed { cause });
            if cause == KillCause::WallClock {
                cancel::record_wall_clock_kill();
            }
            Err(InvokeError::Killed { cause, usage })
        }
        out = async {
            // Sync wasmtime path still runs; wall-clock races it. Host stubs
            // that park on the token (RT-8) must use run_with_wall_clock / host_select.
            invoke_inner_with_token(
                engine,
                component,
                caps,
                budget,
                input,
                started,
                token.clone(),
                &mut guard,
            )
        } => out,
    };

    life.stop_wall_timer();
    life.disarm_parent_drop();
    result
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn invoke_inner_with_token<H: TerminalHook>(
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    started: Instant,
    token: CancellationToken,
    guard: &mut TerminalGuard<'_, H>,
) -> Result<InvokeSuccess, InvokeError> {
    let pre = match link::provision_pre::<InvokeHost>(engine, component, caps) {
        Ok(p) => p,
        Err(err) => {
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    let host = match InvokeHost::new_with_token(caps, budget.memory_bytes(), token) {
        Ok(h) => h,
        Err(err) => {
            let usage = build_usage(started, 0, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    // Store owned by this stack frame / future (S3).
    let mut store = Store::new(engine, host);
    store.limiter(|h| &mut h.limiter);
    store.epoch_deadline_trap();
    store.set_epoch_deadline(preempt_deadline_ticks(budget));

    let instance = match pre.instantiate(&mut store) {
        Ok(i) => i,
        Err(err) => {
            let usage = build_usage(started, store.data().limiter.peak_memory_bytes(), 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: err.to_string(),
            });
            return Err(InvokeError::Failed {
                reason: err.to_string(),
                usage,
            });
        }
    };

    let typed = match instance
        .get_typed_func::<(Vec<u8>,), (Result<Vec<u8>, InvokeErrorPayload>,)>(&mut store, "invoke")
    {
        Ok(f) => f,
        Err(err) => {
            let usage = build_usage(started, store.data().limiter.peak_memory_bytes(), 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Failed {
                reason: format!("missing invoke export: {err}"),
            });
            return Err(InvokeError::Failed {
                reason: format!("missing invoke export: {err}"),
                usage,
            });
        }
    };

    let call = typed.call(&mut store, (input.to_vec(),));
    let peak = store.data().limiter.peak_memory_bytes();

    match call {
        Ok((Ok(bytes),)) => {
            let _ = typed.post_return(&mut store);
            let usage_base = build_usage(started, peak, 0);
            deliver_output(bytes, budget.output_bytes(), usage_base, guard)
        }
        Ok((Err(payload),)) => {
            let _ = typed.post_return(&mut store);
            let usage = build_usage(started, peak, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::ToolError {
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
            let cause = map_trap_to_kill(&err, store.data());
            match cause {
                KillCause::Preempted => preempt::record_preempt_kill(),
                KillCause::Memory => {
                    metrics::counter!(METRIC_KILL_MEMORY).increment(1);
                }
                KillCause::WallClock => cancel::record_wall_clock_kill(),
                KillCause::ParentDropped => cancel::record_parent_dropped_kill(),
                _ => {}
            }
            let usage = build_usage(started, peak, 0);
            guard.set_usage(usage);
            guard.record(TerminalKind::Killed { cause });
            Err(InvokeError::Killed { cause, usage })
        }
    }
}

/// [`run_limited`] under [`InstancePool`] accounting (HLX-29 / B8).
///
/// Acquires one pool slot for the duration of the call; the [`crate::pool::PoolGuard`]
/// drops on every exit path (ok, kill, provision failure, unwind), so
/// `helix_pool_in_use` returns to the prior value.
///
/// # Errors
///
/// Same as [`run_limited`].
pub fn run_limited_pooled<H: TerminalHook>(
    pool: &InstancePool,
    engine: &Engine,
    component: &Component,
    budget: &ResourceBudget,
    hook: &mut H,
) -> Result<Usage, InvokeError> {
    let _slot = pool.acquire();
    run_limited(engine, component, budget, hook)
}

/// [`invoke`] under [`InstancePool`] accounting (HLX-29 / B8).
///
/// # Errors
///
/// Same as [`invoke`].
pub fn invoke_pooled<H: TerminalHook>(
    pool: &InstancePool,
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    hook: &mut H,
) -> Result<InvokeSuccess, InvokeError> {
    let _slot = pool.acquire();
    invoke(engine, component, caps, budget, input, hook)
}

/// [`invoke_with_cancel`] under [`InstancePool`] accounting (HLX-29 / B8).
///
/// Slot is held for the whole async call; cancelled / killed paths still release.
pub async fn invoke_with_cancel_pooled<H: TerminalHook>(
    pool: &InstancePool,
    engine: &Engine,
    component: &Component,
    caps: &CapabilitySet,
    budget: &ResourceBudget,
    input: &[u8],
    hook: &mut H,
) -> Result<InvokeSuccess, InvokeError> {
    let _slot = pool.acquire();
    invoke_with_cancel(engine, component, caps, budget, input, hook).await
}
