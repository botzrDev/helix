//! `CancellationToken` lifecycle, `spawn_cancellable`, and child `JoinSet` (M4-05 / HLX-28).
//!
//! ## ST-2 / ADR-003
//!
//! [`spawn_cancellable`] is the **only** `tokio::spawn` call site in the workspace.
//! Clippy bans bare `tokio::spawn` / `tokio::task::spawn` (`clippy.toml`); this
//! module carries the sole `#[allow(clippy::disallowed_methods)]`.
//!
//! Child invocations use [`ChildJoinSet`] / [`RequestLifecycle`] (`tokio::task::JoinSet`)
//! per ADR-009 A.1 — `JoinSet::spawn` is not `tokio::spawn` and remains the
//! delegation scaffolding (populated by `helix:delegate` in HLX-31).
//!
//! ## L1 / L2 / S3
//!
//! * Wall-clock timer cancels the request token → [`KillCause::WallClock`] (`-32011`).
//! * Dropping the parent lifecycle cancels child tokens → [`KillCause::ParentDropped`] (`-32014`).
//! * The request future owns the `Store` (callers keep Store locals inside the
//!   future body); dropping the future drops the sandbox.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::error::KillCause;

/// Metric: wall-clock kills (`-32011`).
pub const METRIC_KILL_WALL_CLOCK: &str = "helix_kill_wall_clock_total";

/// Metric: parent-dropped child kills (`-32014`).
pub const METRIC_KILL_PARENT_DROPPED: &str = "helix_kill_parent_dropped_total";

/// Record a wall-clock kill metric.
pub fn record_wall_clock_kill() {
    metrics::counter!(METRIC_KILL_WALL_CLOCK).increment(1);
}

/// Record a parent-dropped kill metric.
pub fn record_parent_dropped_kill() {
    metrics::counter!(METRIC_KILL_PARENT_DROPPED).increment(1);
}

/// The only `tokio::spawn` in the workspace (ST-2).
///
/// `factory` receives a clone of `token` and must drive cooperative cancellation
/// (typically `tokio::select!` against `token.cancelled()`).
#[allow(clippy::disallowed_methods)] // ST-2: sole allowed tokio::spawn site
pub fn spawn_cancellable<F, Fut, T>(token: CancellationToken, factory: F) -> JoinHandle<T>
where
    F: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(factory(token))
}

/// Race an async host operation against a [`CancellationToken`].
///
/// On cancel, returns `Err(kill_on_cancel)` without awaiting further host work
/// (cancel-safe: the op future is dropped).
pub async fn host_select<T, Fut>(
    token: &CancellationToken,
    kill_on_cancel: KillCause,
    op: Fut,
) -> Result<T, KillCause>
where
    Fut: Future<Output = T>,
{
    tokio::select! {
        biased;
        () = token.cancelled() => Err(kill_on_cancel),
        out = op => Ok(out),
    }
}

/// Parks until `token` is cancelled (legacy RT-8 double; prefer real HTTP).
///
/// Kept for unit coverage of token parking. RT-8 now uses
/// [`crate::http::host_http_get_status`] against a tarpit listener.
pub async fn stub_blocking_host(token: &CancellationToken) {
    token.cancelled().await;
}

/// Encoded cancel reason shared across the token tree (set-before-cancel).
#[derive(Debug)]
struct CancelReason(AtomicU8);

impl CancelReason {
    const NONE: u8 = 0;
    const WALL: u8 = 1;
    const PARENT: u8 = 2;

    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicU8::new(Self::NONE)))
    }

    fn set_wall(&self) {
        let _ = self
            .0
            .compare_exchange(Self::NONE, Self::WALL, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn set_parent(&self) {
        let _ =
            self.0
                .compare_exchange(Self::NONE, Self::PARENT, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn kill_cause(&self) -> Option<KillCause> {
        match self.0.load(Ordering::SeqCst) {
            Self::WALL => Some(KillCause::WallClock),
            Self::PARENT => Some(KillCause::ParentDropped),
            _ => None,
        }
    }
}

/// Parent-owned cancellation tree + child [`JoinSet`] scaffolding (ADR-009 A.1).
///
/// Dropping this value (while still attached) cancels the root token so children
/// observe [`KillCause::ParentDropped`], and [`JoinSet::abort_all`]s outstanding
/// children. `helix:delegate` (HLX-31) populates the `JoinSet`; tests may spawn
/// doubles via [`Self::spawn_child`].
#[derive(Debug)]
pub struct RequestLifecycle {
    root: CancellationToken,
    reason: Arc<CancelReason>,
    children: JoinSet<()>,
    /// Wall-clock timer task (aborted when this lifecycle is finished/dropped).
    wall_timer: Option<JoinHandle<()>>,
    /// When false, [`Drop`] still aborts children/timer but does not attribute
    /// [`KillCause::ParentDropped`] (used after a normal or wall-clock terminal).
    parent_drop_armed: AtomicBool,
}

impl RequestLifecycle {
    /// Fresh root token and empty child set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: CancellationToken::new(),
            reason: CancelReason::new(),
            children: JoinSet::new(),
            wall_timer: None,
            parent_drop_armed: AtomicBool::new(true),
        }
    }

    /// Borrow the root token (clone for host functions).
    #[must_use]
    pub fn token(&self) -> CancellationToken {
        self.root.clone()
    }

    /// Child token linked to the root (cancelled when the root is).
    #[must_use]
    pub fn child_token(&self) -> CancellationToken {
        self.root.child_token()
    }

    /// Current kill cause if the token was cancelled with a recorded reason.
    #[must_use]
    pub fn kill_cause(&self) -> Option<KillCause> {
        self.reason.kill_cause()
    }

    /// Whether the root token is cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.root.is_cancelled()
    }

    /// Number of child tasks in the `JoinSet` (fan-out bound input for HLX-31).
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Arm `budget.wall_clock_ms`: after the delay, cancel the root as `WallClock`.
    ///
    /// Idempotent: replaces any previous timer handle.
    pub fn arm_wall_clock(&mut self, wall_clock_ms: u32) {
        if let Some(prev) = self.wall_timer.take() {
            prev.abort();
        }
        let token = self.root.clone();
        let reason = Arc::clone(&self.reason);
        let ms = u64::from(wall_clock_ms);
        self.wall_timer = Some(spawn_cancellable(token.clone(), move |token| async move {
            tokio::select! {
                biased;
                () = token.cancelled() => {}
                () = tokio::time::sleep(Duration::from_millis(ms)) => {
                    reason.set_wall();
                    token.cancel();
                }
            }
        }));
    }

    /// Cancel as wall-clock (tests / explicit kill).
    pub fn cancel_wall_clock(&self) {
        self.reason.set_wall();
        self.root.cancel();
    }

    /// Cancel as parent-dropped (also invoked from [`Drop`] when armed).
    pub fn cancel_parent_dropped(&self) {
        self.reason.set_parent();
        self.root.cancel();
    }

    /// Disarm `ParentDropped` attribution (call after a wall-clock or success terminal).
    pub fn disarm_parent_drop(&self) {
        self.parent_drop_armed.store(false, Ordering::SeqCst);
    }

    /// Spawn a child future into the parent `JoinSet` with a linked child token.
    ///
    /// The factory receives the **child** token. When the parent is dropped (or
    /// otherwise cancels the root), the child token fires; cooperative children
    /// should record [`KillCause::ParentDropped`].
    pub fn spawn_child<F, Fut>(&mut self, factory: F)
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let child = self.root.child_token();
        self.children.spawn(factory(child));
    }

    /// Abort all children and cancel the root (`ParentDropped`).
    pub fn abort_children(&mut self) {
        self.cancel_parent_dropped();
        self.children.abort_all();
    }

    /// Wait until every child task has finished (after cooperative cancel).
    pub async fn join_children(&mut self) {
        while self.children.join_next().await.is_some() {}
    }

    /// Stop the wall-clock timer without cancelling the request token.
    pub fn stop_wall_timer(&mut self) {
        if let Some(timer) = self.wall_timer.take() {
            timer.abort();
        }
    }
}

impl Default for RequestLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RequestLifecycle {
    fn drop(&mut self) {
        if let Some(timer) = self.wall_timer.take() {
            timer.abort();
        }
        self.children.abort_all();
        if self.parent_drop_armed.load(Ordering::SeqCst) && !self.root.is_cancelled() {
            self.reason.set_parent();
            self.root.cancel();
            record_parent_dropped_kill();
        } else if !self.root.is_cancelled() {
            // Detached finish: quiet cancel so any leftover host selects exit.
            self.root.cancel();
        }
    }
}

/// Type alias documenting the child `JoinSet` role for HLX-31 wiring.
pub type ChildJoinSet = JoinSet<()>;

/// Run `work` under a wall-clock budget: token cancel → [`KillCause::WallClock`].
///
/// `work` receives the request token (clone into every host call). The Store
/// must be owned inside `work` so dropping this future drops the sandbox (S3).
pub async fn run_with_wall_clock<F, Fut, T>(wall_clock_ms: u32, work: F) -> Result<T, KillCause>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: Future<Output = Result<T, KillCause>>,
{
    let mut life = RequestLifecycle::new();
    life.arm_wall_clock(wall_clock_ms);
    let token = life.token();
    let cancel_wait = token.clone();

    let result = tokio::select! {
        biased;
        () = cancel_wait.cancelled() => {
            Err(life.kill_cause().unwrap_or(KillCause::WallClock))
        }
        out = work(token) => out,
    };

    life.stop_wall_timer();
    life.disarm_parent_drop();

    if matches!(result, Err(KillCause::WallClock)) {
        record_wall_clock_kill();
    }
    result
}
