//! Pinned 1 ms epoch ticker (ADR-009 E.1) and preemption deadlines (ADR-008 E.1).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wasmtime::Engine;

/// Epoch tick interval is pinned at 1 ms; not configurable (ADR-009 E.1).
pub const EPOCH_TICK_MS: u64 = 1;

/// Metric: guest preemption kills (historical name `helix_kill_epoch_total`).
pub const METRIC_KILL_EPOCH: &str = "helix_kill_epoch_total";

/// Alias metric name after ADR-008 E.1 rename (runbook `helix_kill_preempt_total`).
pub const METRIC_KILL_PREEMPT: &str = "helix_kill_preempt_total";

/// Supervised `std::thread` that advances `engine` epoch every [`EPOCH_TICK_MS`].
///
/// Not a tokio task: ADR wants a dedicated ticker thread. Dropping this handle
/// signals stop and joins the thread.
#[derive(Debug)]
pub struct EpochTicker {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl EpochTicker {
    /// Spawn the ticker. Advances unconditionally until [`EpochTicker::stop`] / drop.
    #[must_use]
    pub fn start(engine: Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name("helix-epoch-ticker".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    engine.increment_epoch();
                    thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                }
            })
            .expect("spawn helix-epoch-ticker");
        Self {
            stop,
            join: Some(join),
        }
    }

    /// Signal the ticker to exit and join it.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Derive `preempt_ticks` when absent from a budget: `wall_clock_ms` (tick = 1 ms).
#[must_use]
pub fn default_preempt_ticks(wall_clock_ms: u32) -> u32 {
    wall_clock_ms
}

/// Record preemption kill metrics (both historical and renamed names).
pub fn record_preempt_kill() {
    metrics::counter!(METRIC_KILL_EPOCH).increment(1);
    metrics::counter!(METRIC_KILL_PREEMPT).increment(1);
}
