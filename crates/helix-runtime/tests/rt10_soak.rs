//! RT-10 soak test and pool accounting (HLX-29 / M4-06).
//!
//! Drives 10,000 sequential invocations of `trivial.wasm` through
//! `runtime::run_limited_pooled` (production `invoke` still needs WASI env for
//! hello-world; adversarial `run` fixtures need no imports — same Store /
//! `InstancePre` / pool-slot lifecycle as the request path).
//!
//! Asserts:
//! - `helix_pool_in_use` / [`InstancePool::in_use`] returns to zero
//! - RSS growth ≤ 5 % over warmup
//! - no file-descriptor growth over warmup
//!
//! Pool accounting under concurrent kills (preempt, memory, output, wall clock,
//! parent dropped): every path releases its slot.
//!
//! BENCH-7 (RSS after 100,000 at c=64) is deferred to M7-01.

#![allow(clippy::cast_precision_loss)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use helix_caps::ResourceBudget;
use helix_runtime::{
    build_engine, deliver_output, host_select, run_limited_pooled, run_with_wall_clock,
    spawn_cancellable, EpochTicker, InstancePool, InvokeError, KillCause, NopHook, RecordingHook,
    RequestLifecycle, RuntimeConfig, TerminalGuard, TerminalKind, Usage,
};
use tokio_util::sync::CancellationToken;
use wasmtime::component::Component;

const SOAK_ITERS: usize = 10_000;
const WARMUP_ITERS: usize = 200;
const KILL_FANOUT: usize = 8;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/adversarial")
        .join(name)
}

fn test_engine(mem: usize, concurrent: u32) -> (tempfile::TempDir, wasmtime::Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = RuntimeConfig::new(tmp.path(), concurrent, mem);
    let engine = build_engine(&cfg).expect("engine");
    (tmp, engine)
}

fn budget(preempt: u32, wall: u32, memory: u64, output: u32) -> ResourceBudget {
    ResourceBudget::new(preempt, wall, memory, output, 2, 8, 4)
}

fn read_vm_rss_kb() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .expect("rss");
            return kb;
        }
    }
    panic!("VmRSS missing");
}

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("fd dir")
        .filter_map(Result::ok)
        .count()
}

fn load_component(engine: &wasmtime::Engine, name: &str) -> Component {
    let bytes = fs::read(fixture(name)).unwrap_or_else(|_| panic!("{name}"));
    Component::new(engine, bytes).unwrap_or_else(|_| panic!("parse {name}"))
}

/// RT-10: 10,000 sequential trivial invocations; pool / RSS / FD stay flat.
#[test]
fn rt10_soak_10000_sequential_zero_leak() {
    let mem = 4 * 1024 * 1024;
    let (_tmp, engine) = test_engine(mem, 8);
    let _ticker = EpochTicker::start(engine.clone());
    let component = load_component(&engine, "trivial.wasm");
    let budget = budget(60_000, 60_000, u64::try_from(mem).unwrap(), 1024);
    let pool = InstancePool::new();

    let mut hook = NopHook;
    for _ in 0..WARMUP_ITERS {
        run_limited_pooled(&pool, &engine, &component, &budget, &mut hook).expect("warmup");
    }
    assert_eq!(pool.in_use(), 0, "warmup must release every slot");

    for _ in 0..3 {
        let _ = read_vm_rss_kb();
        let _ = fd_count();
        thread::sleep(Duration::from_millis(20));
    }
    let rss_warmup = read_vm_rss_kb();
    let fd_warmup = fd_count();

    for i in 0..SOAK_ITERS {
        run_limited_pooled(&pool, &engine, &component, &budget, &mut hook)
            .unwrap_or_else(|e| panic!("soak iter {i}: {e:?}"));
        assert_eq!(pool.in_use(), 0, "slot leak after soak iter {i}");
    }

    let rss_after = read_vm_rss_kb();
    let fd_after = fd_count();
    let growth = if rss_warmup == 0 {
        0.0
    } else {
        (rss_after as f64 - rss_warmup as f64) / (rss_warmup as f64)
    };
    eprintln!(
        "RT-10: iters={SOAK_ITERS} rss_warmup_kb={rss_warmup} rss_after_kb={rss_after} \
         growth={:.3}% fd_warmup={fd_warmup} fd_after={fd_after} pool_in_use={}",
        growth * 100.0,
        pool.in_use()
    );

    assert_eq!(pool.in_use(), 0, "helix_pool_in_use must return to zero");
    assert!(
        growth <= 0.05,
        "RSS growth {:.2}% exceeds 5% (warmup={rss_warmup}kb after={rss_after}kb)",
        growth * 100.0
    );
    assert_eq!(
        fd_after, fd_warmup,
        "FD count grew: warmup={fd_warmup} after={fd_after}"
    );
}

fn spawn_preempt_kills(
    pool: &Arc<InstancePool>,
    engine: &wasmtime::Engine,
    spin: &Component,
    mem: usize,
    kills: &Arc<AtomicUsize>,
    errors: &Arc<Mutex<Vec<String>>>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for _ in 0..KILL_FANOUT {
        let pool = Arc::clone(pool);
        let engine = engine.clone();
        let spin = spin.clone();
        let kills = Arc::clone(kills);
        let errors = Arc::clone(errors);
        handles.push(tokio::task::spawn_blocking(move || {
            let budget = budget(8, 5_000, u64::try_from(mem).unwrap(), 1024);
            let mut hook = RecordingHook::default();
            match run_limited_pooled(&pool, &engine, &spin, &budget, &mut hook) {
                Err(InvokeError::Killed {
                    cause: KillCause::Preempted,
                    ..
                }) => {
                    kills.fetch_add(1, Ordering::SeqCst);
                }
                other => errors
                    .lock()
                    .unwrap()
                    .push(format!("preempt path: {other:?}")),
            }
        }));
    }
}

fn spawn_memory_kills(
    pool: &Arc<InstancePool>,
    engine: &wasmtime::Engine,
    membomb: &Component,
    kills: &Arc<AtomicUsize>,
    errors: &Arc<Mutex<Vec<String>>>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for _ in 0..KILL_FANOUT {
        let pool = Arc::clone(pool);
        let engine = engine.clone();
        let membomb = membomb.clone();
        let kills = Arc::clone(kills);
        let errors = Arc::clone(errors);
        handles.push(tokio::task::spawn_blocking(move || {
            let budget = budget(60_000, 60_000, 1024 * 1024, 1024);
            let mut hook = RecordingHook::default();
            match run_limited_pooled(&pool, &engine, &membomb, &budget, &mut hook) {
                Err(InvokeError::Killed {
                    cause: KillCause::Memory,
                    ..
                }) => {
                    kills.fetch_add(1, Ordering::SeqCst);
                }
                other => errors
                    .lock()
                    .unwrap()
                    .push(format!("memory path: {other:?}")),
            }
        }));
    }
}

fn spawn_output_kills(
    pool: &Arc<InstancePool>,
    kills: &Arc<AtomicUsize>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for _ in 0..KILL_FANOUT {
        let pool = Arc::clone(pool);
        let kills = Arc::clone(kills);
        handles.push(tokio::task::spawn_blocking(move || {
            let slot = pool.acquire();
            let mut hook = RecordingHook::default();
            let mut guard = TerminalGuard::new(&mut hook);
            let err = deliver_output(vec![0u8; 64], 16, Usage::default(), &mut guard);
            assert!(matches!(
                err,
                Err(InvokeError::Killed {
                    cause: KillCause::Output,
                    ..
                })
            ));
            drop(guard);
            drop(slot);
            kills.fetch_add(1, Ordering::SeqCst);
        }));
    }
}

fn spawn_wall_kills(
    pool: &Arc<InstancePool>,
    root: &CancellationToken,
    kills: &Arc<AtomicUsize>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for _ in 0..KILL_FANOUT {
        let pool = Arc::clone(pool);
        let kills = Arc::clone(kills);
        handles.push(spawn_cancellable(
            root.child_token(),
            move |_t| async move {
                let slot = pool.acquire();
                let cause = run_with_wall_clock(30, |token| async move {
                    let _: Result<(), KillCause> =
                        host_select(&token, KillCause::WallClock, std::future::pending::<()>())
                            .await;
                    Err::<(), KillCause>(KillCause::WallClock)
                })
                .await
                .expect_err("wall clock");
                assert_eq!(cause, KillCause::WallClock);
                drop(slot);
                kills.fetch_add(1, Ordering::SeqCst);
            },
        ));
    }
}

fn spawn_parent_drop_kills(
    pool: &Arc<InstancePool>,
    root: &CancellationToken,
    kills: &Arc<AtomicUsize>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for _ in 0..KILL_FANOUT {
        let pool = Arc::clone(pool);
        let kills = Arc::clone(kills);
        handles.push(spawn_cancellable(
            root.child_token(),
            move |_t| async move {
                let slot = pool.acquire();
                let finished = Arc::new(AtomicUsize::new(0));
                let mut parent = RequestLifecycle::new();
                let flag = Arc::clone(&finished);
                parent.spawn_child(move |child_token| async move {
                    child_token.cancelled().await;
                    flag.fetch_add(1, Ordering::SeqCst);
                });
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
                parent.cancel_parent_dropped();
                tokio::time::timeout(Duration::from_secs(2), parent.join_children())
                    .await
                    .expect("child join");
                assert_eq!(finished.load(Ordering::SeqCst), 1);
                parent.disarm_parent_drop();
                drop(parent);
                drop(slot);
                kills.fetch_add(1, Ordering::SeqCst);
            },
        ));
    }
}

fn spawn_trivial_ok(
    pool: &Arc<InstancePool>,
    engine: &wasmtime::Engine,
    trivial: &Component,
    mem: usize,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for _ in 0..(KILL_FANOUT * 2) {
        let pool = Arc::clone(pool);
        let engine = engine.clone();
        let trivial = trivial.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let budget = budget(60_000, 60_000, u64::try_from(mem).unwrap(), 1024);
            let mut hook = NopHook;
            run_limited_pooled(&pool, &engine, &trivial, &budget, &mut hook).expect("trivial");
        }));
    }
}

/// Every kill path releases its pool slot (preempt / memory / output / wall / parent-drop).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt10_pool_accounting_exact_under_concurrent_kills() {
    let mem = 4 * 1024 * 1024;
    let (_tmp, engine) = test_engine(mem, 64);
    let _ticker = EpochTicker::start(engine.clone());
    let pool = Arc::new(InstancePool::new());
    let root = CancellationToken::new();

    let spin = load_component(&engine, "spin.wasm");
    let membomb = load_component(&engine, "membomb.wasm");
    let trivial = load_component(&engine, "trivial.wasm");

    let kills = Arc::new(AtomicUsize::new(0));
    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    spawn_preempt_kills(&pool, &engine, &spin, mem, &kills, &errors, &mut handles);
    spawn_memory_kills(&pool, &engine, &membomb, &kills, &errors, &mut handles);
    spawn_output_kills(&pool, &kills, &mut handles);
    spawn_wall_kills(&pool, &root, &kills, &mut handles);
    spawn_parent_drop_kills(&pool, &root, &kills, &mut handles);
    spawn_trivial_ok(&pool, &engine, &trivial, mem, &mut handles);

    for h in handles {
        h.await.expect("join task");
    }

    let errs = errors.lock().unwrap();
    assert!(errs.is_empty(), "kill path mismatches: {errs:?}");
    assert_eq!(
        pool.in_use(),
        0,
        "pool must be empty after concurrent kills"
    );
    assert_eq!(
        kills.load(Ordering::SeqCst),
        KILL_FANOUT * 5,
        "expected {} kill-path completions",
        KILL_FANOUT * 5
    );
}

/// Happy-path pooled trivial completes and releases the slot.
#[test]
fn rt10_trivial_completes_under_pool() {
    let (_tmp, engine) = test_engine(2 * 1024 * 1024, 4);
    let _ticker = EpochTicker::start(engine.clone());
    let component = load_component(&engine, "trivial.wasm");
    let pool = InstancePool::new();
    let mut hook = RecordingHook::default();
    let usage = run_limited_pooled(
        &pool,
        &engine,
        &component,
        &budget(1_000, 1_000, 2 * 1024 * 1024, 256),
        &mut hook,
    )
    .expect("complete");
    assert_eq!(pool.in_use(), 0);
    assert_eq!(hook.records.len(), 1);
    assert!(matches!(
        hook.records[0].kind,
        TerminalKind::Completed { .. }
    ));
    assert!(usage.wall_ms < 1_000);
}
