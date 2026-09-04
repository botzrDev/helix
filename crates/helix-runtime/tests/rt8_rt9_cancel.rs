//! RT-8 / RT-9 cancellation (HLX-28 / M4-05).
//!
//! RT-8 uses a stub blocking host until wasi:http (HLX-30). RT-9 uses a test
//! double child in the parent `JoinSet` until helix:delegate (HLX-31).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use helix_runtime::{
    host_select, run_with_wall_clock, spawn_cancellable, stub_blocking_host, InvokeError,
    KillCause, RecordingHook, RequestLifecycle, TerminalHook, TerminalKind, TerminalRecord, Usage,
};
use tokio_util::sync::CancellationToken;

/// RT-8: blocking host call cancelled at `wall_clock_ms` → `Killed(WallClock)` / `-32011`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt8_blocking_host_cancelled_at_wall_clock() {
    let wall_ms = 40u32;
    let started = Instant::now();

    let mut hook = RecordingHook::default();
    let cause = run_with_wall_clock(wall_ms, |token| async move {
        // Stub tarpit host (stands in for wasi:http until HLX-30): parks until
        // the wall-clock timer cancels the request token.
        let parked: Result<(), KillCause> =
            host_select(&token, KillCause::WallClock, std::future::pending::<()>()).await;
        let _ = parked;
        stub_blocking_host(&token).await;
        Err::<(), KillCause>(KillCause::WallClock)
    })
    .await
    .expect_err("must kill at wall clock");

    assert_eq!(cause, KillCause::WallClock);
    assert_eq!(cause.gateway_code(), -32011);

    let usage = Usage {
        wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        preempt_ticks: 0,
        peak_memory_bytes: 0,
        output_bytes: 0,
    };
    hook.on_terminal(TerminalRecord {
        kind: TerminalKind::Killed { cause },
        usage,
    });

    let err = InvokeError::Killed { cause, usage };
    assert_eq!(err.gateway_code(), -32011);
    assert!(
        usage.wall_ms >= u64::from(wall_ms.saturating_sub(5)),
        "wall_ms={} below budget",
        usage.wall_ms
    );
    assert!(
        usage.wall_ms < u64::from(wall_ms) + 500,
        "wall_ms={} far above budget (cancel stuck?)",
        usage.wall_ms
    );

    assert_eq!(hook.records.len(), 1);
    assert!(matches!(
        hook.records[0].kind,
        TerminalKind::Killed {
            cause: KillCause::WallClock
        }
    ));
    assert_eq!(hook.records[0].gateway_code(), Some(-32011));
}

/// RT-9: parent cancel/drop aborts the child → `Killed(ParentDropped)` / `-32014`.
///
/// Sequence matches L2: cancel the parent token tree (what [`RequestLifecycle`]
/// Drop does), let the `JoinSet` child observe it and write the terminal, then
/// drop the parent. Abort is a backup for non-cooperative children (HLX-31).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt9_parent_drop_aborts_child_parent_dropped() {
    let child_records: Arc<Mutex<RecordingHook>> = Arc::new(Mutex::new(RecordingHook::default()));
    let finished = Arc::new(AtomicBool::new(false));

    let mut parent = RequestLifecycle::new();
    let records = Arc::clone(&child_records);
    let flag = Arc::clone(&finished);
    parent.spawn_child(move |child_token| async move {
        // Test double child (helix:delegate populates JoinSet in HLX-31).
        child_token.cancelled().await;
        let mut hook = records.lock().expect("child hook");
        hook.on_terminal(TerminalRecord {
            kind: TerminalKind::Killed {
                cause: KillCause::ParentDropped,
            },
            usage: Usage::default(),
        });
        flag.store(true, Ordering::SeqCst);
    });

    assert_eq!(parent.child_count(), 1);

    // Park the child on cancelled() before we cancel the parent.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    // Dropping the parent request future cancels child tokens (L2).
    // Cancel + join first so the cooperative terminal is durable; Drop then
    // disarms ParentDropped attribution for the parent itself.
    parent.cancel_parent_dropped();
    tokio::time::timeout(Duration::from_secs(2), parent.join_children())
        .await
        .expect("child should finish after ParentDropped cancel");
    assert!(
        finished.load(Ordering::SeqCst),
        "child did not record ParentDropped"
    );
    parent.disarm_parent_drop();
    drop(parent);

    let hook = child_records.lock().expect("hook");
    assert_eq!(
        hook.records.len(),
        1,
        "child must emit exactly one terminal"
    );
    assert!(matches!(
        hook.records[0].kind,
        TerminalKind::Killed {
            cause: KillCause::ParentDropped
        }
    ));
    assert_eq!(hook.records[0].gateway_code(), Some(-32014));
}

/// Drop of [`RequestLifecycle`] cancels linked child tokens (L2 / RT-9).
#[tokio::test]
async fn rt9_drop_cancels_child_token() {
    let parent = RequestLifecycle::new();
    let child = parent.child_token();
    assert!(!child.is_cancelled());
    drop(parent);
    assert!(
        child.is_cancelled(),
        "dropping parent must cancel child tokens"
    );
}

/// ST-2 helper: `spawn_cancellable` is usable and receives the token.
#[tokio::test]
async fn spawn_cancellable_runs_with_token() {
    let token = CancellationToken::new();
    let handle = spawn_cancellable(token.clone(), |t| async move {
        assert!(!t.is_cancelled());
        t.cancel();
        t.is_cancelled()
    });
    assert!(handle.await.expect("join"));
}

/// Gateway code table for HLX-28 causes.
#[test]
fn gateway_codes_wall_and_parent() {
    assert_eq!(KillCause::WallClock.gateway_code(), -32011);
    assert_eq!(KillCause::ParentDropped.gateway_code(), -32014);
    assert_eq!(KillCause::WallClock.as_str(), "wall-clock");
    assert_eq!(KillCause::ParentDropped.as_str(), "parent-dropped");
}
