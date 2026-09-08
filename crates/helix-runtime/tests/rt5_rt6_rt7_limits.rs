//! RT-5 / RT-6 / RT-7 resource limits (HLX-27 / M4-04).
//!
//! BENCH-8 (preempt kill ≤ 12 ms p99 at `preempt_ticks = 10`) is informational
//! until M7-01 and is not asserted here.

use std::fs;
use std::path::PathBuf;

use helix_caps::ResourceBudget;
use helix_runtime::{
    build_engine, deliver_output, run_limited, BoundedWriter, EpochTicker, InvokeError, KillCause,
    NopHook, RecordingHook, RuntimeConfig, TerminalGuard, TerminalKind, Usage,
};
use wasmtime::component::Component;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/adversarial")
        .join(name)
}

fn test_engine(mem: usize) -> (tempfile::TempDir, wasmtime::Engine) {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = RuntimeConfig::new(tmp.path(), 4, mem);
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

/// RT-5: `loop {}` killed with `Killed(Preempted)` within `preempt_ticks + 2`.
#[test]
fn rt5_spin_preempted_within_preempt_ticks_plus_two() {
    let preempt_ticks = 10u32;
    let (_tmp, engine) = test_engine(4 * 1024 * 1024);
    let _ticker = EpochTicker::start(engine.clone());

    let bytes = fs::read(fixture("spin.wasm")).expect("spin.wasm");
    let component = Component::new(&engine, &bytes).expect("parse spin");
    let budget = budget(preempt_ticks, 5_000, 4 * 1024 * 1024, 1024);

    let mut hook = RecordingHook::default();
    let started = std::time::Instant::now();
    let err = run_limited(&engine, &component, &budget, &mut hook).expect_err("must kill");
    let elapsed_ms = started.elapsed().as_millis();

    match &err {
        InvokeError::Killed {
            cause: KillCause::Preempted,
            usage,
        } => {
            assert_eq!(err.gateway_code(), -32010);
            assert!(
                usage.wall_ms <= u64::from(preempt_ticks) + 50,
                "wall_ms={} too large",
                usage.wall_ms
            );
        }
        other => panic!("expected Preempted, got {other:?}"),
    }

    // Tick is 1 ms ⇒ kill within preempt_ticks + 2 ticks (plus small scheduler slack).
    assert!(
        elapsed_ms <= u128::from(preempt_ticks) + 2 + 25,
        "elapsed {elapsed_ms} ms exceeds preempt_ticks+2 (+slack); BENCH-8 tighter bound is M7-01"
    );

    assert_eq!(hook.records.len(), 1);
    assert!(matches!(
        hook.records[0].kind,
        TerminalKind::Killed {
            cause: KillCause::Preempted
        }
    ));
}

/// RT-6: memory bomb → `Killed(Memory)`; host RSS stays within budget + 8 MiB of baseline.
#[test]
fn rt6_membomb_killed_rss_bound() {
    let memory_budget = 1024 * 1024u64; // 1 MiB
    let slack = 8 * 1024 * 1024u64; // 8 MiB
    let (_tmp, engine) = test_engine(2 * 1024 * 1024);
    let _ticker = EpochTicker::start(engine.clone());

    let bytes = fs::read(fixture("membomb.wasm")).expect("membomb.wasm");
    let component = Component::new(&engine, &bytes).expect("parse membomb");
    // Generous preempt so memory kill wins.
    let budget = budget(60_000, 60_000, memory_budget, 1024);

    let rss_before = read_vm_rss_kb() * 1024;
    let mut hook = RecordingHook::default();
    let err = run_limited(&engine, &component, &budget, &mut hook).expect_err("must kill");
    let rss_after = read_vm_rss_kb() * 1024;

    match &err {
        InvokeError::Killed {
            cause: KillCause::Memory,
            usage,
        } => {
            assert_eq!(err.gateway_code(), -32012);
            assert!(
                usage.peak_memory_bytes <= memory_budget + 64 * 1024,
                "peak {} > budget",
                usage.peak_memory_bytes
            );
        }
        other => panic!("expected Memory kill, got {other:?}"),
    }

    let growth = rss_after.saturating_sub(rss_before);
    assert!(
        growth <= memory_budget + slack,
        "RSS grew by {growth} bytes; budget+8MiB = {}",
        memory_budget + slack
    );

    assert_eq!(hook.records.len(), 1);
    assert!(matches!(
        hook.records[0].kind,
        TerminalKind::Killed {
            cause: KillCause::Memory
        }
    ));
}

/// RT-7: output past `output_bytes` → `Killed(Output)`; caller gets no partial bytes.
#[test]
fn rt7_output_flood_killed_no_partial() {
    let limit = 64u32;
    let flood = vec![0x41u8; (limit as usize) + 1];

    // Direct writer (S4).
    let mut w = BoundedWriter::new(limit);
    assert!(w.write(&flood).is_err());
    assert!(w.exceeded());
    assert_eq!(w.written(), 0);
    assert!(w.finish().is_err());

    // Through deliver_output + terminal guard.
    let mut hook = RecordingHook::default();
    let mut guard = TerminalGuard::new(&mut hook);
    let usage_base = Usage {
        wall_ms: 1,
        preempt_ticks: 1,
        peak_memory_bytes: 0,
        output_bytes: 0,
    };
    let err = deliver_output(flood, limit, usage_base, &mut guard).expect_err("output kill");
    match err {
        InvokeError::Killed {
            cause: KillCause::Output,
            usage,
        } => {
            assert_eq!(usage.output_bytes, 0);
            assert_eq!(err.gateway_code(), -32013);
        }
        other => panic!("expected Output kill, got {other:?}"),
    }
    drop(guard);
    assert_eq!(hook.records.len(), 1);
    match &hook.records[0].kind {
        TerminalKind::Killed {
            cause: KillCause::Output,
        } => {}
        other => panic!("terminal {other:?}"),
    }
    // No partial output retained on the record.
    assert_eq!(hook.records[0].usage.output_bytes, 0);
}

/// D3: drop guard emits exactly one `Killed{panic}` when the guarded scope panics.
#[test]
fn d3_terminal_guard_fires_on_panic() {
    let mut hook = RecordingHook::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = TerminalGuard::new(&mut hook);
        guard.set_usage(Usage::default());
        panic!("host boom");
        #[allow(unreachable_code)]
        {
            guard.record(TerminalKind::Completed { output: vec![] });
        }
    }));
    assert!(result.is_err());
    assert_eq!(hook.records.len(), 1);
    assert!(matches!(
        hook.records[0].kind,
        TerminalKind::Killed {
            cause: KillCause::Panic
        }
    ));
    assert_eq!(hook.records[0].gateway_code(), Some(-32007));
}

/// Happy-path bound under the limit yields Completed with `output_bytes` set.
#[test]
fn output_within_limit_completes() {
    let mut hook = RecordingHook::default();
    let mut guard = TerminalGuard::new(&mut hook);
    let out = deliver_output(b"ok".to_vec(), 16, Usage::default(), &mut guard).unwrap();
    assert_eq!(out.output, b"ok");
    assert_eq!(out.usage.output_bytes, 2);
    drop(guard);
    assert_eq!(hook.records.len(), 1);
}

/// `NopHook` compiles / accepts terminals (gateway may use until audit is wired).
#[test]
fn nop_hook_accepts_terminal() {
    let mut nop = NopHook;
    let mut guard = TerminalGuard::new(&mut nop);
    guard.record(TerminalKind::Completed { output: vec![1] });
    assert!(guard.recorded());
}
