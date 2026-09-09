//! BENCH-3: pooled instantiate + invoke of `trivial.wasm`, no audit sync.
//!
//! Protocol gate: median < 50 µs (single thread). Absolute gate is
//! informational on CI without AX42-1; set `HELIX_BENCH_ENFORCE_GATES=1`
//! for strict reference-hardware enforcement.

use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use helix_caps::ResourceBudget;
use helix_runtime::{
    build_engine, run_limited_pooled, EpochTicker, InstancePool, NopHook, RuntimeConfig,
};
use wasmtime::component::Component;

const GATE_US: u64 = 50;
const CI_SLACK: u64 = 80;
const GATE_ITERS: usize = 2_000;
const WARM_ITERS: usize = 50;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/adversarial/trivial.wasm")
}

struct InvokeFixture {
    _tmp: tempfile::TempDir,
    engine: wasmtime::Engine,
    _ticker: EpochTicker,
    component: Component,
    budget: ResourceBudget,
    pool: InstancePool,
}

fn setup() -> InvokeFixture {
    let tmp = tempfile::tempdir().expect("tmp");
    let mem = 4 * 1024 * 1024;
    let cfg = RuntimeConfig::new(tmp.path(), 8, mem);
    let engine = build_engine(&cfg).expect("engine");
    let ticker = EpochTicker::start(engine.clone());
    let bytes = fs::read(fixture_path()).expect("trivial.wasm");
    let component = Component::new(&engine, bytes).expect("parse");
    let budget = ResourceBudget::new(60_000, 60_000, u64::try_from(mem).unwrap(), 1024, 2, 8, 4);
    let pool = InstancePool::new();
    let mut hook = NopHook;
    for _ in 0..WARM_ITERS {
        run_limited_pooled(&pool, &engine, &component, &budget, &mut hook).expect("warm");
    }
    InvokeFixture {
        _tmp: tmp,
        engine,
        _ticker: ticker,
        component,
        budget,
        pool,
    }
}

fn criterion_bench(c: &mut Criterion) {
    let f = setup();
    let mut hook = NopHook;
    c.bench_function("BENCH-3 pooled instantiate+trivial invoke", |b| {
        b.iter(|| {
            run_limited_pooled(
                black_box(&f.pool),
                black_box(&f.engine),
                black_box(&f.component),
                black_box(&f.budget),
                &mut hook,
            )
            .expect("invoke");
        });
    });
}

fn gate_check() {
    let f = setup();
    let mut hook = NopHook;
    let mut samples = Vec::with_capacity(GATE_ITERS);
    for _ in 0..GATE_ITERS {
        let t0 = Instant::now();
        run_limited_pooled(&f.pool, &f.engine, &f.component, &f.budget, &mut hook).expect("invoke");
        samples.push(t0.elapsed());
    }
    samples.sort_unstable();
    let median = samples[GATE_ITERS / 2];
    let median_us = u64::try_from(median.as_micros()).unwrap_or(u64::MAX);
    let enforce = std::env::var_os("HELIX_BENCH_ENFORCE_GATES").is_some();
    let limit = if enforce {
        GATE_US
    } else {
        GATE_US.saturating_mul(CI_SLACK)
    };
    eprintln!("BENCH-3 median={median_us} µs gate={GATE_US} µs limit={limit} µs enforce={enforce}");
    assert!(
        median_us <= limit,
        "BENCH-3 median {median_us} µs exceeds limit {limit} µs (protocol gate {GATE_US} µs)"
    );
}

fn benches(c: &mut Criterion) {
    criterion_bench(c);
    if std::env::var_os("HELIX_BENCH_SKIP_GATES").is_none() {
        gate_check();
    }
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);
