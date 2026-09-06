//! BENCH-1: `CapabilitySet::is_subset_of` on sets with 32 files, 32 dirs, and 8 hosts.
//!
//! Protocol gate: median < 500 ns. Regression > 20 % fails CI when a tagged
//! baseline exists. Absolute gate is informational on shared CI runners
//! (AX42-1 / D-5 not provisioned); set `HELIX_BENCH_ENFORCE_GATES=1` for
//! strict reference-hardware enforcement.

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use helix_caps::{
    CapabilitySet, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner, Method,
    MethodMask,
};

const GATE_NS: u64 = 500;
/// Slack for noisy CI VMs when absolute gate is checked without AX hardware.
const CI_SLACK: u64 = 40;
const GATE_ITERS: usize = 10_000;
const WARMUP_ITERS: usize = 1_000;

fn build_sets() -> (CapabilitySet, CapabilitySet) {
    let mut intern = Interner::new();
    let mut files = Vec::with_capacity(32);
    let mut dirs = Vec::with_capacity(32);
    for i in 0..32 {
        let f = format!("/srv/bench/files/f{i:02}.dat");
        let d = format!("/srv/bench/dirs/d{i:02}");
        files.push(FileGrant::new(
            intern.intern_path(Path::new(&f)),
            FileMode::Read,
        ));
        dirs.push(DirGrant::new(
            intern.intern_path(Path::new(&d)),
            FileMode::ReadWrite,
        ));
    }
    let mut hosts = Vec::with_capacity(8);
    for i in 0..8 {
        let auth = format!("host{i}.bench.test:443");
        hosts.push(HostGrant::new(
            intern.intern_authority(&auth),
            MethodMask::new(&[Method::Get, Method::Post]),
        ));
    }
    let parent = CapabilitySet::new(
        &[
            Interface::Filesystem,
            Interface::HttpOutbound,
            Interface::Stdio,
        ],
        files.clone(),
        dirs.clone(),
        hosts.clone(),
    )
    .expect("parent")
    .with_interner(intern.clone());

    let child_files = files.into_iter().take(16).collect::<Vec<_>>();
    let child_hosts = hosts
        .into_iter()
        .map(|h| HostGrant::new(h.authority(), MethodMask::new(&[Method::Get])))
        .collect::<Vec<_>>();
    let child = CapabilitySet::new(
        &[
            Interface::Filesystem,
            Interface::HttpOutbound,
            Interface::Stdio,
        ],
        child_files,
        dirs,
        child_hosts,
    )
    .expect("child")
    .with_interner(intern);

    (child, parent)
}

fn criterion_bench(c: &mut Criterion) {
    let (child, parent) = build_sets();
    assert!(child.is_subset_of(&parent), "fixture must be a true subset");
    c.bench_function("BENCH-1 is_subset_of 32f/32d/8h", |b| {
        b.iter(|| black_box(child.is_subset_of(black_box(&parent))));
    });
}

fn gate_check() {
    let (child, parent) = build_sets();
    for _ in 0..WARMUP_ITERS {
        black_box(child.is_subset_of(&parent));
    }
    let mut samples = Vec::with_capacity(GATE_ITERS);
    for _ in 0..GATE_ITERS {
        let t0 = Instant::now();
        black_box(child.is_subset_of(black_box(&parent)));
        samples.push(t0.elapsed());
    }
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let median_ns = u64::try_from(median.as_nanos()).unwrap_or(u64::MAX);
    let enforce = std::env::var_os("HELIX_BENCH_ENFORCE_GATES").is_some();
    let limit = if enforce {
        GATE_NS
    } else {
        GATE_NS.saturating_mul(CI_SLACK)
    };
    eprintln!("BENCH-1 median={median_ns} ns gate={GATE_NS} ns limit={limit} ns enforce={enforce}");
    assert!(
        median_ns <= limit,
        "BENCH-1 median {median_ns} ns exceeds limit {limit} ns (protocol gate {GATE_NS} ns)"
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
