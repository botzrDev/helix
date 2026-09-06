#![allow(clippy::cast_precision_loss)]

//! In-process e2e load scaffolding for BENCH-4..8 (not AX-gated).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use helix_caps::ResourceBudget;
use helix_runtime::{
    build_engine, run_limited_pooled, EpochTicker, InstancePool, NopHook, RuntimeConfig,
};
use wasmtime::component::Component;

use crate::results::{LatencyNs, Metric};

/// Supported load fixtures (protocol §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixture {
    Trivial,
    FsRead,
    HttpGet,
    Spin,
}

impl Fixture {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "trivial" => Ok(Self::Trivial),
            "fs_read" => Ok(Self::FsRead),
            "http_get" => Ok(Self::HttpGet),
            "spin" => Ok(Self::Spin),
            other => Err(format!("unknown fixture {other}")),
        }
    }

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Trivial => "trivial.wasm",
            Self::FsRead => "fs_read.wasm",
            Self::HttpGet => "http_get.wasm",
            Self::Spin => "spin.wasm",
        }
    }
}

fn resolve_fixture(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let candidates = [
        root.join("adversarial").join(name),
        root.join(name),
        root.join("adversarial/runtime").join(name),
    ];
    for c in candidates {
        if c.is_file() {
            return c;
        }
    }
    root.join("adversarial").join(name)
}

#[allow(clippy::too_many_lines)]
/// Run a short in-process load against a fixture; returns a metric row.
///
/// Full gateway+audit e2e on AX42-1 is deferred (HLX-7/8, D-5). This path
/// exercises pool instantiate+invoke so BENCH-4..8 scaffolding is real code.
pub fn run_scaffold(
    id: &str,
    name: &str,
    fixture: Fixture,
    concurrency: u32,
    duration: Duration,
    warmup: Duration,
    audit_sync: bool,
) -> Result<Metric, String> {
    let path = resolve_fixture(fixture.file_name());
    if !path.is_file() {
        return Ok(Metric {
            id: id.to_owned(),
            name: name.to_owned(),
            concurrency: Some(concurrency),
            throughput_rps: None,
            latency_ns: None,
            rss_bytes: None,
            rss_growth: None,
            gate_status: "deferred_ax".to_owned(),
            gate: gate_text(id),
            notes: format!(
                "fixture {} missing at {}; scaffold only (AX/D-5 pending)",
                fixture.file_name(),
                path.display()
            ),
        });
    }

    // Only `trivial` / `spin` adversarial fixtures run via `run_limited_pooled`
    // (no WASI imports). fs_read/http_get need guest components — mark deferred.
    if !matches!(fixture, Fixture::Trivial | Fixture::Spin) {
        return Ok(Metric {
            id: id.to_owned(),
            name: name.to_owned(),
            concurrency: Some(concurrency),
            throughput_rps: None,
            latency_ns: None,
            rss_bytes: None,
            rss_growth: None,
            gate_status: "deferred_ax".to_owned(),
            gate: gate_text(id),
            notes: format!(
                "{} guest component not yet wired for in-process load; \
                 helix-bench accepts the name for future AX runs",
                fixture.file_name()
            ),
        });
    }

    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mem = 4 * 1024 * 1024usize;
    let cfg = RuntimeConfig::new(tmp.path(), concurrency.max(1), mem);
    let engine = build_engine(&cfg).map_err(|e| e.to_string())?;
    let _ticker = EpochTicker::start(engine.clone());
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let component = Component::new(&engine, &bytes).map_err(|e| e.to_string())?;
    let budget = ResourceBudget::new(
        if matches!(fixture, Fixture::Spin) {
            10
        } else {
            60_000
        },
        60_000,
        u64::try_from(mem).unwrap_or(u64::MAX),
        1024,
        2,
        8,
        concurrency.max(1),
    );
    let pool = Arc::new(InstancePool::new());

    // Warmup (single-threaded).
    let warm_deadline = Instant::now() + warmup;
    let mut hook = NopHook;
    while Instant::now() < warm_deadline {
        let _ = run_limited_pooled(&pool, &engine, &component, &budget, &mut hook);
    }

    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));
    let samples = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let workers = concurrency.max(1) as usize;
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let pool = Arc::clone(&pool);
        let engine = engine.clone();
        let component = component.clone();
        let ok = Arc::clone(&ok);
        let err = Arc::clone(&err);
        let samples = Arc::clone(&samples);
        let stop = Arc::clone(&stop);
        handles.push(std::thread::spawn(move || {
            let mut hook = NopHook;
            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                match run_limited_pooled(&pool, &engine, &component, &budget, &mut hook) {
                    Ok(_) => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut g) = samples.lock() {
                            if g.len() < 100_000 {
                                g.push(u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX));
                            }
                        }
                    }
                    Err(_) => {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    std::thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let total_ok = ok.load(Ordering::Relaxed);
    let total_err = err.load(Ordering::Relaxed);
    let secs = duration.as_secs_f64().max(1e-9);
    let rps = total_ok as f64 / secs;
    let mut lat = samples.lock().map_err(|e| e.to_string())?;
    lat.sort_unstable();
    let latency = if lat.is_empty() {
        None
    } else {
        Some(LatencyNs {
            p50: percentile(&lat, 50),
            p90: percentile(&lat, 90),
            p99: percentile(&lat, 99),
            max: *lat.last().unwrap_or(&0),
        })
    };

    Ok(Metric {
        id: id.to_owned(),
        name: name.to_owned(),
        concurrency: Some(concurrency),
        throughput_rps: Some(rps),
        latency_ns: latency,
        rss_bytes: read_rss_bytes(),
        rss_growth: None,
        gate_status: "deferred_ax".to_owned(),
        gate: gate_text(id),
        notes: format!(
            "in-process pool load scaffold; audit_sync={audit_sync}; \
             ok={total_ok} err={total_err}; NOT reference-hardware gated \
             (AX42-1 missing, D-5/HLX-8 open)"
        ),
    })
}

fn gate_text(id: &str) -> String {
    match id {
        "BENCH-4" => {
            "Numeric gate left to D-5 / HLX-8; provisional 16000 rps @ c=64 p99≤5ms".to_owned()
        }
        "BENCH-5" => "Throughput delta vs BENCH-4 must not exceed 2×".to_owned(),
        "BENCH-6" => "informational".to_owned(),
        "BENCH-7" => "≤ 5% RSS growth after 100000 @ c=64".to_owned(),
        "BENCH-8" => "Killed within 12 ms p99 (informational)".to_owned(),
        _ => "see benchmark-protocol.md".to_owned(),
    }
}

fn percentile(sorted: &[u64], p: u8) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (usize::from(p) * (sorted.len() - 1)) / 100;
    sorted[idx]
}

fn read_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Resolve output path `bench-results/<date>-<commit>.json`.
pub fn default_out_path(date: &str, commit: &str, out_dir: &Path) -> PathBuf {
    let short = if commit.len() >= 7 {
        &commit[..7]
    } else {
        commit
    };
    out_dir.join(format!("{date}-{short}.json"))
}
