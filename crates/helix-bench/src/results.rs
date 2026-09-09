//! Bench-results JSON shape (`benchmark-protocol.md` §4).

use serde::{Deserialize, Serialize};

/// Hardware fingerprint recorded beside every run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareFingerprint {
    /// Machine class (e.g. `hetzner-ax42-1`) or `unknown` / CI label.
    pub machine: String,
    /// CPU model string when known.
    pub cpu: String,
    /// Logical CPUs observed.
    pub cpus: u32,
    /// Total memory bytes when known.
    pub memory_bytes: u64,
    /// OS / kernel summary.
    pub os: String,
    /// True when this matches the pinned AX42-1 reference host.
    pub is_reference_hardware: bool,
    /// Free-form note (AX / D-5 holes).
    pub notes: String,
}

/// Latency percentiles in nanoseconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencyNs {
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub max: u64,
}

/// One benchmark metric row.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metric {
    /// Stable id (`BENCH-1` … `BENCH-8`).
    pub id: String,
    /// Human label.
    pub name: String,
    /// Concurrency / in-flight when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    /// Throughput req/s when measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throughput_rps: Option<f64>,
    /// Latency percentiles (ns).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ns: Option<LatencyNs>,
    /// RSS bytes after run (BENCH-7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_bytes: Option<u64>,
    /// RSS growth fraction vs warmup (BENCH-7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_growth: Option<f64>,
    /// `pass` / `fail` / `informational` / `deferred_ax`.
    pub gate_status: String,
    /// Protocol gate text.
    pub gate: String,
    /// Extra notes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Top-level `bench-results/<date>-<commit>.json` document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BenchResults {
    /// Schema version for `helix-bench compare`.
    pub schema_version: u32,
    /// UTC date `YYYY-MM-DD`.
    pub date: String,
    /// Full commit hash.
    pub commit: String,
    /// Short commit when available.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub commit_short: String,
    /// Hardware fingerprint.
    pub hardware: HardwareFingerprint,
    /// Metrics.
    pub metrics: Vec<Metric>,
    /// Explicit AX / D-5 hole documentation.
    #[serde(default)]
    pub holes: Vec<String>,
}

impl BenchResults {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// Detect a best-effort fingerprint on the current host.
#[must_use]
pub fn detect_hardware() -> HardwareFingerprint {
    let cpus =
        std::thread::available_parallelism().map_or(1, |n| u32::try_from(n.get()).unwrap_or(1));
    let os = std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_owned())
        .lines()
        .next()
        .unwrap_or("unknown")
        .to_owned();
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("model name\t: ").map(str::to_owned))
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let memory_bytes = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|kb| kb.parse::<u64>().ok())
                    .map(|kb| kb.saturating_mul(1024))
            })
        })
        .unwrap_or(0);
    HardwareFingerprint {
        machine: std::env::var("HELIX_BENCH_MACHINE").unwrap_or_else(|_| "unknown".to_owned()),
        cpu,
        cpus,
        memory_bytes,
        os,
        is_reference_hardware: false,
        notes: "AX42-1 not provisioned; HLX-7/8 parked; D-5 gate unset (HLX-40).".to_owned(),
    }
}
