//! `helix-bench` — end-to-end load scaffolding + result compare (HLX-40 / M7-01).
//!
//! **Holes:** AX42-1 reference hardware does not exist yet (HLX-7/8 parked).
//! BENCH-4/5 numeric gates are owned by D-5 / HLX-8 and are **not** claimed
//! green by this binary. Results are marked `deferred_ax`.

#![forbid(unsafe_code)]

mod compare;
mod load;
mod results;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use crate::load::{default_out_path, run_scaffold, Fixture};
use crate::results::{detect_hardware, BenchResults, Metric};

#[derive(Debug, Parser)]
#[command(
    name = "helix-bench",
    about = "HELIX end-to-end bench harness (AX gates deferred)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a single fixture load (scaffold).
    Run {
        /// Fixture: `trivial` | `fs_read` | `http_get` | `spin`
        #[arg(long, default_value = "trivial")]
        fixture: String,
        /// In-flight concurrency `c`.
        #[arg(long, default_value_t = 8)]
        concurrency: u32,
        /// Measured duration seconds.
        #[arg(long, default_value_t = 5)]
        duration: u64,
        /// Warmup seconds.
        #[arg(long, default_value_t = 1)]
        warmup: u64,
        /// Audit sync on (notes only until gateway e2e lands on AX).
        #[arg(long, default_value_t = true)]
        audit_sync: bool,
        /// Output JSON path (default `bench-results/<date>-<commit>.json`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Metric id label (default `BENCH-4`).
        #[arg(long, default_value = "BENCH-4")]
        id: String,
    },
    /// Scaffold BENCH-4 (audit sync on) at c=8,64,256 — short durations by default.
    Bench4 {
        #[arg(long, default_value_t = 3)]
        duration: u64,
        #[arg(long, default_value_t = 1)]
        warmup: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Scaffold BENCH-5 (audit sync off) — same shape as Bench4.
    Bench5 {
        #[arg(long, default_value_t = 3)]
        duration: u64,
        #[arg(long, default_value_t = 1)]
        warmup: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Scaffold BENCH-6 informational `fs_read` + `http_get` at c=8.
    Bench6 {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Scaffold BENCH-7 RSS growth (reduced iter count unless `--full`).
    Bench7 {
        #[arg(long, default_value_t = false)]
        full: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Scaffold BENCH-8 preempt kill latency with `spin.wasm`.
    Bench8 {
        #[arg(long, default_value_t = 3)]
        duration: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print deltas between two result JSON files.
    Compare { a: PathBuf, b: PathBuf },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Run {
            fixture,
            concurrency,
            duration,
            warmup,
            audit_sync,
            out,
            id,
        } => cmd_run(
            &fixture,
            concurrency,
            duration,
            warmup,
            audit_sync,
            out,
            &id,
        ),
        Commands::Bench4 {
            duration,
            warmup,
            out,
        } => cmd_multi("BENCH-4", true, duration, warmup, out),
        Commands::Bench5 {
            duration,
            warmup,
            out,
        } => cmd_multi("BENCH-5", false, duration, warmup, out),
        Commands::Bench6 { out } => cmd_bench6(out),
        Commands::Bench7 { full, out } => cmd_bench7(full, out),
        Commands::Bench8 { duration, out } => cmd_bench8(duration, out),
        Commands::Compare { a, b } => match compare::compare(&a, &b) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("compare error: {e}");
                1
            }
        },
    };
    std::process::exit(code);
}

fn holes() -> Vec<String> {
    vec![
        "AX42-1 / LTD reference hardware does not exist yet (HLX-1/D-2 pinned on paper only)."
            .to_owned(),
        "HLX-7 (M0-03 walking skeleton) and HLX-8 (D-5 BENCH-4 gate) are parked.".to_owned(),
        "Exit criterion 'BENCH-1..5 gated green on reference hardware' is NOT met.".to_owned(),
        "bench-results/hardware.json fio fdatasync latency and Granted-record size pending AX."
            .to_owned(),
        "BENCH-4/5 full gateway+group-commit audit path requires AX host + D-5 pin.".to_owned(),
    ]
}

fn git_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn utc_date() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            format!("epoch-{secs}")
        })
}

fn write_results(out: &Path, metrics: Vec<Metric>) -> Result<(), String> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let commit = git_commit();
    let commit_short = if commit.len() >= 7 {
        commit[..7].to_owned()
    } else {
        commit.clone()
    };
    let doc = BenchResults {
        schema_version: BenchResults::SCHEMA_VERSION,
        date: utc_date(),
        commit,
        commit_short,
        hardware: detect_hardware(),
        metrics,
        holes: holes(),
    };
    let raw = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(out, raw).map_err(|e| e.to_string())?;
    println!("wrote {}", out.display());
    Ok(())
}

fn default_out(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bench-results");
    default_out_path(&utc_date(), &git_commit(), &root)
}

fn finish(out: Option<PathBuf>, metrics: Vec<Metric>) -> i32 {
    match write_results(&default_out(out), metrics) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn cmd_run(
    fixture: &str,
    concurrency: u32,
    duration: u64,
    warmup: u64,
    audit_sync: bool,
    out: Option<PathBuf>,
    id: &str,
) -> i32 {
    let fix = match Fixture::parse(fixture) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    match run_scaffold(
        id,
        &format!("{fixture} c={concurrency}"),
        fix,
        concurrency,
        Duration::from_secs(duration),
        Duration::from_secs(warmup),
        audit_sync,
    ) {
        Ok(m) => finish(out, vec![m]),
        Err(e) => {
            eprintln!("run error: {e}");
            1
        }
    }
}

fn cmd_multi(id: &str, audit_sync: bool, duration: u64, warmup: u64, out: Option<PathBuf>) -> i32 {
    let sync_label = if audit_sync { "on" } else { "off" };
    let mut metrics = Vec::new();
    for c in [8_u32, 64, 256] {
        match run_scaffold(
            id,
            &format!("e2e trivial audit_sync={sync_label} c={c}"),
            Fixture::Trivial,
            c,
            Duration::from_secs(duration),
            Duration::from_secs(warmup),
            audit_sync,
        ) {
            Ok(m) => metrics.push(m),
            Err(e) => {
                eprintln!("{id} c={c}: {e}");
                return 1;
            }
        }
    }
    finish(out, metrics)
}

fn cmd_bench6(out: Option<PathBuf>) -> i32 {
    let mut metrics = Vec::new();
    for (fix, label) in [(Fixture::FsRead, "fs_read"), (Fixture::HttpGet, "http_get")] {
        match run_scaffold(
            "BENCH-6",
            &format!("{label} c=8"),
            fix,
            8,
            Duration::from_secs(1),
            Duration::from_secs(0),
            true,
        ) {
            Ok(m) => metrics.push(m),
            Err(e) => {
                eprintln!("BENCH-6 {label}: {e}");
                return 1;
            }
        }
    }
    finish(out, metrics)
}

fn cmd_bench7(full: bool, out: Option<PathBuf>) -> i32 {
    let target = if full { 100_000_u64 } else { 1_000 };
    let concurrency = 64_u32;
    match run_scaffold(
        "BENCH-7",
        "rss scaffold pulse",
        Fixture::Trivial,
        8,
        Duration::from_secs(1),
        Duration::from_secs(0),
        false,
    ) {
        Ok(mut pulse) => {
            "BENCH-7".clone_into(&mut pulse.id);
            pulse.name = format!("RSS after {target} invocations at c={concurrency}");
            "≤ 5% RSS growth".clone_into(&mut pulse.gate);
            "deferred_ax".clone_into(&mut pulse.gate_status);
            pulse.notes = format!(
                "scaffold only: run `helix-bench run --fixture trivial --concurrency {concurrency}` \
                 on AX for real RSS; target_iters={target}; full={full}"
            );
            finish(out, vec![pulse])
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn cmd_bench8(duration: u64, out: Option<PathBuf>) -> i32 {
    match run_scaffold(
        "BENCH-8",
        "preempt kill spin.wasm preempt_ticks=10",
        Fixture::Spin,
        1,
        Duration::from_secs(duration),
        Duration::from_secs(0),
        false,
    ) {
        Ok(m) => finish(out, vec![m]),
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}
