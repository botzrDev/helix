//! `helix-bench compare <a> <b>`.

use std::collections::BTreeMap;
use std::path::Path;

use crate::results::BenchResults;

/// Print human-readable deltas between two result files.
///
/// # Errors
///
/// I/O or JSON parse failures.
pub fn compare(a_path: &Path, b_path: &Path) -> Result<(), String> {
    let a: BenchResults = load(a_path)?;
    let b: BenchResults = load(b_path)?;
    println!(
        "compare {} ({}) -> {} ({})",
        a.commit_short_or(),
        a.date,
        b.commit_short_or(),
        b.date
    );
    println!(
        "hardware a: {} ref={} | b: {} ref={}",
        a.hardware.machine,
        a.hardware.is_reference_hardware,
        b.hardware.machine,
        b.hardware.is_reference_hardware
    );
    if !a.hardware.is_reference_hardware || !b.hardware.is_reference_hardware {
        println!(
            "note: one or both runs are NOT on AX42-1 reference hardware; \
             do not treat BENCH-4/5 deltas as gated."
        );
    }

    let map_a: BTreeMap<&str, _> = a.metrics.iter().map(|m| (m.id.as_str(), m)).collect();
    let map_b: BTreeMap<&str, _> = b.metrics.iter().map(|m| (m.id.as_str(), m)).collect();
    let mut ids: Vec<&str> = map_a.keys().chain(map_b.keys()).copied().collect();
    ids.sort_unstable();
    ids.dedup();

    for id in ids {
        let ma = map_a.get(id);
        let mb = map_b.get(id);
        match (ma, mb) {
            (Some(x), Some(y)) => {
                print_metric_delta(id, x, y);
            }
            (Some(_), None) => println!("{id}: present only in a"),
            (None, Some(_)) => println!("{id}: present only in b"),
            (None, None) => {}
        }
    }
    Ok(())
}

fn load(path: &Path) -> Result<BenchResults, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

fn print_metric_delta(id: &str, a: &crate::results::Metric, b: &crate::results::Metric) {
    print!("{id} ({}) ", a.name);
    if let (Some(ra), Some(rb)) = (a.throughput_rps, b.throughput_rps) {
        let delta = rb - ra;
        let pct = if ra.abs() > f64::EPSILON {
            100.0 * delta / ra
        } else {
            0.0
        };
        print!("rps {ra:.1} -> {rb:.1} ({delta:+.1}, {pct:+.1}%) ");
    }
    if let (Some(la), Some(lb)) = (&a.latency_ns, &b.latency_ns) {
        print!(
            "p50 {}ns -> {}ns ({:+}ns) p99 {}ns -> {}ns ({:+}ns) ",
            la.p50,
            lb.p50,
            i64::try_from(lb.p50).unwrap_or(0) - i64::try_from(la.p50).unwrap_or(0),
            la.p99,
            lb.p99,
            i64::try_from(lb.p99).unwrap_or(0) - i64::try_from(la.p99).unwrap_or(0),
        );
    }
    println!("gate {} -> {}", a.gate_status, b.gate_status);
}

trait CommitShort {
    fn commit_short_or(&self) -> &str;
}

impl CommitShort for BenchResults {
    fn commit_short_or(&self) -> &str {
        if self.commit_short.is_empty() {
            &self.commit
        } else {
            &self.commit_short
        }
    }
}
