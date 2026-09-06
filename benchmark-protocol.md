# Benchmark Protocol

Numbers in the PRD (Section 7) are estimates until this protocol replaces them. Every figure published in the README or a status update comes from this harness, on the reference hardware, with the commit hash attached.


## 0. Status (HLX-40)

Reference host **AX42-1 is not provisioned**. HLX-7 / HLX-8 are parked. This repository ships the Criterion + `helix-bench` harness, result JSON, and CI smoke for BENCH-1..3. **Do not claim BENCH-4/5 gated green on reference hardware.** D-5 numeric pin for BENCH-4 remains open. See `bench-results/hardware.json` and `benches/README.md`.


## 1. Reference hardware

Recorded and pinned (D-2 / HLX-1, decided 2026-09-03). Change only via ADR.

- Machine: Hetzner AX42-1
- CPU: AMD Ryzen 7 PRO 8700GE, SMT off (8 threads), fixed frequency governor (`performance`), C-states limited to C1
- Memory: 64 GiB DDR5 (**named deviation** from the earlier 32 GiB ask)
- Storage: 2×512 GB NVMe RAID1; `fdatasync` latency measured with `fio --rw=write --fsync=1 --bs=4k` and recorded in `bench-results/hardware.json`
- OS: Ubuntu 24.04; kernel, Rust toolchain, and wasmtime versions recorded in the same file at M0-03

Not local `botzrDev`. Not AWS `c6id.4xlarge`.

`c` is total in-flight requests **per host**, not per core.

## 2. Harness

`benches/` uses Criterion for in-process microbenchmarks and a standalone `helix-bench` binary for end-to-end load. The load generator runs on a separate machine or, if colocated, is pinned to cores the gateway does not use.

Fixtures:
- `trivial.wasm`: echoes a 1 KB input. Measures overhead, not tool work.
- `fs_read.wasm`: reads a 64 KiB granted file and returns its length.
- `http_get.wasm`: GETs a local mock server and returns status.

## 3. Benchmarks

| ID | What | Method | Gate |
|---|---|---|---|
| BENCH-1 | `is_subset_of` on sets with 32 files, dirs, and 8 hosts | Criterion, 10 000 iterations | < 500 ns median; regression > 20 % fails CI |
| BENCH-2 | Ed25519 JWT plus DPoP verification | Criterion | < 150 µs median |
| BENCH-3 | Pooled instantiate plus `invoke` of `trivial.wasm`, no audit sync | Criterion, single thread | < 50 µs median |
| BENCH-4 | End-to-end `helix.invoke` of `trivial.wasm` on the reference host, group-committed audit sync on, at **c = 8, 64, 256** (in-flight per host) | `helix-bench`, 60 s warm, 300 s measured | **Numeric gate left to D-5 / HLX-8** (not yet measured). Provisional design target the walking skeleton tests: 16 000 req/s per host at c=64 with p99 ≤ 5 ms. Express the pinned gate as a multiple of measured `fio` sync latency once known. |
| BENCH-5 | Same as BENCH-4 with audit sync off | **Gated**: throughput difference between BENCH-4 and BENCH-5 must not exceed **2×** |
| BENCH-6 | `fs_read.wasm` and `http_get.wasm` at c=8 | informational |
| BENCH-7 | Memory: RSS after 100 000 invocations at c=64 vs after warmup | ≤ 5 % growth |
| BENCH-8 | Preempt kill latency: `spin.wasm` with `preempt_ticks = 10` | Killed within 12 ms p99 (informational until M7-01; RT-5 covers functional preempt) |

Record size: a `Granted` audit record is ~200 bytes (deterministic CBOR). Record that figure beside the `fio` result in `bench-results/hardware.json` so group-commit batch arithmetic is checkable.

## 4. Reporting

Each run writes `bench-results/<date>-<commit>.json` with hardware fingerprint, every metric, and p50/p90/p99/max. `helix-bench compare <a> <b>` prints deltas. CI gates on BENCH-1 through BENCH-5 against the last tagged release, not the previous commit, to avoid drift by small steps.

## 5. What not to measure yet

Do not benchmark tool bodies, policy reload, or exporter throughput in v1. They are cold paths.
