# HELIX microbenchmarks (Criterion)

Criterion targets for **BENCH-1..3** (`benchmark-protocol.md`). End-to-end load lives in `crates/helix-bench`.

| ID | Target | Protocol gate |
|---|---|---|
| BENCH-1 | `is_subset_of` 32 files / 32 dirs / 8 hosts | median &lt; 500 ns |
| BENCH-2 | Ed25519 JWT + DPoP verify | median &lt; 150 µs |
| BENCH-3 | pooled instantiate + `trivial.wasm` invoke | median &lt; 50 µs |

## Run

```bash
cargo bench -p helix-benches
# quick smoke (CI):
HELIX_BENCH_SKIP_GATES=1 cargo bench -p helix-benches -- --warm-up-time 1 --measurement-time 1 --sample-size 10
```

Absolute protocol gates are enforced when `HELIX_BENCH_ENFORCE_GATES=1` (reference AX42-1). On shared CI the harness applies a slack multiplier so noisy VMs do not false-fail; results are **informational** until AX exists.

## Holes (AX / D-5)

- **AX42-1 does not exist yet.** HLX-7 / HLX-8 are parked.
- Do **not** claim BENCH-4/5 gated green on reference hardware.
- D-5 pin for BENCH-4 throughput is unset; see `bench-results/hardware.json`.
