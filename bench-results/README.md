# Bench results

Files: `<YYYY-MM-DD>-<commit>.json` plus `hardware.json`.

Shape: see `helix-bench` (`schema_version`, `hardware`, `metrics[]` with p50/p90/p99/max, `holes`).

```bash
cargo run -p helix-bench -- compare bench-results/a.json bench-results/b.json
```

**AX hole:** until AX42-1 exists and D-5/HLX-8 pins BENCH-4, do not treat e2e numbers as gated. CI regresses Criterion BENCH-1..3 only (smoke, or vs last tag baseline when tags exist).
