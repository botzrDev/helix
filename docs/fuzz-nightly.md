# Nightly fuzz and release gate (HLX-43 / M7-04)

## What runs

| Schedule | Workflow | Targets | Duration |
|---|---|---|---|
| PR / push CI | `CI` (`ci.yml`) `gw8` / `gw9` / `gw10` smokes | `envelope`, `dpop_proof`, `payload_validator` | 30s each |
| Nightly 05:00 UTC + `workflow_dispatch` | `Nightly fuzz` (`nightly-fuzz.yml`) | same | **4 hours** each (`-max_total_time=14400`) |

PR smokes stay short on purpose. Full GW-8 / GW-9 / GW-10 duration is schedule-only.

## Corpus persistence

- Restored each night via `actions/cache` (`fuzz-corpus-<target>-*`).
- Uploaded as artifacts `fuzz-corpus-<target>` (30-day retention) so a cold cache can be reseeded manually.

## Crashes → issues

On a non-zero fuzz exit the job:

1. Uploads `fuzz/artifacts/<target>/` as `fuzz-crash-<target>-<run_id>`.
2. Opens (or comments on) a GitHub issue titled `[fuzz] nightly crash: <target>` with label **`gateway`**.

### Linear mirror

GitHub Actions does not assume a Linear API token. Mirror `gateway`-labeled fuzz issues into Linear (HELIX / Helix-Dev) and link the GH issue. Optional later: repository secret `LINEAR_API_KEY` plus a step that creates the Linear issue automatically.

## E2 — seven consecutive clean nights

Security checklist row **E2** requires ≥ 7 consecutive nights with no new crashes. The counter:

- Lives in `fuzz-status/clean-nights.json` (bootstrap copy in-tree).
- Is updated by the nightly `consolidate` job and force-pushed to the dedicated **`fuzz-status`** branch (avoids noisy commits on `main`).
- **Resets to 0** if any matrix target fails that night.
- Same UTC calendar day is not double-counted.

### How release tags check the counter

1. Cut a `v*` tag (or run **Release fuzz gate** manually).
2. Workflow `release-fuzz-gate.yml` loads `clean-nights.json` from `origin/fuzz-status` (fallback: in-tree bootstrap).
3. Runs `scripts/fuzz-clean-nights.sh check`, which fails unless `consecutive_clean_nights >= required_for_release` (7).

**This PR only wires the machinery.** Exit criterion “job green for seven consecutive nights” is **not** claimed here; the counter starts at 0 and the release gate correctly fails until real nights accumulate on `main`.

## Local helpers

```bash
# Short local smoke (same as CI)
cargo +nightly fuzz run envelope -- -max_total_time=30

# Nightly-shaped run (override duration)
./scripts/fuzz-nightly-run.sh envelope 60

# Inspect / enforce E2 counter
./scripts/fuzz-clean-nights.sh read
./scripts/fuzz-clean-nights.sh check
```
