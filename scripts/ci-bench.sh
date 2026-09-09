#!/usr/bin/env bash
# CI microbench smoke / optional regression vs last tag (HLX-40).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Default: run absolute gates with CI slack (not AX-strict).
unset HELIX_BENCH_ENFORCE_GATES || true

echo "::group::helix-benches Criterion smoke (BENCH-1..3)"
cargo bench -p helix-benches -- --warm-up-time 1 --measurement-time 2 --sample-size 25
echo "::endgroup::"

echo "::group::helix-bench binary smoke"
cargo build -p helix-bench --release
BIN="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/helix-bench"
tmpdir="$(mktemp -d)"
"$BIN" run --fixture trivial --concurrency 2 --duration 1 --warmup 0 \
  --out "${tmpdir}/smoke.json"
"$BIN" bench6 --out "${tmpdir}/bench6.json"
"$BIN" compare "${tmpdir}/smoke.json" "${tmpdir}/bench6.json" || true
echo "::endgroup::"

last_tag="$(git describe --tags --abbrev=0 2>/dev/null || true)"
if [[ -n "${last_tag}" ]]; then
  echo "::group::Criterion baseline vs ${last_tag}"
  if [[ -d "${CARGO_TARGET_DIR:-target}/criterion" ]]; then
    echo "Criterion reports present (informational)."
  fi
  echo "No checked-in Criterion baselines for ${last_tag}; smoke-only (AX/D-5 pending)."
  echo "::endgroup::"
else
  echo "No git tags found; smoke that benches run (no regression baseline)."
fi

echo "HLX-40 CI bench: BENCH-1..3 ran; BENCH-4..5 NOT claimed gated on reference hardware."
