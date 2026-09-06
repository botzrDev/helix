#!/usr/bin/env bash
# HLX-43 / M7-04: run one gateway fuzz target for the nightly duration.
# Usage: fuzz-nightly-run.sh <target> [max_total_time_secs]
# Env:
#   FUZZ_MAX_TOTAL_TIME — override duration (default 14400 = 4h)
#   FUZZ_JOBS           — libFuzzer -jobs (default 1)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?usage: fuzz-nightly-run.sh <envelope|dpop_proof|payload_validator> [secs]}"
MAX_TOTAL_TIME="${2:-${FUZZ_MAX_TOTAL_TIME:-14400}}"
JOBS="${FUZZ_JOBS:-1}"

case "${TARGET}" in
  envelope|dpop_proof|payload_validator) ;;
  *)
    echo "unknown fuzz target: ${TARGET}" >&2
    exit 2
    ;;
esac

GW="${ROOT}/crates/helix-gateway"
CORPUS="${GW}/fuzz/corpus/${TARGET}"
ARTIFACTS="${GW}/fuzz/artifacts/${TARGET}"
mkdir -p "${CORPUS}" "${ARTIFACTS}"

echo "::group::cargo-fuzz ${TARGET} (-max_total_time=${MAX_TOTAL_TIME})"
cd "${GW}"
set +e
cargo +nightly fuzz run "${TARGET}" -- \
  -max_total_time="${MAX_TOTAL_TIME}" \
  -jobs="${JOBS}" \
  -artifact_prefix="${ARTIFACTS}/"
rc=$?
set -e
echo "::endgroup::"

if [[ "${rc}" -ne 0 ]]; then
  echo "fuzz target ${TARGET} exited ${rc}"
  echo "artifacts:"
  find "${ARTIFACTS}" -type f 2>/dev/null | head -50 || true
  exit "${rc}"
fi

echo "fuzz target ${TARGET} completed cleanly (${MAX_TOTAL_TIME}s budget)"
