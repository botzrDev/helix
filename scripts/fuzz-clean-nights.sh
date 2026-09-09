#!/usr/bin/env bash
# HLX-43 / security-checklist E2: consecutive clean-night counter.
#
# Usage:
#   fuzz-clean-nights.sh read [path]
#   fuzz-clean-nights.sh check [path]          # exit 0 iff count >= required
#   fuzz-clean-nights.sh record-clean [path]   # increment (same UTC day = no-op)
#   fuzz-clean-nights.sh record-crash [path]   # reset to 0
#
# Status file default: fuzz-status/clean-nights.json (repo or fuzz-status branch).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CMD="${1:?usage: fuzz-clean-nights.sh <read|check|record-clean|record-crash> [path]}"
STATUS_PATH="${2:-${ROOT}/fuzz-status/clean-nights.json}"

require_jq() {
  command -v jq >/dev/null 2>&1 || {
    echo "jq is required" >&2
    exit 127
  }
}

ensure_file() {
  if [[ ! -f "${STATUS_PATH}" ]]; then
    mkdir -p "$(dirname "${STATUS_PATH}")"
    cat > "${STATUS_PATH}" <<'JSON'
{
  "schema_version": 1,
  "consecutive_clean_nights": 0,
  "required_for_release": 7,
  "last_night_utc": null,
  "last_status": "never_run",
  "last_run_url": null,
  "targets": ["envelope", "dpop_proof", "payload_validator"],
  "notes": "HLX-43 / E2 wiring. Counter resets on crash."
}
JSON
  fi
}

today_utc() {
  date -u +%Y-%m-%d
}

read_status() {
  require_jq
  ensure_file
  jq -c '{
    consecutive_clean_nights,
    required_for_release,
    last_night_utc,
    last_status,
    last_run_url,
    remaining: ([.required_for_release - .consecutive_clean_nights, 0] | max)
  }' "${STATUS_PATH}"
}

check_gate() {
  require_jq
  ensure_file
  local count required
  count="$(jq -r '.consecutive_clean_nights' "${STATUS_PATH}")"
  required="$(jq -r '.required_for_release' "${STATUS_PATH}")"
  echo "E2 clean nights: ${count} / ${required} (file=${STATUS_PATH})"
  if [[ "${count}" -ge "${required}" ]]; then
    echo "release fuzz gate PASS"
    return 0
  fi
  echo "release fuzz gate FAIL: need ${required} consecutive clean nights (have ${count})" >&2
  echo "HLX-43: do not cut a release tag until nightly fuzz has been green for seven nights." >&2
  return 1
}

record_clean() {
  require_jq
  ensure_file
  local today prev count run_url
  today="$(today_utc)"
  prev="$(jq -r '.last_night_utc // empty' "${STATUS_PATH}")"
  count="$(jq -r '.consecutive_clean_nights' "${STATUS_PATH}")"
  run_url="${GITHUB_RUN_URL:-}"

  if [[ "${prev}" == "${today}" ]]; then
    echo "already recorded clean for ${today}; leaving count=${count}"
    return 0
  fi

  count=$((count + 1))
  jq --arg day "${today}" \
     --arg url "${run_url}" \
     --argjson n "${count}" \
     '.consecutive_clean_nights = $n
      | .last_night_utc = $day
      | .last_status = "clean"
      | .last_run_url = (if $url == "" then .last_run_url else $url end)' \
     "${STATUS_PATH}" > "${STATUS_PATH}.tmp"
  mv "${STATUS_PATH}.tmp" "${STATUS_PATH}"
  echo "recorded clean night ${today}; consecutive_clean_nights=${count}"
}

record_crash() {
  require_jq
  ensure_file
  local today run_url
  today="$(today_utc)"
  run_url="${GITHUB_RUN_URL:-}"
  jq --arg day "${today}" \
     --arg url "${run_url}" \
     '.consecutive_clean_nights = 0
      | .last_night_utc = $day
      | .last_status = "crash"
      | .last_run_url = (if $url == "" then .last_run_url else $url end)' \
     "${STATUS_PATH}" > "${STATUS_PATH}.tmp"
  mv "${STATUS_PATH}.tmp" "${STATUS_PATH}"
  echo "recorded crash/failure for ${today}; consecutive_clean_nights reset to 0"
}

case "${CMD}" in
  read) read_status ;;
  check) check_gate ;;
  record-clean) record_clean ;;
  record-crash) record_crash ;;
  *)
    echo "usage: fuzz-clean-nights.sh <read|check|record-clean|record-crash> [path]" >&2
    exit 2
    ;;
esac
