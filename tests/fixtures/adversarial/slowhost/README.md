# slowhost.wasm

Adversarial tarpit client: issues an HTTP GET to a host that accepts the
connection and never responds.

**Expected:** `Killed(WallClock)` when `wall_clock_ms` elapses.

**HLX-30:** Covered by `rt8_real_http_tarpit_killed_wall_clock` and
`slowhost_wasi_http_send_killed_wall_clock` in `crates/helix-runtime/tests/rt8_http.rs`
(real TCP tarpit + cancel-aware `send_request_with_grants`).
