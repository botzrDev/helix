# Gateway adversarial namespace (HLX-37)

Implemented in `crates/helix-gateway/tests/adversarial_gateway.rs`.

| Case | Expected |
|---|---|
| Batch JSON-RPC array | `-32600` `batch_not_supported` |
| `alg: none` access token | `-32001` (closed reason) |
| Replayed DPoP proof (`jti`) | `-32001` `replay` |
| Concurrency flood (one identity) | `-32002` `concurrency` |
| `spin_invoke` / `membomb_invoke` / `flood` e2e | `-32010` / `-32012` / `-32013` within `budget.wall_clock_ms` |

Fixtures reserved under `tests/fixtures/adversarial/gateway/` for future host-side corpora.
