# Gateway adversarial fixtures (M5-06 / HLX-37)

Gateway-namespace assertions live in `crates/helix-gateway/tests/adversarial_gateway.rs`
(batch envelope, `alg:none`, replayed DPoP proof, concurrency flood, kill e2e).

This directory holds optional host-side corpora; runtime-owned wasm remains under
`../runtime/` and `../`.
