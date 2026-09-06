# Adversarial suite (HLX-37 / M5-06)

Split per ADR-009 A.4 / test-plan §8:

| Namespace | Path | CI |
|---|---|---|
| Runtime | [`runtime/`](runtime/) | `cargo test -p helix-runtime` filters listed in README |
| Gateway | [`gateway/`](gateway/) | `cargo test -p helix-gateway --test adversarial_gateway` |

Fixtures live under `tests/fixtures/adversarial/`. Exit: whole suite green; zero escapes.
