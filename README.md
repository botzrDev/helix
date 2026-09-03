# HELIX

Hardware-Enforced Logic & Interaction eXecution. A Rust-native, capability-based execution bridge.

## Workspace

| Crate | Role |
| --- | --- |
| `helix-caps` | Capability lattice |
| `helix-policy` | Policy TOML / snapshots |
| `helix-audit` | Audit log / witnesses |
| `helix-runtime` | Wasmtime sandbox |
| `helix-gateway` | axum JSON-RPC gateway |
| `helix-sdk` | Author-facing SDK |
| `helix-ctl` | Operator CLI |

Empty crates on purpose: HLX-5 is workspace + lints + CI only.

Tickets live in Linear (HELIX / Helix-Dev).

ADR-001, 002, 003, 005, 006 are amended; see ADR-008 Part G and ADR-009 Part G before relying on any decision in them.

## Documentation

Companion set to `HELIX_PRD_v2.md`. Read in this order.

| Document | Purpose |
|---|---|
| `adr/ADR-001` to `ADR-007` | The irreversible decisions and why the alternatives were rejected (companion docs) |
| `adr/ADR-008`, `adr/ADR-009` | Audit resolution and in-process delegation; Part G of each is the amendment index (companion docs) |
| [`interfaces/state-machine.md`](interfaces/state-machine.md) | Authoritative invocation table; every later ticket cites its cells |
| [`interfaces/audit-record.md`](interfaces/audit-record.md) | Deterministic CBOR record, framing, header, caps side files |
| [`interfaces/delegate.md`](interfaces/delegate.md) | `helix:delegate/invoke` identity, bounds, errors, audit, semaphore ownership |
| [`interfaces/helix-caps-api.rs`](interfaces/helix-caps-api.rs) | `CapabilitySet` contract the M1 crate implements. Spec sketch, not a workspace member |
| [`wit/helix-tool.wit`](wit/helix-tool.wit) | The only world a tool may target |
| [`interfaces/gateway-protocol.md`](interfaces/gateway-protocol.md) | JSON-RPC methods, headers, error codes, the internal `Request` seam |
| `policy-format.md` | Operator-facing policy TOML, validation rules, reload semantics (companion docs) |
| `test-plan.md` | Stable test IDs per crate, adversarial suite, static gates (companion docs) |
| `milestone-plan.md` | Crate build order, tickets sized for one bare prompt each (companion docs) |
| `benchmark-protocol.md` | Reference hardware, harness, gated numbers (companion docs) |
| `runbook.md` | Deployment, config, registration, audit handling, alerts, incidents (companion docs) |
| `tool-author-guide.md` | External-facing: build, test, and ship a tool (companion docs) |
| `security-checklist.md` | Threat model rows mapped to code paths and tests; release gate (companion docs) |

Open items that need a human decision before M1 starts (ADR-008/009 Part H):

1. Reference hardware for benchmarks (benchmark-protocol section 1).
2. Which OAuth issuer will be used, and confirmation it supports EdDSA and `cnf.jkt` (and mints `sub` as the JWK thumbprint).
3. Audit retention period and off-host witness-sink destination.
4. Whether `wasi:http` outbound is P0 or slips to P1.
5. The pinned BENCH-4 number.

## WIT

`wit/helix-tool.wit` is the `helix:tool@1.0.0` world, including the ADR-009 A.2 `delegate` host import. Host implementation of `delegate` is M4-08; tools may import it now.

WASI Preview 2 WIT (`wasi:cli@0.2.0`, `wasi:http@0.2.0`, and their deps) is vendored under `wit/deps/` from the upstream v0.2.0 tags.

Hello-world fixture is **not** a workspace member. `cargo-component` 0.21 compiles it via `wasm32-wasip1` and wraps a WASI P2 component:

```
cargo component build --release --manifest-path tests/fixtures/hello-world/Cargo.toml
```
