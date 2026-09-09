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
| `helix-bench` | E2E load harness + result compare (HLX-40) |
| `helix-benches` | Criterion BENCH-1..3 (`benches/`) |

Empty crates on purpose: HLX-5 is workspace + lints + CI only.

Tickets live in Linear (HELIX / Helix-Dev).

ADR-001, 002, 003, 005, 006 are amended; see ADR-008 Part G and ADR-009 Part G before relying on any decision in them.

## Documentation

Read in this order. Interface files landed with HLX-9 (PR #3). Remaining docs land with HLX-44 (Part G amendments applied).

| Document | Purpose |
|---|---|
| [`HELIX_PRDv2.md`](HELIX_PRDv2.md) | Product requirements. Sections 3, 4, and 5.5 are superseded by `interfaces/` |
| `adr/ADR-001` to `ADR-007` | Irreversible decisions (companion / project knowledge until checked in) |
| `adr/ADR-008`, `adr/ADR-009` | Audit resolution and in-process delegation; Part G of each is the amendment index |
| [`interfaces/state-machine.md`](interfaces/state-machine.md) | Authoritative invocation table; every later ticket cites its cells. `Described` is the `helix.describe` success transition |
| [`interfaces/audit-record.md`](interfaces/audit-record.md) | Deterministic CBOR record, framing, header, caps side files |
| [`interfaces/delegate.md`](interfaces/delegate.md) | `helix:delegate/invoke` identity, bounds, errors, audit, semaphore ownership |
| [`interfaces/helix-caps-api.rs`](interfaces/helix-caps-api.rs) | `CapabilitySet` contract the M1 crate implements. Spec sketch, not a workspace member |
| [`wit/helix-tool.wit`](wit/helix-tool.wit) | The only world a tool may target |
| [`interfaces/gateway-protocol.md`](interfaces/gateway-protocol.md) | JSON-RPC methods, headers, error codes, the internal `Request` seam |
| [`policy-format.md`](policy-format.md) | Operator-facing policy TOML, validation rules 1–12, reload semantics |
| [`test-plan.md`](test-plan.md) | Stable test IDs per crate, adversarial suite, static gates |
| [`milestone-plan.md`](milestone-plan.md) | 14-week crate build order; tickets HLX-5 through HLX-43 |
| [`benchmark-protocol.md`](benchmark-protocol.md) | Reference hardware, harness, gated numbers |
| [`runbook.md`](runbook.md) | Deployment, config, registration, audit / witness handling, alerts, incidents |
| [`tool-author-guide.md`](tool-author-guide.md) | External-facing: build, test, delegate, and ship a tool |
| [`security-checklist.md`](security-checklist.md) | Threat model rows mapped to code paths and tests; release gate |
| [`docs/fuzz-nightly.md`](docs/fuzz-nightly.md) | Nightly 4h fuzz (GW-8..10), corpus, crash issues, E2 seven-clean-nights gate (HLX-43) |

Cycle 1 facts (decided 2026-09-03) are written into the matching docs above. Linear HLX-1 through HLX-4 stay open until those tickets are closed deliberately:

1. **D-2 / HLX-1** — reference hardware: Hetzner AX42-1 (see `benchmark-protocol.md`).
2. **D-3 / HLX-3** — OAuth issuer: self-hosted Keycloak, EdDSA-only, `sub` = `cnf.jkt`; URL `https://<host>/realms/helix` (see `runbook.md`).
3. **D-4 / HLX-4** — 90 days local audit retention; witness sink Hetzner Object Storage with Object Lock + SigV4 (see `runbook.md`).
4. **D-1 / HLX-2** — `wasi:http` outbound is P0; M4-07 stays in the 14-week plan (see `HELIX_PRDv2.md` §6.2).
5. **D-5 / HLX-8** — pinned BENCH-4 gate value (still open; left to walking-skeleton measurement).

## WIT

`wit/helix-tool.wit` is the `helix:tool@1.0.0` world, including the ADR-009 A.2 `delegate` host import. Host implementation of `delegate` is M4-08; tools may import it now.

WASI Preview 2 WIT (`wasi:cli@0.2.0`, `wasi:http@0.2.0`, and their deps) is vendored under `wit/deps/` from the upstream v0.2.0 tags.

Hello-world fixture is **not** a workspace member. `cargo-component` 0.21 compiles it via `wasm32-wasip1` and wraps a WASI P2 component:

```
cargo component build --release --manifest-path tests/fixtures/hello-world/Cargo.toml
```
