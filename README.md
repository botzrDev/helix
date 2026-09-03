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

## WIT

`wit/helix-tool.wit` is the `helix:tool@1.0.0` world, including the ADR-009 A.2 `delegate` host import. Host implementation of `delegate` is M4-08; tools may import it now.

WASI Preview 2 WIT (`wasi:cli@0.2.0`, `wasi:http@0.2.0`, and their deps) is vendored under `wit/deps/` from the upstream v0.2.0 tags.

Hello-world fixture is **not** a workspace member. `cargo-component` 0.21 compiles it via `wasm32-wasip1` and wraps a WASI P2 component:

```
cargo component build --release --manifest-path tests/fixtures/hello-world/Cargo.toml
```
