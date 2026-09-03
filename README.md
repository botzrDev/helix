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
