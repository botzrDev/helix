# Milestone Plan

Build order follows the dependency direction. A milestone exits when its listed test IDs pass in CI on `main`. Each milestone is broken into tickets sized for one bare prompt to the dev session. Ticket IDs below are Linear identifiers (HELIX / Helix-Dev).

Suggested workspace layout:

```
helix/
  Cargo.toml            workspace, resolver = "2", [workspace.lints]
  crates/
    helix-caps/
    helix-policy/
    helix-runtime/
    helix-gateway/
    helix-audit/
    helix-sdk/
    helix-ctl/          thin CLI binary, main.rs under 100 lines
  wit/helix-tool.wit
  interfaces/
  tests/adversarial/{runtime,gateway}/
  benches/
```

Pinned versions at kickoff: wasmtime 36.x, wasmtime-wasi 36.x, wit-bindgen 0.44.x, tokio 1.x, axum 0.8.x, cap-std 3.x. Bump only via a ticket.

Sequence (ADR-008 F.3): M0 skeleton (2 wk), M1 caps (1 wk), M2 policy (1 wk), M3 audit (1.5 wk), M4 runtime (4 wk), M5 gateway (2 wk), M6 sdk (1 wk), M7 hardening (1.5 wk). **Total 14 weeks.**

Owner decisions HLX-1 through HLX-4 and HLX-8 (D-1 through D-5) sit alongside M0 and are not restated as build tickets here.

## M0: Skeleton + interfaces (2 weeks)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M0-01 | HLX-5 | Workspace `Cargo.toml`, seven crates, shared lints, CI static gates | ST-1 through ST-6 on empty crates |
| M0-02 | HLX-6 | Check in `wit/helix-tool.wit` with the `delegate` interface; hello-world fixture | Fixture builds |
| M0-03 | HLX-7 | Walking skeleton: one binary, hardcoded grant, real EdDSA + group-committed audit; pin BENCH-4/5 | BENCH-4 and BENCH-5 numbers recorded; feeds HLX-8 |
| M0-04 | HLX-9 | Interface docs: `state-machine.md`, `audit-record.md`, `delegate.md`, `helix-caps-api.rs` rewrite | Docs land; `Described` defined |

Docs companion (this ticket's family): HLX-44 propagates ADR-008/009 Part G into the remaining documents so later "as amended" references resolve.

## M1: `helix-caps` (1 week)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M1-01 | HLX-10 | Types: private fields, `try_from` deserialization, `DirGrant`, `ResourceBudget`, `Interner`, `Method` enum | CAPS-8, CAPS-9 |
| M1-02 | HLX-11 | Lattice operations with `dirs` and Interner ids | CAPS-1 through CAPS-7, CAPS-10 |
| M1-03 | HLX-12 | Miri in CI for this crate; docs.rs-quality rustdoc | ST-5 |
| M1-04 | HLX-13 | CAPS-11 through CAPS-15 | CAPS-11 through CAPS-15 |

## M2: `helix-policy` (1 week)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M2-01 | HLX-14 | TOML parsing, rules 1 through 12, pure structural pass + host resolve pass | POL-1, POL-2, POL-7 |
| M2-02 | HLX-15 | `ArcSwap` snapshot holder, `PolicyGuard` threaded per request tree, lookup, reload, new POL-5 | POL-3, POL-4, POL-5 |
| M2-03 | HLX-16 | Delegation composition: authority attenuation, resource composition, depth and fan-out | POL-6 |
| M2-04 | HLX-17 | `helix-ctl policy check` (structural / host modes) and `policy explain` | manual |

## M3: `helix-audit` (1.5 weeks)

Audit builds before the gateway (ADR-008 F.3).

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M3-01 | HLX-18 | `AuditRecord` in deterministic CBOR, hash chain, group-commit writer task | AUD-1, AUD-2, AUD-5, AUD-8 |
| M3-02 | HLX-19 | Log rotation with header carry-forward; `helix-ctl audit verify`, `dump`, `caps` | AUD-3 |
| M3-03 | HLX-20 | OTel tail exporter: one span per invocation, one event per transition | AUD-4 |
| M3-04 | HLX-21 | Caps side-file store under `audit/caps/` | AUD-5 side-file half |

**M3-04 slot note:** the former M5-04 "wire audit into gateway transitions" cannot precede the gateway now that audit builds first; that work is folded into M5-05 (HLX-36). This slot carries the content-addressed CapabilitySet CBOR side-file store from ADR-008 D.2 / ADR-009 D.1.

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M3-05 | HLX-22 | Witness emission, S3-style witness sink contract, `witness-receive` and `verify --witnesses` | AUD-9, AUD-10 |
| M3-06 | HLX-23 | Fail-closed audit paths: writer error surface, `-32030`, consecutive-error fatality, health | AUD-6, AUD-7 |

## M4: `helix-runtime` (4 weeks)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M4-01 | HLX-24 | Engine config, artifact cache, `InstancePre` per digest, pooling allocator | RT-11 |
| M4-02 | HLX-25 | `link(&CapabilitySet) -> Linker`: bit-driven WASI binding, fail closed | RT-1, RT-12 |
| M4-03 | HLX-26 | Filesystem grants via cap-std: `O_NOFOLLOW`, `FileGrant` and `DirGrant` preopens | RT-2, RT-3, RT-4 |
| M4-04 | HLX-27 | `ResourceLimiter`, `preempt_ticks` deadline on the pinned 1 ms ticker, output-bounded writer, terminal-record drop guard | RT-5, RT-6, RT-7 |
| M4-05 | HLX-28 | `CancellationToken` through every host function, wall-clock timer, `spawn_cancellable`, `JoinSet` for children | RT-8, RT-9 |
| M4-06 | HLX-29 | Soak test and pool accounting: 10,000 sequential invocations, zero leak | RT-10 |
| M4-07 | HLX-30 | `wasi:http` outbound with `HostGrant` authority and method enforcement | covered by RT-8 and GW-7; P0 (D-1 locked) |
| M4-08 | HLX-31 | `helix:delegate` host import: in-process delegation under the parent identity, bounds, RT-13 through RT-16 | RT-13 through RT-16 |

## M5: `helix-gateway` (2 weeks)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M5-01 | HLX-32 | axum server, JSON-RPC envelope parsing, internal `Request` seam, envelope fuzz | GW-6, GW-8 |
| M5-02 | HLX-33 | EdDSA-only JWT verification and JWK-thumbprint identity derivation | GW-1, GW-2 |
| M5-03 | HLX-34 | DPoP: stateless HMAC nonces, challenge flow, `helix.nonce`, `external_url` htu, bounded sharded `jti` cache | GW-3, GW-4, GW-9, GW-12, GW-14 |
| M5-04 | HLX-35 | Payload validation against the registered `input-schema` before instantiation | GW-5, GW-10 |
| M5-05 | HLX-36 | Full pipeline: state machine, audit wiring, error map incl. `-32030`, per-identity semaphore, describe grant check | GW-7, GW-15, GW-16 |
| M5-06 | HLX-37 | Adversarial suite in CI: `runtime/` and `gateway/` namespaces, end to end through the gateway | Section 8 of test plan |

## M6: `helix-sdk` (1 week)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M6-01 | HLX-38 | `#[helix_tool]` proc macro, `ToolError` mapping, `helix_sdk::delegate` wrapper | SDK-1, SDK-2, SDK-3 |
| M6-02 | HLX-39 | Author-guide example tools end to end, including delegation, and `helix-ctl run` | SDK-4 |

## M7: Hardening and release (1.5 weeks)

| Ticket | Linear | Scope | Exit |
|---|---|---|---|
| M7-01 | HLX-40 | Benchmark harness, `helix-bench`, CI regression gate on BENCH-1 through BENCH-5 | BENCH-1 through BENCH-5 |
| M7-02 | HLX-41 | Security checklist walkthrough; every row initialed with a commit hash; findings ticketed | `security-checklist.md` fully checked |
| M7-03 | HLX-42 | Runbook validated on a fresh machine by someone who did not write it | manual |
| M7-04 | HLX-43 | Nightly 4-hour fuzz jobs; seven clean nights as a release gate | GW-8 through GW-10 nightly |

Total: 14 weeks of focused work for two engineers, leaving late Q4 2026 for integration with the first upstream agent and Q1 2027 for release.

## Bare-prompt template

For each ticket, the PM writes a prompt under 400 words that opens with the literal paths to read, in this order: the ticket row above, `HELIX_PRDv2.md` (sections 3, 4, and 5.5 are superseded by `interfaces/`), the relevant `interfaces/` file, and the test IDs the ticket must make pass. The dev implements only what the ticket names. Scope questions come back to the PM.
