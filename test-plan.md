# Test Plan

Test IDs are stable and referenced from the milestone plan. A milestone exits when every test listed for it passes in CI.

## 1. Static gates (every crate, every PR)

| ID | Check |
|---|---|
| ST-1 | `cargo build --workspace` with `RUSTFLAGS="-D warnings"` |
| ST-2 | `cargo clippy --workspace --all-targets -- -D clippy::pedantic -D clippy::disallowed_methods` (disallowed: `tokio::spawn` outside `helix-runtime::spawn_cancellable`, `std::process::exit`, `unwrap` in lib crates) |
| ST-3 | `cargo fmt --check` |
| ST-4 | `#![forbid(unsafe_code)]` compiled in every crate except `helix-runtime`; `helix-runtime` has exactly one `#[allow(unsafe_code)]` in `artifact.rs` |
| ST-5 | `cargo miri test -p helix-caps -p helix-audit` |
| ST-6 | `cargo deny check` (licenses, advisories, duplicate versions) |

## 2. `helix-caps` (M1)

| ID | Type | Assertion |
|---|---|---|
| CAPS-1 | property | `is_subset_of` is reflexive for all generated sets (including `dirs`) |
| CAPS-2 | property | `a ⊆ b ∧ b ⊆ a ⇒ a == b` |
| CAPS-3 | property | `a ⊆ b ∧ b ⊆ c ⇒ a ⊆ c` |
| CAPS-4 | property | `attenuate(p, r).is_ok() ⇔ r ⊆ p` (authority only; budgets out of lattice) |
| CAPS-5 | property | `attenuate(p, r) == Ok(s) ⇒ s ⊆ p` |
| CAPS-6 | property | `meet(a, b) ⊆ a ∧ meet(a, b) ⊆ b`, and any `c ⊆ a, c ⊆ b` satisfies `c ⊆ meet(a, b)` |
| CAPS-7 | exhaustive | All combinations of `interfaces` over the defined bits, with zero grants, against each other |
| CAPS-8 | unit | `new` rejects relative paths, `..` components, duplicate paths, duplicate authorities, orphan grants |
| CAPS-9 | unit | JSON round-trip of every field; unknown interface name fails to deserialize |
| CAPS-10 | unit | `EMPTY ⊆ x` for every generated `x` |
| CAPS-11 | property | every input that `new` rejects is rejected by `Deserialize`, driven by the same proptest generator; every input `new` accepts round-trips through serialize and deserialize to an equal value |
| CAPS-12 | unit | `MethodMask` rejects unknown method names; `interfaces` rejects unknown names and rejects any encoding that is not a name array |
| CAPS-13 | unit | `DirGrant` prefix containment edge cases, including `/a/b` not containing `/a/bc`, and `/` containing everything |
| CAPS-14 | property | `ResourceBudget::min` is the componentwise greatest lower bound and `is_within` is reflexive and transitive |
| CAPS-15 | unit | `RequestId` round-trips through JSON as a ULID string; rejects integers; rejects malformed base32 |

## 3. `helix-policy` (M2)

| ID | Type | Assertion |
|---|---|---|
| POL-1 | unit | Each of the 12 validation rules in `policy-format.md` produces the documented fatal error |
| POL-2 | unit | Directory grants are not expanded; a symlink at a granted `files[].path` or `dirs[].path` is fatal at load |
| POL-3 | unit | Lookup miss returns `None`; hit returns the exact `CapabilitySet` and `ResourceBudget` |
| POL-4 | unit | Reload with an invalid file leaves the prior snapshot live |
| POL-5 | integration | Reload mid-parent; child resolves against the parent's snapshot; a child delegated after `max_snapshot_age_s` is refused |
| POL-6 | unit | Delegation effective set equals `attenuate(parent, meet(policy(child), requested))`; child budget is `is_within` both ceilings |
| POL-7 | property | Structural validation never touches the filesystem (Fs mock that panics on any call) and rejects every generated rule violation |

## 4. `helix-runtime` (M4)

| ID | Type | Assertion |
|---|---|---|
| RT-1 | integration | Component with the http import but `HttpOutbound` bit clear fails at `Provisioned`, error `-32004` |
| RT-2 | integration | Filesystem grant for `/a/b.txt`: reading it succeeds, reading `/a/c.txt` fails inside the sandbox |
| RT-3 | integration | Symlink at grant path pointing outside the allowed tree is refused at open |
| RT-4 | integration | `../` in a guest path never resolves outside the preopen |
| RT-5 | adversarial | `loop {}` component killed with `Killed(Preempted)` within `preempt_ticks + 2` ticks |
| RT-6 | adversarial | Component allocating past `memory_bytes` gets `Killed(Memory)`; host RSS never exceeds budget plus 8 MiB |
| RT-7 | adversarial | Component writing `output_bytes + 1` gets `Killed(Output)`; caller receives no partial output |
| RT-8 | adversarial | Component blocking in a host HTTP call is cancelled at `wall_clock_ms`, `Killed(WallClock)` |
| RT-9 | adversarial | Dropping the parent request future aborts the child; child audit record is `Killed(ParentDropped)` |
| RT-10 | integration | 10 000 sequential invocations of a trivial tool; pooled instance count returns to zero; no RSS growth beyond 5 % |
| RT-11 | integration | Artifact compiled with a different wasmtime version fails to load with a clear error at startup, not at request time |
| RT-12 | unit | `link(&caps)` binds exactly the interfaces whose bits are set (inspect linker names) |
| RT-13 | runtime | (was GW-11) `escalate.wasm` calling `helix:delegate/invoke` with a superset receives `delegate-error::escalation`; audit record under the parent carries both `caps_hash` values |
| RT-14 | runtime | (was GW-13) depth and fan-out exceeded receive `::depth` / `::fanout`; no child Store is created |
| RT-15 | runtime | child killed by its own budget surfaces as `::child-killed`; parent continues and completes |
| RT-16 | runtime | parent killed by wall clock while a child runs; child audit record is `Killed(ParentDropped)` and the parent's is `Killed(WallClock)` |

## 5. `helix-gateway` (M5)

| ID | Type | Assertion |
|---|---|---|
| GW-1 | unit | JWT with `alg: HS256`, `none`, `RS256` rejected before claims are parsed |
| GW-2 | unit | Expired, not-yet-valid, wrong `aud`, `sub` / `cnf.jkt` / DPoP thumbprint mismatch each produce `-32001` with reason `binding` where applicable |
| GW-3 | unit | DPoP proof with reused `jti` inside the window is rejected; outside the window accepted |
| GW-4 | unit | DPoP `htu` mismatch against `gateway.external_url` and stale nonce rejected |
| GW-5 | unit | Payload violating `input-schema` produces `-32602` with correct `data.path` |
| GW-6 | unit | Batch JSON-RPC array produces `-32600` |
| GW-7 | integration | One test per row of `interfaces/state-machine.md`, asserting the JSON-RPC error code and the audit transition written |
| GW-8 | fuzz | `cargo fuzz run envelope` 10 minutes per PR, 4 hours nightly, no panics |
| GW-9 | fuzz | `cargo fuzz run dpop_proof` same schedule |
| GW-10 | fuzz | `cargo fuzz run payload_validator` same schedule |
| GW-12 | integration | Two gateway instances sharing `nonce_key`; nonce issued by A accepted by B; proof with a nonce from three buckets ago refused by both; challenge flow yields a nonce accepted on retry; `helix.nonce` from A accepted by B |
| GW-14 | unit | The `jti` cache at capacity refuses a fresh proof and increments `helix_dpop_jti_full_total`; after the window passes, insertion succeeds |
| GW-15 | integration | Per-identity concurrency cap refuses the 33rd concurrent root request (`-32002` reason `concurrency`); a second identity is unaffected |
| GW-16 | unit | `helix.describe` on an ungranted tool and on a nonexistent tool produce byte-identical responses apart from `request_id` and timing |

GW-11 and GW-13 are retired; their assertions live as RT-13 and RT-14.

## 6. `helix-audit` (M3)

| ID | Type | Assertion |
|---|---|---|
| AUD-1 | unit | Chain verification passes on a clean file, fails at the exact record index after a single byte flip |
| AUD-2 | integration | Process killed with `SIGKILL` between `Granted` and terminal write: on restart, verifier reports the chain intact through `Granted` |
| AUD-3 | integration | Rotation carries the last hash into the new file header; `verify` accepts the two-file sequence |
| AUD-4 | integration | Exporter stopped for 60 s under load: store is complete, exporter catches up, no gateway latency change beyond 5 % |
| AUD-5 | unit | Every `Transition` variant and every record field round-trips through deterministic CBOR to byte-identical output; two `CapabilitySet`s that are `==` produce identical side-file bytes and hash |
| AUD-6 | integration | Audit directory on a filesystem filled to capacity; `helix.invoke` returns `-32030`; `helix_instantiate_seconds` count does not increase |
| AUD-7 | integration | Rotation target directory made unwritable at the rotation boundary; same `-32030` behavior |
| AUD-8 | integration | Under 64 concurrent invocations, `helix_audit_sync_seconds` count is strictly less than the number of synced records; the chain verifies; every response was preceded by a sync covering its record |
| AUD-9 | integration | Rewrite records 100 through 200 and rechain forward; local verify passes; `verify --witnesses` fails at the first witness after record 100; a 412 on a rewritten sequence is surfaced as tampering |
| AUD-10 | integration | `witness-receive` under `SIGKILL` mid-PUT leaves no partial object visible to GET (write to temp, rename) |

## 7. `helix-sdk` (M6)

| ID | Type | Assertion |
|---|---|---|
| SDK-1 | build | `#[helix_tool]` on a function with a `schemars`-derivable input compiles to a component that exports `signature` and `invoke` |
| SDK-2 | integration | Generated `signature` schema rejects the same inputs as the Rust type's `Deserialize` |
| SDK-3 | build | Function with non-serializable argument fails at compile time with a pointed error |
| SDK-4 | integration | Example tool in the author guide builds, delegates to `word_count`, and passes RT-2 against the reference runtime |

## 8. Adversarial component suite (M4 / M5 exit, rerun at every release)

Split into `tests/adversarial/runtime/` and `tests/adversarial/gateway/`. Each is a component plus an expected terminal outcome.

### `tests/adversarial/runtime/`

| Component | Expected |
|---|---|
| `spin.wasm` | `Killed(Preempted)` |
| `membomb.wasm` | `Killed(Memory)` |
| `flood.wasm` | `Killed(Output)` |
| `traverse.wasm` (opens `../../etc/passwd`) | `invoke-error::capability-denied`, no host file opened (verified via `strace` in CI) |
| `unlinked.wasm` (imports `wasi:sockets`) | `Failed(Provision)` |
| `slowhost.wasm` (HTTP to a tarpit) | `Killed(WallClock)` |
| `escalate.wasm` (calls `helix:delegate/invoke` with a capability superset) | `delegate-error::escalation` |
| `fanout.wasm` (exceeds `max_children` or `max_delegation_depth`) | `delegate-error::fanout` or `delegate-error::depth` |

### `tests/adversarial/gateway/`

Gateway-namespace adversarial cases owned by M5-06 (HLX-37). Runtime fixtures above are exercised end-to-end through the gateway in that ticket; they remain runtime-owned assertions (RT-5 through RT-9, RT-13, RT-14).

## 9. Benchmarks

See `benchmark-protocol.md`. `BENCH-1` through `BENCH-5` are regression-gated in CI.
