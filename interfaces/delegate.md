# In-process delegation (v1)

Authoritative host-import contract for `helix:delegate/invoke`. The WIT in `wit/helix-tool.wit` is the landed shape (ADR-009 A.2, HLX-6). This file states identity, bounds, audit, and admission. There is no other way to create a child invocation. The gateway never receives a child request over HTTP.

Sources: ADR-009 A.1–A.4, B.1; Plan_Audit 2026-09-03 (HLX-31 / HLX-36 semaphore ownership).

## Host import

Package `helix:tool@1.0.0`, interface `delegate`. Tools import it; the host implementation is M4-08 (HLX-31). Hello-world does not call it.

```
invoke: func(req: delegation-request) -> result<delegation-result, delegate-error>
```

`delegation-request`:

| Field | Type | Rule |
|---|---|---|
| `tool` | `tool-ref` (`alias(string)` or `digest(list<u8>)`) | Resolved against the parent's snapshot |
| `requested` | `capability-set` | Must be a subset of the parent's effective set |
| `budget` | `option<resource-budget>` | Absent = `min(parent budget, child policy budget)` |
| `input` | `list<u8>` | Validated against the child's `input-schema` before provisioning |

`delegation-result` mirrors the JSON-RPC success shape: `request-id` (string), `digest` (`list<u8>`), `output` (`list<u8>`), `usage` (`resource-usage`).

`capability-set` on this import has `interfaces`, `files`, `hosts` only. Budget is a sibling (ADR-008 A.4). Directory grants are a lattice element in `helix-caps` (`DirGrant`); the WIT `capability-set` in v1 has no `dirs` field. How a parent requests a directory grant over this import is not specified in ADR-009 A.2 or the landed WIT.

`resource-budget` and `resource-usage` field lists are in `wit/helix-tool.wit`.

## Identity

The child runs under the parent's identity. There is no second agent key and no second token. `X-Helix-Parent` and `X-Helix-Delegation` are not on the wire (ADR-009 A.4).

Policy lookup: `policy(parent_identity, child_digest)`.

Effective set:

```
attenuate(parent_effective, meet(policy(parent_identity, child_digest), requested))
```

exactly as ADR-008 A.4. `requested` is supplied by the parent in the host call. Resources compose separately: the child's budget must be `is_within` both the child's policy budget and the parent's budget.

The child inherits the parent's `PolicyGuard`. `policy.max_snapshot_age_s` (default 300) applies unchanged. A child whose parent's guard is older than that is refused with `delegate-error::stale-snapshot`.

## Execution

The child is spawned into the parent's `tokio::task::JoinSet` with a `CancellationToken` child of the parent's. Dropping the parent aborts the child (`Killed(ParentDropped)`, RT-9). This is the only delegation path (ADR-003 as amended by ADR-009 A.1).

The parent blocks in the host call until the child terminates. The parent's own `wall_clock_ms` keeps running; a parent that delegates a 30 second child with a 2 second budget is killed by its own clock.

A killed or failed child is an error value to the parent, not a kill of the parent. The parent decides what to do with it.

The child's output is bounded by the child's `output_bytes`. It is returned to the parent through host memory and does not count against the parent's `output_bytes` unless the parent includes it in its own result.

The child gets its own Store, its own audit record chain (Granted through terminal) with `parent: Some(parent_request_id)`, and its own `RequestId`. The tree is reconstructible from parent pointers.

## Bounds

`max_delegation_depth` (default 2) and `max_children` (default 8) are enforced in the host function (ADR-008 A.4). Depth is carried in the parent's request context; fan-out is `JoinSet::len()` at the moment of the call. Exceeding either returns `delegate-error::depth` or `::fanout` and writes `DelegationRefused{reason}` to the audit log under the parent's request id, since no child request id exists yet.

The ability to delegate is governed by the tree bounds in the budget, not by the lattice. There is no `Interface` bit for delegation. A budget with `max_children = 0` is a tool that cannot delegate.

`-32020 Delegation refused` remains as an HTTP error for one case only: a root request whose params reference a budget or tree bound that cannot be satisfied at admission (for example a `[budgets.*]` entry with `max_delegation_depth = 0` when the tool's signature declares it delegates). All other delegation refusals are `delegate-error` variants inside the sandbox and surface to the HTTP caller only as whatever the parent tool returns.

## Per-identity concurrency

`[budgets.*].max_concurrent_instances` (default 32) bounds the live instances, across all request trees, attributable to one `Identity` on one gateway (ADR-009 B.1). The whole tree counts against the root identity's cap.

**Semaphore ownership (amendment to ADR-009 B.1 wording; Plan_Audit 2026-09-03, HLX-31, HLX-36):**

The type `helix-runtime::admission::IdentitySemaphore` is owned by `helix-runtime`. The gateway holds the per-identity instances, takes the root permit at Authenticated → Authorized, and passes a handle into the invocation context. Children acquire through `runtime::delegate`. This preserves crate dependency direction (runtime does not import gateway) and makes RT-14 testable without a gateway.

If no permit is available:

- root request: refused `-32002` with `reason = "concurrency"`; audit transition `Denied{concurrency}` (`state-machine.md`)
- child: `delegate-error::denied`

The cap is per gateway. With N gateways an identity can hold N times the cap.

Permits are released on terminal. The permit count for a root request is 1; each delegated child acquires one more.

## Error variants

Landed WIT `delegate-error`:

| Variant | When |
|---|---|
| `unknown-tool` | Child alias/digest does not resolve in the parent's snapshot |
| `denied` | Policy miss, or per-identity cap exhausted for the child |
| `escalation(string)` | `requested` is not a subset of the parent effective set |
| `depth` | `max_delegation_depth` exceeded |
| `fanout` | `max_children` exceeded |
| `stale-snapshot` | Parent guard older than `policy.max_snapshot_age_s` |
| `invalid-input(string)` | Child input fails the child's `input-schema` |
| `audit-unavailable` | Granted (or terminal) record cannot be made durable; maps to the `-32030` rows of `state-machine.md` for the child |
| `child-failed(string)` | Provision failure |
| `child-killed(kill-cause)` | `preempted`, `wall-clock`, `memory`, `output`, `parent-dropped` |
| `child-tool-error(invoke-error)` | Child returned `invalid-input`, `capability-denied`, or `internal` |

RT-13 through RT-16 own the runtime assertions (escalation, depth/fan-out, child killed while parent continues, parent killed while child runs).
