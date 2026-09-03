# Invocation state machine (v1)

This file is the authoritative table. Every other document cites its cells and restates nothing. GW-7 is one test per row of the `helix.invoke` table.

Sources: ADR-008 F.1, ADR-008 D.3, ADR-009 B.1, ADR-009 B.2. The `Described` success transition is defined here (HLX-9); ADR-009 B.2 did not name it.

## Terminal states

Exactly `Completed`, `Failed`, `Killed`. Every path from `Granted` reaches exactly one terminal record, including panic, via a drop guard in `runtime::invoke` (ADR-008 D.3 / F.1).

`Described` is not a terminal state. `helix.describe` never reaches `Granted`.

## `helix.invoke`

| State | Event | Next | Audit transition | Synced | Exit code |
|---|---|---|---|---|---|
| Received | parse ok | Parsed | Received | no | |
| Received | parse fail | end | none | | -32700, -32600, -32601 |
| Parsed | token and proof valid | Authenticated | Authenticated | no | |
| Parsed | auth fail | end | AuthFailed{reason} | no | -32001 |
| Authenticated | alias resolves, policy hit, delegation ok, payload valid, permit available | Authorized | Authorized | no | |
| Authenticated | unknown tool | end | Rejected{unknown_tool} | no | -32003 |
| Authenticated | policy miss | end | Denied | no | -32002 |
| Authenticated | per-identity cap exhausted | end | Denied{concurrency} | no | -32002 |
| Authenticated | delegation escalation, depth, fan-out, stale snapshot | end | DelegationRefused{reason} | no | -32020 |
| Authenticated | payload invalid | end | Rejected{invalid_params} | no | -32602 |
| Authorized | Granted record durable | Granted | Granted{caps_hash, budget} | yes | |
| Authorized | audit write fails | end | none possible | | -32030 |
| Granted | instance provisioned | Provisioned | Provisioned | no | |
| Granted | link or instantiate fails | Failed | Failed{provision} | yes | -32004 |
| Provisioned | invoke entered | Running | Running | no | |
| Running | tool returns ok, output within bound | Completed | Completed{usage} | yes | result |
| Running | tool returns invoke-error | Completed | ToolError{kind, usage} | yes | -32005, -32006, -32007 |
| Running | preempted, wall clock, memory, output, parent dropped | Killed | Killed{cause, usage} | yes | -32010 to -32014 |
| Running | host panic | Killed | Killed{panic, usage} | yes | -32007 |
| any terminal | terminal record sync fails | end | none possible | | -32030 |

Notes:

- ADR-008 F.1 names the post-parse state `Parsed` in the Next column of the first row and as the State of the auth rows. There is no separate `Parsed` audit transition.
- `Denied{concurrency}` is ADR-009 B.1: enforced at the Authenticated → Authorized transition by the per-identity semaphore. Root requests receive `-32002` with `reason = "concurrency"`. A child that cannot acquire a permit receives `delegate-error::denied` (see `delegate.md`); that path is not an HTTP row.
- `-32020` on this table is the root-admission case (ADR-009 A.4): a root request whose params reference a budget or tree bound that cannot be satisfied at admission. In-process child refusals are `delegate-error` variants and write `DelegationRefused{reason}` under the parent's request id when no child request id exists yet (`depth`, `fanout`).
- `-32030` (ADR-008 D.3): no component is instantiated unless its Granted record is durable. If the writer returns an error, the gateway returns `-32030 Audit unavailable`, origin Authorized, with no data beyond `request_id`, and does not provision. If the terminal record cannot be synced, the response is still `-32030` even if the tool completed; output is discarded.
- Synced means the writer has `fdatasync`'d a batch that covers the record before the HTTP response is sent (ADR-008 D.1). Empty Synced cells are rows that write no audit record.
- Kill causes on the `-32010` to `-32014` row: `Preempted`, `WallClock`, `Memory`, `Output`, `ParentDropped`. ADR-008 E.1 renamed `Killed(Epoch)` to `Killed(Preempted)` and `-32010` to `Killed: preempted`.

## `helix.describe`

Describe shares the `Received` through `Authenticated` rows with `helix.invoke` (parse, token, proof). After `Authenticated` it writes exactly one of the following and ends. It never reaches `Authorized` or `Granted`. It writes no Granted record and provisions nothing (ADR-009 B.2).

| State | Event | Next | Audit transition | Synced | Exit code |
|---|---|---|---|---|---|
| Authenticated | alias resolves and policy(identity, digest) is a hit | end | Described | no | result |
| Authenticated | miss or no grant | end | Rejected{unknown_tool} | no | -32003 |

Notes:

- Both "no such tool" and "no grant" return `-32003` with `data.tool` or `data.digest` echoed back. The two cases are indistinguishable to the caller. The audit transition is `Rejected{unknown_tool}` in both; the distinction is logged at debug only (ADR-009 B.2, GW-16).
- `Described` is the success transition defined by this file. ADR-009 B.2 specified the miss and the absence of Granted / provision; it did not name the hit transition.
- Success body is the `tool-signature` record (see `gateway-protocol.md` section 3).

## `helix.nonce` and `helix.health`

Out of this table. `helix.nonce` is unauthenticated (ADR-009 C.1). `helix.health` is unauthenticated. Neither writes invocation audit transitions named above.

## Audit transition names

The names in the Audit transition column are the values carried as field 5 of the audit record (see `audit-record.md`). Integer tags for those names are not assigned in ADR-008 F.1 or ADR-009 D.1; `helix-audit` (M3) assigns them.
