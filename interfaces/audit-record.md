# Audit record (v1)

Authoritative encoding for `helix-audit`. Written before any M-ticket that touches audit (ADR-008 D.2). Encoding is ADR-009 D.1.

Sources: ADR-008 D.1, D.2, D.3, D.4; ADR-009 D.1, D.2.

## Codec

RFC 8949 section 4.2.1 Core Deterministic Encoding for the audit record and for the `caps/<hash>` side files. One codec, one verifier.

Deterministic encoding is enforced by a unit test that re-encodes every decoded record and asserts byte equality (AUD-5).

The crate picks `ciborium` or `minicbor`; that choice is not architectural (ADR-009 D.1).

## Framing

Each frame on the log file:

```
u32 big-endian length || CBOR record || 32-byte prev_hash
```

`length` is the byte length of the CBOR record (not including the length prefix or the trailing `prev_hash`).

`prev_hash` of this frame is `sha256(length || record || prev_hash)` of the **previous** frame, so the hash covers the framing.

The first frame of a file uses the `prev_hash` carried in the file header (rotation rule, ADR-005 as amended by ADR-008 D.1 / ADR-009 D.1). Genesis `prev_hash` for the first file a gateway ever opens is not specified in ADR-009 D.1.

## File header

Each log file begins with a CBOR map:

| Field | Meaning |
|---|---|
| `version` | Header / format version |
| `file_ulid` | ULID of this log file |
| `gateway_id` | Gateway that opened the file |
| `prev_hash` | Hash carried from the previous file (ADR-005 rotation) |

ADR-009 D.1 names these fields and does not assign integer keys, CBOR types, or widths for the header (unlike the record schema below). Readers treat unknown header keys as they treat unknown record keys: ignore them. A reader must accept all lower versions.

## Record schema (v1)

A CBOR map with integer keys. Integer keys keep records small and make the deterministic encoding trivial.

| Key | Name | Type |
|---|---|---|
| 0 | version | uint (`u8` in ADR-008 D.2) |
| 1 | request_id | bytes16 |
| 2 | parent | bytes16 or null |
| 3 | identity | bytes32 |
| 4 | digest | bytes32 |
| 5 | transition | small int |
| 6 | reason | text, max 256 bytes |
| 7 | caps_hash | bytes32 or null |
| 8 | budget | array of 4 uints or null |
| 9 | usage | array of 4 uints or null |
| 10 | wall_time_ns | uint |
| 11 | sequence | uint |

Rules:

- A reader must accept any version less than or equal to its own and must ignore keys it does not know (ADR-009 D.1).
- `reason` is capped at 256 bytes (ADR-008 D.2). Other fields are the CBOR types above; records are not fixed-width on disk.
- `parent` is `Some(parent_request_id)` for in-process children and null for roots (ADR-009 A.2).
- `identity` is the 32-byte JWK thumbprint (ADR-008 B.1).
- `digest` is the 32-byte tool SHA-256.
- `request_id` is the ULID as 16 bytes (in-memory `u128`).
- `transition` is the audit transition from `state-machine.md`. The name-to-integer map is not specified in ADR-009 D.1; M3 assigns it. Names in v1 include: `Received`, `Authenticated`, `AuthFailed`, `Authorized`, `Rejected`, `Denied`, `DelegationRefused`, `Granted`, `Provisioned`, `Running`, `Completed`, `ToolError`, `Failed`, `Killed`, `Described`. Reason / cause / kind payloads use field 6 and are not a second map.
- `caps_hash` is present on transitions that carry a capability set (at least `Granted{caps_hash, budget}` and the RT-13 parent record that carries both hashes). Null on transitions that do not.
- `budget` and `usage` are each an array of 4 uints or null. ADR-009 D.1 does not name the four elements. The adjacent WIT `resource-usage` record is four fields in this order: `preempt-ticks`, `wall-clock-ms`, `memory-bytes`, `output-bytes`. Tree-bound fields on `ResourceBudget` (`max_delegation_depth`, `max_children`, `max_concurrent_instances`) are not in this array. M3 must not invent a fifth element without an amendment.
- `wall_time_ns` is the record's wall timestamp. Epoch and units beyond "ns" in the field name are not further specified.
- `sequence` is the per-file (or per-chain) sequence number used by witnesses (ADR-008 D.4, ADR-009 D.2).

ADR-008 D.2 also stated: a record that references a `caps_hash` whose side file is missing is a verification failure; `helix-ctl audit verify` checks this.

## Caps side file

Path: `caps/<hex sha256>.cbor`.

Content is the deterministic CBOR encoding of the `CapabilitySet` with paths and authorities resolved to strings (not intern ids, which are snapshot-scoped). `caps_hash` is the sha256 of those bytes.

The `CapabilitySet` itself is written once, the first time that hash is seen in a process. The side file directory is append-only: files are created, never modified. Rotation (ADR-005) applies to the log only; the caps directory does not rotate and is retained for as long as any log file that references it.

`helix-ctl audit caps <hash>` prints the side file as JSON. `helix-ctl audit dump <file>` prints records as JSON lines.

Two `CapabilitySet` values that are `==` produce identical side-file bytes and hash (AUD-5).

## Group commit (writer)

One writer task owns the file and the chain. All records arrive on a bounded channel. The writer drains everything available, frames each record with `prev_hash`, appends the batch with one write, issues one `fdatasync`, then completes every waiter whose record was in the batch (ADR-008 D.1).

A response is sent only after a sync that covers its Granted record, and a terminal record is synced before the terminal response. Non-synced transitions travel the same channel and are appended in the same batches; they have no waiter.

Fail-closed behaviour is `state-machine.md` rows that exit `-32030`.

## Witness objects

Not part of the log frame. Specified in ADR-009 D.2 (M3-05 / HLX-22): HTTP PUT of a deterministic-CBOR object `{ version, gateway_id, file_ulid, sequence, head_hash, wall_time_ns }` to `<witness_sink>/<gateway_id>/<file_ulid>/<sequence:020>` with `If-None-Match: *`. Witness delivery never blocks the writer and never fails a request.
