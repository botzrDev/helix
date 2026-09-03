# Gateway Wire Protocol (v1)

JSON-RPC 2.0 over HTTP/1.1 or HTTP/2, `Content-Type: application/json`. One request per HTTP call; batch arrays are rejected with `-32600`.

Error origins cite [`state-machine.md`](state-machine.md). This file does not restate that table.

Sources: ADR-008 B.1, B.2, A.4, A.5, C.3, D.3, E.1, F.1; ADR-009 A.4, B.2, C.1.

## 1. Headers

| Header | Required | Value |
|---|---|---|
| `Authorization` | yes (except `helix.health`, `helix.nonce`) | `DPoP <access-token>` when `gateway.dpop != off`, otherwise `Bearer <access-token>` |
| `DPoP` | when dpop is `required` | DPoP proof JWT (RFC 9449), `alg: EdDSA`, `htm: POST`, `htu` as computed below, `jti`, `iat`, `nonce` |

`X-Helix-Parent` and `X-Helix-Delegation` are deleted (ADR-009 A.4). They have no producer. Delegation is in-process via `helix:delegate/invoke` (see [`delegate.md`](delegate.md)).

### `htu`

Compared against configuration, not headers (ADR-008 B.2). `gateway.external_url` is required. The gateway computes the expected `htu` from it plus the request path. `X-Forwarded-Proto` and `X-Forwarded-Host` are not inputs to DPoP validation; they are used only for logging. `trusted_proxies` remains for source-address purposes.

### Nonce bootstrap (ADR-009 C.1)

Nonces are stateless: `DPoP-Nonce = base64url(HMAC-SHA256(k, epoch_bucket || client_jkt))` with `epoch_bucket = floor(now / dpop_nonce_ttl_s)` and `k = gateway.nonce_key`. A gateway accepts a nonce from the current or the immediately previous bucket. No gateway stores nonces.

Both bootstrap paths are supported:

1. **Challenge (RFC 9449 section 8).** A request whose proof lacks a nonce, or carries one outside the current or previous bucket, is answered with HTTP 401, JSON-RPC `-32001` with `reason = "nonce"`, and a `DPoP-Nonce` header carrying the current nonce for the proof's `jkt`. The client retries once.
2. **Warm-up.** `helix.nonce` (section 3).

A nonce obtained from any gateway is valid at every gateway behind the same `nonce_key`.

## 2. Access token claims

```json
{
  "iss": "https://issuer.example",
  "sub": "<base64url JWK thumbprint>",
  "aud": "helix",
  "exp": 1780000000,
  "iat": 1779999400,
  "cnf": { "jkt": "<base64url JWK thumbprint of the same key>" }
}
```

`sub` is the RFC 7638 JWK thumbprint of the agent's Ed25519 public key (SHA-256 over the canonical `{"crv":"Ed25519","kty":"OKP","x":"..."}`), base64url-encoded. `cnf.jkt` is the same string. `Identity` in helix-caps is the same 32 bytes (ADR-008 B.1).

`sub` must equal `cnf.jkt` must equal the thumbprint of the DPoP proof key. Any mismatch among the three is `-32001` with `reason = "binding"`.

## 3. Methods

### `helix.invoke`

```json
{
  "jsonrpc": "2.0",
  "id": "c9f1...",
  "method": "helix.invoke",
  "params": {
    "tool": "read_customer_db",
    "digest": "sha256:ab34...",
    "input": { "query": "SELECT ..." }
  }
}
```

- Exactly one of `tool` (alias) or `digest` is required. If both are present they must agree.
- `input` is validated against the tool's `input-schema` before instantiation. Failure is `-32602` with `data.path` pointing at the offending JSON pointer.
- Alias is a caller convenience; authority is granted by digest (ADR-008 C.1).

Success:

```json
{
  "jsonrpc": "2.0",
  "id": "c9f1...",
  "result": {
    "request_id": "01J...",
    "digest": "sha256:ab34...",
    "output": { "...": "..." },
    "usage": { "wall_ms": 12, "preempt_ticks": 9, "peak_memory_bytes": 1048576, "output_bytes": 812 }
  }
}
```

`request_id` is a 26-character Crockford base32 ULID string (ADR-008 A.5). `preempt_ticks` is the renamed `epoch_ticks` (ADR-008 E.1). The success-body field names `wall_ms` / `peak_memory_bytes` are inherited from the pre-rewrite protocol; ADR-008/009 do not rename them.

### `helix.describe`

`params: { "tool" | "digest" }`. Returns the `tool-signature` record if and only if `policy(identity, digest)` is a hit. Both "no such tool" and "no grant" return `-32003` with `data.tool` or `data.digest` echoed back. The two cases are indistinguishable to the caller (ADR-009 B.2, GW-16).

Writes no Granted record and provisions nothing. After `Authenticated` it writes exactly one of `Rejected{unknown_tool}` or `Described` and ends. It never reaches `Authorized` or `Granted` (see `state-machine.md`).

### `helix.nonce`

Unauthenticated. `params: { "jkt": "<base64url thumbprint>" }`. Returns `{ "nonce": "..." }` and the same value in the `DPoP-Nonce` header (ADR-009 C.1). Exists so a client can prime before its first invoke. Rate-limited at ingress like every other method.

### `helix.health`

No auth. Returns `{ "status": "ok", "artifacts_loaded": N, "policy_version": "..." }`.

ADR-008 D.3 and F.4 add `audit: "ok" | "degraded" | "failed"` and `gateway.health_detail = minimal | full`. Those amendments are owned by later tickets (HLX-36 / HLX-44) and are not applied here.

## 4. Error codes

Cite [`state-machine.md`](state-machine.md) for origin. The previous "State-table origin" column is withdrawn (ADR-008 F.1).

| Code | Name | `data` |
|---|---|---|
| -32700 | Parse error | none |
| -32600 | Invalid request | `reason` |
| -32601 | Method not found | none |
| -32602 | Invalid params | `path`, `reason` |
| -32001 | Unauthenticated | `reason` in the closed set `signature`, `expired`, `replay`, `binding`, `nonce`. Never leaks which check failed beyond that set. `nonce` does not leak anything the `DPoP-Nonce` header does not already disclose. |
| -32002 | Denied | `reason` (`concurrency` when the per-identity cap is exhausted). `requested` and `available` (both as `CapabilitySet` JSON with budget sibling) omitted unless `gateway.verbose_denials = true`. |
| -32003 | Unknown tool | `tool` or `digest` |
| -32004 | Provision failed | `reason` |
| -32005 | Tool error: invalid input | `message` from `invoke-error::invalid-input` |
| -32006 | Tool error: capability denied | `message` |
| -32007 | Tool error: internal | none (message is logged only). Also the HTTP mapping of host panic (`Killed{panic}`). |
| -32010 | Killed: preempted | `usage` |
| -32011 | Killed: wall clock | `usage` |
| -32012 | Killed: memory | `usage` |
| -32013 | Killed: output | `usage` |
| -32014 | Killed: parent dropped | none |
| -32020 | Delegation refused | `reason` (`depth`, `fanout`, `stale_snapshot`, or `escalation` as applicable). HTTP code for **root admission only** (ADR-009 A.4). Child refusals are `delegate-error` variants. |
| -32030 | Audit unavailable | `request_id` only. No other data. Origin is the Authorized or terminal `-32030` row of `state-machine.md`. |

Every error response carries `request_id` in `data` once the request has passed `Received`.

`reason = "nonce"` is a `-32001` reason, not a separate JSON-RPC code.

## 5. `CapabilitySet` JSON encoding

Used in verbose denials and `helix-ctl run --caps` (ADR-009 E.2). Not used on a delegation header.

`budget` is a sibling of the set, not a field of it (ADR-008 A.4).

```json
{
  "interfaces": ["stdio", "clocks", "random", "filesystem", "http_outbound"],
  "files": [{ "path": "/srv/data/report.csv", "mode": "read" }],
  "dirs": [{ "path": "/srv/inbox", "mode": "read_write" }],
  "hosts": [{ "authority": "api.example.com:443", "methods": ["GET", "POST"] }],
  "budget": {
    "preempt_ticks": 500,
    "wall_clock_ms": 2000,
    "memory_bytes": 67108864,
    "output_bytes": 1048576,
    "max_delegation_depth": 2,
    "max_children": 8,
    "max_concurrent_instances": 32
  }
}
```

- `interfaces` is encoded as names on the wire and as a `u64` bitset in memory. The name-to-bit table is defined once in `helix-caps` and is append-only. `environment` is not a name. Bit 5 is unassigned.
- `files[].path` / `dirs[].path` are absolute canonical strings on the wire; in memory they are intern ids.
- `hosts[].methods` is an array of the six `Method` names. An unknown name is a fatal error.
- `budget` is `ResourceBudget`. Absence on a child delegation request means `min(parent budget, child policy budget)` (WIT `option`; HTTP children do not exist).
- Audit log encoding of sets is deterministic CBOR in `caps/<hex>.cbor`, not this JSON (see [`audit-record.md`](audit-record.md)).

The JSON field name on directory grants (`path` vs `canonical_root`) is not named in ADR-008 A.2 for the wire; this file uses `path` to match `files[]` and `policy-format.md` `dirs[].path`.

## 6. Internal seam

`helix-gateway` parses the above into:

```rust
pub struct Request {
    pub id: RequestId,
    pub identity: Identity,
    pub tool: ToolDigest,
    pub payload: Bytes,
    pub snapshot: PolicyGuard,
}
```

`parent` and `delegation` are deleted (ADR-009 A.4). Delegation state lives in the runtime's invocation context, not in the gateway request.

`snapshot` is the `arc_swap` guard captured once at admission (ADR-008 C.3). It owns the interner and the alias table. Every lookup for the request and for every delegated child uses that guard. `PolicyGuard` is defined by `helix-policy`; this seam names the field only.

Nothing downstream of this struct knows about JSON-RPC or HTTP.
