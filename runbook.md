# Operational Runbook

## 1. Topology

```
[upstream agents] --HTTPS--> [ingress / TLS termination] --HTTP--> [helix-gateway :8080]
                                                                        |
                                                                   in-process
                                                                        |
                                                              [helix-runtime pool]
                                                                        |
                                                             [audit store on local NVMe]
                                                                        |
                                          [OTel exporter --> collector]
                                          [witness sink --> object store / witness-receive]
```

- One gateway process per host. Scale horizontally; there is no shared state between gateways except the token issuer and the shared `nonce_key`.
- TLS is terminated at ingress. DPoP `htu` is compared against `gateway.external_url` plus the request path (not against forwarded headers). `trusted_proxies` remains for source-address logging only.
- Unauthenticated methods on the gateway: `helix.health` and `helix.nonce`. Rate-limit both at ingress like every other method.
- Per-gateway concurrency: `max_concurrent_instances` in each `[budgets.*]` bounds live instances for one identity **on one gateway**. With N gateways an identity can hold N times the cap.

## 2. Configuration

`/etc/helix/helix.toml`:

```toml
[gateway]
listen            = "0.0.0.0:8080"
dpop              = "required"          # required | optional | off
# D-3 / HLX-3: self-hosted Keycloak, EdDSA-only, DPoP cnf.jkt, protocol mapper so sub == cnf.jkt.
# Host unknown until the box exists. M0 walking skeleton stays on a hardcoded key.
issuer            = "https://<host>/realms/helix"
jwks_url          = "https://<host>/realms/helix/protocol/openid-connect/certs"
jwks_refresh_s    = 300
audience          = "helix"
# Returns granted host paths to the caller when true. Logs gateway.verbose_denials.enabled at warn on startup and every reload.
verbose_denials   = false
trusted_proxies   = ["10.0.0.0/8"]
external_url      = "https://helix.example.com"   # required; DPoP htu base
health_detail     = "minimal"                     # minimal | full
nonce_key         = "/etc/helix/nonce.key"        # 32-byte secret, file mode 0600, never inline
# nonce_key_next  = "/etc/helix/nonce.key.next"   # set during rotation; see section 7
dpop_nonce_ttl_s  = 60
dpop_jti_window_s = 60
dpop_jti_max_entries = 1048576

[runtime]
artifact_dir             = "/var/lib/helix/artifacts"
max_concurrent_instances = 256
pool_max_memory_bytes    = 536870912   # per instance ceiling; ResourceBudget may be lower
# guest preemption ticker is pinned at 1 ms; no configurable tick interval

[policy]
file               = "/etc/helix/policy.toml"
max_snapshot_age_s = 300

[audit]
dir                      = "/var/lib/helix/audit"
rotate_bytes             = 1073741824
otel_endpoint            = "http://collector:4317"
# D-4 / HLX-4: 90 days local retention; witness to Hetzner Object Storage with Object Lock (compliance) via SigV4.
retention_days           = 90
witness_sink             = "https://<hetzner-object-storage>/<bucket>"
witness_auth             = "sigv4"                # sigv4 | bearer
# witness_token_file     = "/etc/helix/witness.token"  # when witness_auth = bearer (witness-receive)
witness_interval_records = 10000
witness_interval_s       = 60
max_consecutive_errors   = 3
```

## 3. Registering a tool

```
helix-ctl tool register ./summarize_pdf.wasm
# prints: sha256:9e1d02...03  compiled in 840ms  signature: summarize_pdf v1.2.0
# also prints the exact [tools] line and grants that reference the old alias
```

Then add the alias and grants (pinning both `tool` and `digest`) to `policy.toml` and reload. Until the grant exists, invocations return `-32002`.

## 4. Policy reload

```
helix-ctl policy check /etc/helix/policy.toml                 # structural
helix-ctl policy check /etc/helix/policy.toml --artifacts ... # structural + host
helix-ctl policy reload                                       # sends SIGHUP
# with health_detail = full:
curl :8080/health | jq .policy_version
```

A failed reload logs `policy.reload.failed` with the rule violated and keeps the old snapshot.

## 5. Audit log

- Files: `audit/helix-<start-ulid>.log`. Header line carries `prev_hash` from the previous file. Caps side files: `audit/caps/<hex sha256>.cbor`.
- Local retention: **90 days** (D-4). Never edit or truncate a file; delete only whole files older than retention, oldest first, and record the deleted file's final hash in the retention log (also written to the witness sink).
- Verify: `helix-ctl audit verify /var/lib/helix/audit/` walks every file in order and prints the first break, if any. Run nightly and alert on failure.
- Witnesses: every `witness_interval_records` records or `witness_interval_s` seconds (whichever first), the writer PUTs a deterministic-CBOR object to:

  ```
  <witness_sink>/<gateway_id>/<file_ulid>/<sequence:020>
  ```

  with `If-None-Match: *`. Body fields: `version`, `gateway_id`, `file_ulid`, `sequence`, `head_hash`, `wall_time_ns`.

- Accepted sink types:
  1. **Object store with object lock** (primary: Hetzner Object Storage, Object Lock compliance mode, `audit.witness_auth = sigv4`).
  2. **`helix-ctl audit witness-receive`** on a second host (bearer token via `witness_token_file`).
- Nightly: `helix-ctl audit verify --witnesses <url>` against the sink. A 412 conflict on rewrite is an integrity signal (`helix_audit_witness_conflict_total`).
- Off-host copy: rsync the directory hourly. The exporter is not a backup. OTel remains a tail; it is not the WORM control.

## 6. Metrics and alerts

| Metric | Meaning | Alert |
|---|---|---|
| `helix_invocations_total{terminal=...}` | Count by terminal state | ratio of `killed_*` to `completed` > 5 % over 10 min |
| `helix_kill_preempt_total` | Guest preemption kills (was epoch) | sudden rise usually means a new tool version loops |
| `helix_kill_memory_total` | Memory kills | rise means a tool's budget is too low or the tool regressed |
| `helix_policy_denied_total{identity,digest}` | Denials | spike on one identity suggests a compromised or misconfigured agent |
| `helix_auth_failed_total{reason}` | `signature`, `expired`, `replay`, `binding`, `nonce` | `replay` > 0 sustained is an attack signal; `nonce` expected ~1/client/min and excluded from that alert |
| `helix_instantiate_seconds` | Histogram | p99 > 1 ms means pool exhaustion or artifact reload |
| `helix_pool_in_use` | Live instances | at `max_concurrent_instances` for > 30 s: scale out |
| `helix_identity_in_use` | Live instances per identity | approaching that identity's `max_concurrent_instances` |
| `helix_audit_sync_seconds` | Group-commit `fdatasync` latency | **p99 > 2 ms**: storage problem |
| `helix_audit_batch_size` | Records per group-commit batch | histogram; informational under load |
| `helix_audit_export_lag_records` | Exporter backlog | > 10 000: collector is down; store is safe |
| `helix_audit_witness_lag_s` | Age of last delivered witness | **> 300 s** |
| `helix_audit_witness_conflict_total` | 412 on witness PUT | any sustained rise: integrity investigation |
| `helix_audit_witness_dropped_total` | Witness queue overflow drops | > 0 sustained: sink unreachable |
| `helix_dpop_jti_entries` | Current `jti` cache occupancy | gauge |
| `helix_dpop_jti_full_total` | Proofs refused because a shard was full | any sustained rise: raise `dpop_jti_max_entries` or investigate flood |

## 7. Key rotation

- Issuer keys: the gateway refreshes JWKS every `jwks_refresh_s`. Rotate at the issuer with overlap of at least twice that interval.
- Agent keys: a new key is a new `Identity` (JWK thumbprint). Add the new identity to policy before the agent switches; remove the old one after.
- Nonce key: deploy the new key to every gateway as `nonce_key_next`. After `2 * dpop_nonce_ttl_s`, promote it to `nonce_key` on every gateway and remove `nonce_key_next`. Both keys are accepted during the overlap so in-flight nonces survive.

## 8. Upgrading wasmtime

Serialized artifacts are version-bound. Procedure: deploy the new binary to one host, run `helix-ctl tool reregister-all` (recompiles every artifact in `artifact_dir`), confirm `/health` shows the expected `artifacts_loaded` when `health_detail = full`, then roll.

## 9. Incident quick reference

| Symptom | First check |
|---|---|
| All requests `-32001` | JWKS fetch failing; check `helix_auth_failed_total{reason="signature"}` and issuer reachability |
| All requests `-32004` | Artifacts failed to load after upgrade; see section 8 |
| All requests `-32030` | Audit storage; check `helix_audit_sync_seconds`, free space, `helix.health` audit status |
| One tool always `-32010` (preempted) | Check `helix_pool_in_use` and host load first; then whether the tool loops or `preempt_ticks` is too low |
| Latency p99 spike, `helix_audit_sync_seconds` high | Storage; move audit dir or check NVMe health |
| `helix_pool_in_use` pinned at max | Long-running tools; lower `wall_clock_ms` or scale out |
| `helix_audit_witness_lag_s` > 300 | Witness sink unreachable or misconfigured SigV4; local chain still appends |
