# Security Review Checklist

Maps each threat-model row in the PRD to the code paths and tests that address it. Every line needs a checked box, a reviewer initial, and a commit hash before release. An unchecked line is a release blocker unless an ADR accepts the risk.

## A. Compromised or malicious calling agent

| # | Control | Code path | Tests | Checked |
|---|---|---|---|---|
| A1 | Only EdDSA tokens accepted; `alg` checked before claims | `helix-gateway::auth::verify_token` | GW-1 | [ ] |
| A2 | `sub` equals `cnf.jkt` equals the JWK thumbprint of the DPoP key | `auth::bind_identity` | GW-2 | [ ] |
| A3a | DPoP nonce valid across gateways sharing `nonce_key` | `auth::dpop` stateless HMAC nonce | GW-12 | [ ] |
| A3b | DPoP `jti` replay refused within one process; bounded cache | `auth::dpop::JtiCache` | GW-3, GW-14 | [ ] |
| A4 | Payload validated against tool schema before instantiation | `validate::payload` | GW-5, GW-10 | [ ] |
| A5 | Policy lookup is exact-match; no wildcards | `helix-policy::lookup` | POL-3 | [ ] |
| A6 | Delegation cannot escalate | `runtime::delegate`, `helix-caps::attenuate` | CAPS-4, CAPS-5, POL-6, RT-13 | [ ] |
| A7 | Output bounded | `runtime::BoundedWriter` | RT-7 | [ ] |
| A8 | Denial reasons do not leak policy contents unless `verbose_denials` | `gateway::error_map` | GW-7 | [ ] |
| A9 | Ingress rate limiting covers **external** requests only; internally generated calls are bounded by A10 (ADR-008 A.4) | runbook section 1 | n/a | [ ] |
| A10 | Resource exhaustion by an authorized caller through delegation: depth and fan-out enforced in `runtime::delegate`; per-identity cap at Authorized via `runtime::admission::IdentitySemaphore` (semaphore type owned by the runtime; HLX-31) | `runtime::delegate`, `runtime::admission` | RT-14, GW-15 | [ ] |
| A11 | Tool signatures visible only to granted identities (`helix.describe` grant check) | `gateway::describe` | GW-16 | [ ] |

## B. Malicious or replaced tool component

| # | Control | Code path | Tests | Checked |
|---|---|---|---|---|
| B1 | Identity is content digest; alias resolved before policy; grants pin alias and digest | `helix-policy::aliases` | POL-1 rules 2, 10 | [ ] |
| B2 | Blank linker; unlinked imports fail closed | `runtime::link` | RT-1, RT-12 | [ ] |
| B3 | Filesystem via cap-std, `O_NOFOLLOW`, `FileGrant` and `DirGrant` | `runtime::fs` | RT-2, RT-3, RT-4 | [ ] |
| B4 | HTTP authority and method enforced in host handler | `runtime::http` | RT-8, adversarial `slowhost` | [ ] |
| B5 | Memory ceiling via `ResourceLimiter`; table growth capped | `runtime::limits` | RT-6 | [ ] |
| B6 | Guest code that does not yield is preempted at `preempt_ticks`; host calls are cancelled at `wall_clock_ms` | `runtime::preempt` | RT-5, BENCH-8 | [ ] |
| B7 | Wall clock via cancellation token in every host fn | `runtime::host::*` | RT-8 | [ ] |
| B8 | Fresh `Store` per invocation; nothing reused | `runtime::invoke` | RT-10 | [ ] |
| B9 | Only `unsafe` is `Component::deserialize`, artifacts written only by `helix-ctl` with dir perms 0700 | `runtime::artifact` | ST-4, runbook | [ ] |
| B10 | Environment interface is never linked because it does not exist in v1 | `runtime::link` | RT-12 | [ ] |

## C. Network attacker

| # | Control | Code path | Tests | Checked |
|---|---|---|---|---|
| C1 | DPoP `htu` compared against `gateway.external_url` (not forwarded headers) | `auth::dpop::htu` | GW-4, GW-12 | [ ] |
| C2 | TLS at ingress; gateway refuses `X-Forwarded-*` from untrusted sources for logging/source-address | `gateway::proxy` | GW-7 | [ ] |

## D. Audit integrity

| # | Control | Code path | Tests | Checked |
|---|---|---|---|---|
| D1 | `Granted` and terminal records synced before response (group commit) | `helix-audit::Writer` | AUD-2, AUD-8 | [ ] |
| D2a | Local hash chain verified nightly (corruption, truncation, non-adversarial damage) | runbook section 5 | AUD-1, AUD-3 | [ ] |
| D2b | Chain verified against off-host witnesses nightly (adversarial rewrite older than one witness interval) | runbook section 5; `verify --witnesses` | AUD-9 | [ ] |
| D3 | Every invocation writes a terminal record even on panic | `runtime::invoke` guard | GW-7 | [ ] |
| D4 | Audit write failure refuses instantiation (`-32030`) | `helix-audit::Writer`, gateway error map | AUD-6, AUD-7 | [ ] |

## E. Process

| # | Item | Checked |
|---|---|---|
| E1 | `cargo deny` advisories clean at release commit | [ ] |
| E2 | Nightly fuzz has run ≥ 7 consecutive nights with no new crashes | [ ] |
| E3 | Adversarial suite passes at release commit | [ ] |
| E4 | Runbook incident table validated by an operator who did not write it | [ ] |
| E5 | Residual risks listed below reviewed and accepted | [ ] |

## Residual risks (accepted for v1, per PRD non-goals)

- Cross-sandbox side channels (timing, cache).
- Compromised host kernel.
- DoS against the TCP listener; delegated to ingress.
- Cross-gateway `jti` replay within `dpop_jti_window_s`: a proof captured and replayed to a different gateway that has not seen the `jti` succeeds. Mitigated by `htu`/`htm`/nonce-bucket/`iat` binding and token key binding (ADR-008 B.2). Shared `jti` store is a v2 option.
