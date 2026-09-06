//! `helix-gateway`: axum JSON-RPC front door and internal [`Request`] seam.
//!
//! M5-01 / HLX-32: envelope parsing, `helix.health`, trusted-proxy logging,
//! and the `Request { id, identity, tool, payload, snapshot }` admission type.
//! M5-02 / HLX-33: `EdDSA`-only JWT verification, RFC 7638 thumbprint identity,
//! JWKS refresh, Bearer mode when `gateway.dpop = off`.
//! M5-03 / HLX-34: `DPoP` RFC 9449 — HMAC nonces, challenge / `helix.nonce`,
//! `external_url` `htu`, bounded sharded `jti` cache.
//! M5-04 / HLX-35: [`validate::payload`] against registered `input-schema`
//! (`-32602` + `data.path`).
//! M5-05 / HLX-36: full pipeline (state machine, audit wiring, error map incl.
//! `-32030`, per-identity [`admission::IdentityAdmission`], `helix.describe`
//! grant check, metrics).
//!
//! ## HOLES (remaining)
//!
//! - Root `-32020` admission for `depth`/`fanout`/`stale_snapshot`/`escalation` on HTTP
//!   params is stubbed (`pipeline::refuse_root_delegation`); root HTTP requests
//!   do not carry child tree bounds on the wire (ADR-009 A.4). Covered in-process
//!   by `runtime::delegate` (RT-13/14).
//! - Adversarial kill paths (`-32010`…`-32013`) through the gateway: HLX-37
//!   suite in `tests/adversarial/` (gateway e2e + runtime namespace). Escalate /
//!   fanout / slowhost guest-through-gateway remain runtime-owned where
//!   `helix:delegate` / HTTP guest linking is not yet wired on the root path.
//! - `Caps` dual-hash on escalation records (RT-13) still deferred (record key 7
//!   is singular).
//! - Full Draft 2020-12 schema keywords: see `helix_policy::input_schema` HOLE.
//!
//! Cites: `interfaces/gateway-protocol.md` §§1–4,6; `interfaces/state-machine.md`;
//! ADR-008 D.3 / F.4; ADR-009 B.1 / B.2.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod admission;
pub mod auth;
mod config;
mod envelope;
pub mod error_map;
mod health;
pub mod pipeline;
mod request;
mod rpc;
mod server;
pub mod tools;
pub mod validate;

pub use admission::IdentityAdmission;
pub use auth::{
    authenticate, bind_identity, check_dpop, derive_identity, expected_htu, extract_access_token,
    fuzz_dpop_proof, identity_from_jkt, identity_to_jkt, issue_nonce, load_nonce_key_file,
    nonce_acceptable, verify_dpop_proof, verify_token, AccessClaims, AuthError, AuthReason,
    CnfClaim, DpopCheck, DpopRuntime, Ed25519PublicJwk, ExtractedToken, JtiCache, JwksCache,
    JwksSnapshot, NonceKeys, VerificationKeys, VerifiedAccessToken, VerifiedDpopProof,
    VerifyParams, METRIC_AUTH_FAILED, METRIC_JTI_ENTRIES, METRIC_JTI_FULL,
};
pub use config::{
    ConfigError, DpopMode, GatewayConfig, HealthDetail, TrustedProxy, DEFAULT_DPOP_JTI_MAX_ENTRIES,
    DEFAULT_DPOP_TTL_S,
};
pub use envelope::{parse_envelope, parse_envelope_value, EnvelopeOutcome, ParsedRequest};
pub use error_map::{METRIC_IDENTITY_IN_USE, METRIC_INVOCATIONS_TOTAL, METRIC_POLICY_DENIED};
pub use health::HealthStatus;
pub use request::{Request, RequestBuildError};
pub use rpc::{error as rpc_error, invalid_request, success as rpc_success, RpcCode, RpcId};
pub use server::{router, GatewayRuntime, GatewayState};
pub use tools::{LoadedTool, ToolRuntime};
pub use validate::{
    fuzz_payload_validator, invalid_params as invalid_params_path, payload as validate_payload,
    registry_from_signatures, PathError as PayloadPathError, Schema as PayloadSchema,
    SchemaRegistry,
};
