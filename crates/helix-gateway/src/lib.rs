//! `helix-gateway`: axum JSON-RPC front door and internal [`Request`] seam.
//!
//! M5-01 / HLX-32: envelope parsing, `helix.health`, trusted-proxy logging,
//! and the `Request { id, identity, tool, payload, snapshot }` admission type.
//! M5-02 / HLX-33: `EdDSA`-only JWT verification, RFC 7638 thumbprint identity,
//! JWKS refresh, Bearer mode when `gateway.dpop = off`.
//! M5-03 / HLX-34: `DPoP` RFC 9449 — HMAC nonces, challenge / `helix.nonce`,
//! `external_url` `htu`, bounded sharded `jti` cache.
//! M5-04 / HLX-35: [`validate::payload`] against registered `input-schema`
//! (`-32602` + `data.path`); full state machine remains HLX-36.
//!
//! Cites: `interfaces/gateway-protocol.md` §§1–4,6; ADR-004; ADR-008 B.1/B.2;
//! ADR-009 A.4, C.1.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auth;
mod config;
mod envelope;
mod health;
mod request;
mod rpc;
mod server;
pub mod validate;

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
pub use health::HealthStatus;
pub use request::{Request, RequestBuildError};
pub use rpc::{error as rpc_error, invalid_request, success as rpc_success, RpcCode, RpcId};
pub use server::{router, GatewayRuntime, GatewayState};
pub use validate::{
    fuzz_payload_validator, invalid_params as invalid_params_path, payload as validate_payload,
    registry_from_signatures, PathError as PayloadPathError, Schema as PayloadSchema,
    SchemaRegistry,
};
