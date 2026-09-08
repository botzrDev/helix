//! `helix-gateway`: axum JSON-RPC front door and internal [`Request`] seam.
//!
//! M5-01 / HLX-32: envelope parsing, `helix.health`, trusted-proxy logging,
//! and the `Request { id, identity, tool, payload, snapshot }` admission type.
//! M5-02 / HLX-33: `EdDSA`-only JWT verification, RFC 7638 thumbprint identity,
//! JWKS refresh, Bearer mode when `gateway.dpop = off`.
//! `DPoP` (HLX-34), payload schema (HLX-35), and the full state machine
//! (HLX-36) are deferred.
//!
//! Cites: `interfaces/gateway-protocol.md` §§1–4,6; ADR-004; ADR-008 B.1;
//! ADR-009 A.4.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auth;
mod config;
mod envelope;
mod health;
mod request;
mod rpc;
mod server;

pub use auth::{
    authenticate, bind_identity, derive_identity, extract_access_token, identity_from_jkt,
    identity_to_jkt, verify_token, AccessClaims, AuthError, AuthReason, CnfClaim, Ed25519PublicJwk,
    ExtractedToken, JwksCache, JwksSnapshot, VerificationKeys, VerifiedAccessToken, VerifyParams,
    METRIC_AUTH_FAILED,
};
pub use config::{ConfigError, DpopMode, GatewayConfig, HealthDetail, TrustedProxy};
pub use envelope::{parse_envelope, parse_envelope_value, EnvelopeOutcome, ParsedRequest};
pub use health::HealthStatus;
pub use request::{Request, RequestBuildError};
pub use rpc::{error as rpc_error, invalid_request, success as rpc_success, RpcCode, RpcId};
pub use server::{router, GatewayRuntime, GatewayState};
