//! `helix-gateway`: axum JSON-RPC front door and internal [`Request`] seam.
//!
//! M5-01 / HLX-32: envelope parsing, `helix.health`, trusted-proxy logging,
//! and the `Request { id, identity, tool, payload, snapshot }` admission type.
//! Auth (HLX-33), `DPoP` (HLX-34), payload schema (HLX-35), and the full state
//! machine (HLX-36) are deferred.
//!
//! Cites: `interfaces/gateway-protocol.md` §§1,3,4,6; ADR-004; ADR-009 A.4.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod envelope;
mod health;
mod request;
mod rpc;
mod server;

pub use config::{ConfigError, GatewayConfig, HealthDetail, TrustedProxy};
pub use envelope::{parse_envelope, parse_envelope_value, EnvelopeOutcome, ParsedRequest};
pub use health::HealthStatus;
pub use request::{Request, RequestBuildError};
pub use rpc::{error as rpc_error, invalid_request, success as rpc_success, RpcCode, RpcId};
pub use server::{router, GatewayRuntime, GatewayState};
