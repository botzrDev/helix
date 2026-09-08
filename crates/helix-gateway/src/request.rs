//! Internal admission seam: [`Request`].
//!
//! Downstream of this type knows nothing about JSON-RPC or HTTP (ADR-004).
//! `parent` / `delegation` do not exist (ADR-009 A.4).
//!
//! Free of serde attributes — this is an in-process struct, not a wire type.
//!
//! Cites: `interfaces/gateway-protocol.md` §6.

use bytes::Bytes;
use helix_caps::{Identity, RequestId, ToolDigest};
use helix_policy::{AliasDigestError, PolicyGuard};
use serde_json::Value;
use thiserror::Error;

use crate::envelope::ParsedRequest;

/// Gateway → runtime admission record.
///
/// Built once after envelope + (later) auth succeed. No JSON-RPC / HTTP types.
#[derive(Clone, Debug)]
pub struct Request {
    /// ULID for this invocation tree root.
    pub id: RequestId,
    /// Authenticated agent identity (`EdDSA` JWT + thumbprint; HLX-33).
    pub identity: Identity,
    /// Resolved tool digest (alias already resolved against `snapshot`).
    pub tool: ToolDigest,
    /// Raw JSON params `input` object as bytes (validated by [`crate::validate::payload`]).
    pub payload: Bytes,
    /// Policy snapshot captured at admission (ADR-008 C.3).
    pub snapshot: PolicyGuard,
}

/// Failures while mapping `helix.invoke` params onto [`Request`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestBuildError {
    /// Neither `tool` nor `digest` present, or both disagree / malformed.
    #[error("invalid params: {0}")]
    InvalidParams(&'static str),
    /// Alias / digest resolution against the snapshot failed.
    #[error("unknown tool")]
    UnknownTool(AliasDigestError),
    /// `input` was present but not a JSON object.
    #[error("input must be an object")]
    BadInput,
}

impl Request {
    /// Build a [`Request`] from a parsed `helix.invoke` envelope.
    ///
    /// `identity` is supplied by `auth::authenticate`; callers may pass a
    /// placeholder for envelope-only tests.
    ///
    /// # Errors
    ///
    /// Returns [`RequestBuildError`] when params are incomplete or the alias
    /// table cannot resolve the tool.
    pub fn from_invoke(
        parsed: &ParsedRequest,
        identity: Identity,
        snapshot: PolicyGuard,
        request_id: RequestId,
    ) -> Result<Self, RequestBuildError> {
        let params = &parsed.params;
        let tool_alias = params.get("tool").and_then(Value::as_str);
        let digest_str = params.get("digest").and_then(Value::as_str);

        let tool = match (tool_alias, digest_str) {
            (None, None) => {
                return Err(RequestBuildError::InvalidParams(
                    "exactly one of tool or digest required",
                ));
            }
            (Some(alias), None) => snapshot.resolve_alias(alias).ok_or_else(|| {
                RequestBuildError::UnknownTool(AliasDigestError::UnknownAlias {
                    alias: alias.to_owned(),
                })
            })?,
            (None, Some(d)) => helix_policy::parse_tool_digest("digest", d)
                .map_err(|_| RequestBuildError::InvalidParams("digest must be sha256:<64 hex>"))?,
            (Some(alias), Some(d)) => {
                let provided = helix_policy::parse_tool_digest("digest", d).map_err(|_| {
                    RequestBuildError::InvalidParams("digest must be sha256:<64 hex>")
                })?;
                snapshot
                    .check_alias_digest(alias, &provided)
                    .map_err(RequestBuildError::UnknownTool)?;
                provided
            }
        };

        let payload = match params.get("input") {
            None => Bytes::from_static(b"{}"),
            Some(Value::Object(map)) => {
                Bytes::from(serde_json::to_vec(map).unwrap_or_else(|_| b"{}".to_vec()))
            }
            Some(_) => return Err(RequestBuildError::BadInput),
        };

        Ok(Self {
            id: request_id,
            identity,
            tool,
            payload,
            snapshot,
        })
    }
}
