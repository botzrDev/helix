//! Closed `-32001` reason set and auth failures.
//!
//! Cites: `interfaces/gateway-protocol.md` §4; security-checklist A1/A2.

use thiserror::Error;

/// Closed set of `-32001` `data.reason` values. Nothing else may leak.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthReason {
    /// Bad `alg`, bad signature, bad issuer, malformed token, wrong audience.
    Signature,
    /// `exp` in the past or `nbf` in the future.
    Expired,
    /// `DPoP` `jti` replay (HLX-34).
    Replay,
    /// `sub` / `cnf.jkt` / proof-key thumbprint disagree.
    Binding,
    /// Missing or stale `DPoP` nonce (HLX-34).
    Nonce,
}

impl AuthReason {
    /// Wire string for JSON-RPC `data.reason` and the metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Expired => "expired",
            Self::Replay => "replay",
            Self::Binding => "binding",
            Self::Nonce => "nonce",
        }
    }
}

impl std::fmt::Display for AuthReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Authentication failure mapped to `-32001` with a closed reason.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unauthenticated: {reason}")]
pub struct AuthError {
    /// Closed reason emitted on the wire and in metrics.
    pub reason: AuthReason,
}

impl AuthError {
    /// Construct and record `helix_auth_failed_total{reason}`.
    #[must_use]
    pub fn new(reason: AuthReason) -> Self {
        metrics::counter!(
            crate::auth::METRIC_AUTH_FAILED,
            "reason" => reason.as_str()
        )
        .increment(1);
        Self { reason }
    }

    /// `reason = signature`.
    #[must_use]
    pub fn signature() -> Self {
        Self::new(AuthReason::Signature)
    }

    /// `reason = expired`.
    #[must_use]
    pub fn expired() -> Self {
        Self::new(AuthReason::Expired)
    }

    /// `reason = binding`.
    #[must_use]
    pub fn binding() -> Self {
        Self::new(AuthReason::Binding)
    }

    /// `reason = replay` (reserved for HLX-34).
    #[must_use]
    pub fn replay() -> Self {
        Self::new(AuthReason::Replay)
    }

    /// `reason = nonce` (reserved for HLX-34).
    #[must_use]
    pub fn nonce() -> Self {
        Self::new(AuthReason::Nonce)
    }
}
