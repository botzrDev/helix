//! `EdDSA`-only JWT verification and JWK-thumbprint identity (M5-02 / HLX-33).
//!
//! Pure entry points: [`verify_token`], [`derive_identity`], [`bind_identity`].
//! JWKS refresh: [`JwksCache`]. `DPoP` proof verification is HLX-34; this module
//! exposes an optional proof-key hook on [`bind_identity`].
//!
//! Cites: ADR-008 B.1; `interfaces/gateway-protocol.md` §2; security-checklist
//! A1/A2; runbook §7; test-plan GW-1/GW-2.

mod bind;
mod error;
mod jwks;
mod thumbprint;
mod verify;

pub use bind::bind_identity;
pub use error::{AuthError, AuthReason};
pub use jwks::{JwksCache, JwksSnapshot};
pub use thumbprint::{derive_identity, identity_from_jkt, identity_to_jkt, Ed25519PublicJwk};
pub use verify::{
    verify_token, AccessClaims, CnfClaim, VerificationKeys, VerifiedAccessToken, VerifyParams,
};

use crate::config::DpopMode;

/// Prometheus counter: `helix_auth_failed_total{reason}`.
pub const METRIC_AUTH_FAILED: &str = "helix_auth_failed_total";

/// Extracted access token from the `Authorization` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedToken {
    /// Raw JWT (never logged).
    pub token: String,
    /// True when the scheme was `DPoP` (proof header handled by HLX-34).
    pub dpop_scheme: bool,
}

/// Pull the access token from `Authorization` according to `gateway.dpop`.
///
/// - `off` → `Bearer <token>` required
/// - `required` / `optional` → prefer `DPoP <token>`; `optional` also accepts Bearer
///
/// # Errors
///
/// [`AuthError`] with reason `signature` when the header is missing/malformed.
pub fn extract_access_token(
    authorization: Option<&str>,
    dpop: DpopMode,
) -> Result<ExtractedToken, AuthError> {
    let header = authorization.ok_or_else(AuthError::signature)?;
    let header = header.trim();
    let (scheme, rest) = header.split_once(' ').ok_or_else(AuthError::signature)?;
    let token = rest.trim();
    if token.is_empty() {
        return Err(AuthError::signature());
    }

    match (dpop, scheme) {
        (DpopMode::Off, s) if s.eq_ignore_ascii_case("Bearer") => Ok(ExtractedToken {
            token: token.to_owned(),
            dpop_scheme: false,
        }),
        (DpopMode::Required, s) if s.eq_ignore_ascii_case("DPoP") => Ok(ExtractedToken {
            token: token.to_owned(),
            dpop_scheme: true,
        }),
        (DpopMode::Optional, s) if s.eq_ignore_ascii_case("DPoP") => Ok(ExtractedToken {
            token: token.to_owned(),
            dpop_scheme: true,
        }),
        (DpopMode::Optional, s) if s.eq_ignore_ascii_case("Bearer") => Ok(ExtractedToken {
            token: token.to_owned(),
            dpop_scheme: false,
        }),
        _ => Err(AuthError::signature()),
    }
}

/// End-to-end authenticate: extract → verify → bind (proof key deferred).
///
/// `proof_key` is the HLX-34 hook; pass `None` for Bearer / until `DPoP` lands.
///
/// # Errors
///
/// Closed-set [`AuthError`].
pub fn authenticate(
    authorization: Option<&str>,
    dpop: DpopMode,
    keys: &VerificationKeys,
    params: &VerifyParams,
    proof_key: Option<&Ed25519PublicJwk>,
) -> Result<helix_caps::Identity, AuthError> {
    let extracted = extract_access_token(authorization, dpop)?;
    let verified = verify_token(&extracted.token, keys, params)?;
    bind_identity(&verified.claims, proof_key)
}
