//! `EdDSA`-only JWT verification, JWK-thumbprint identity, and `DPoP` (M5-02/03).
//!
//! Pure entry points: [`verify_token`], [`derive_identity`], [`bind_identity`],
//! [`verify_dpop_proof`]. JWKS refresh: [`JwksCache`]. `DPoP`: [`dpop`].
//!
//! Cites: ADR-008 B.1/B.2; ADR-009 C.1; `interfaces/gateway-protocol.md` §§1–2;
//! security-checklist A1/A2/A3a/A3b/C1; runbook §7; test-plan GW-1…4,9,12,14.

mod bind;
pub mod dpop;
mod error;
mod jwks;
mod thumbprint;
mod verify;

pub use bind::bind_identity;
pub use dpop::{
    check_dpop, expected_htu, fuzz_dpop_proof, issue_nonce, load_nonce_key_file, nonce_acceptable,
    verify_dpop_proof, DpopCheck, DpopRuntime, JtiCache, NonceKeys, VerifiedDpopProof,
    METRIC_JTI_ENTRIES, METRIC_JTI_FULL,
};
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

/// End-to-end access-token authenticate: extract → verify → bind.
///
/// `proof_key` is required when a `DPoP` proof was verified (HLX-34).
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
