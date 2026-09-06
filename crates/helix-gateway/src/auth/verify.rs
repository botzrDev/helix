//! `EdDSA`-only JWT verification (`auth::verify_token`).
//!
//! `alg` is inspected on the unprotected header **before** any claim is
//! deserialized (security-checklist A1 / GW-1). Only then is
//! `jsonwebtoken::decode` invoked with `Algorithm::EdDSA`.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::error::AuthError;

/// Confirmation claim carrying the agent's JWK thumbprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// RFC 7638 thumbprint (base64url) of the agent's Ed25519 key.
    pub jkt: String,
}

/// Access-token claims required by `interfaces/gateway-protocol.md` §2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Issuer URL (`gateway.issuer`).
    pub iss: String,
    /// Agent identity thumbprint (base64url).
    pub sub: String,
    /// Audience; wire may be a string or array — normalized below.
    #[serde(deserialize_with = "deserialize_aud")]
    pub aud: Vec<String>,
    /// Expiration (seconds since epoch).
    pub exp: i64,
    /// Issued-at (seconds since epoch).
    pub iat: i64,
    /// Not-before (optional).
    #[serde(default)]
    pub nbf: Option<i64>,
    /// Confirmation (`cnf.jkt`).
    pub cnf: CnfClaim,
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::String(s) => Ok(vec![s]),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => out.push(s),
                    _ => return Err(serde::de::Error::custom("aud array entry must be string")),
                }
            }
            Ok(out)
        }
        _ => Err(serde::de::Error::custom(
            "aud must be string or array of strings",
        )),
    }
}

/// Static verification parameters from `[gateway]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyParams {
    /// Expected `iss`.
    pub issuer: String,
    /// Expected `aud` member.
    pub audience: String,
}

/// Verified access token ready for [`crate::auth::bind_identity`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccessToken {
    /// Validated claims.
    pub claims: AccessClaims,
    /// JWT `kid` when present (JWKS lookup hint).
    pub kid: Option<String>,
}

/// A set of `EdDSA` verification keys keyed by optional `kid`.
///
/// Empty `kid` entries are tried when the token has no `kid`, or as fallback.
#[derive(Clone, Default)]
pub struct VerificationKeys {
    /// `kid` → decoding key. The empty string holds the default / sole key.
    keys: HashMap<String, Arc<DecodingKey>>,
}

impl VerificationKeys {
    /// Empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Insert a key under `kid` (use `""` for the default key).
    pub fn insert(&mut self, kid: impl Into<String>, key: DecodingKey) {
        self.keys.insert(kid.into(), Arc::new(key));
    }

    /// Number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no keys are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn select(&self, kid: Option<&str>) -> Result<Arc<DecodingKey>, AuthError> {
        if let Some(k) = kid {
            if let Some(key) = self.keys.get(k) {
                return Ok(Arc::clone(key));
            }
        }
        if let Some(key) = self.keys.get("") {
            return Ok(Arc::clone(key));
        }
        // Fall back to the sole key when only one is present.
        if self.keys.len() == 1 {
            return Ok(Arc::clone(self.keys.values().next().expect("len == 1")));
        }
        Err(AuthError::signature())
    }
}

/// Verify an access token: `EdDSA`-only, `alg` before claims, `iss`/`aud`/`exp`/`iat`.
///
/// # Errors
///
/// [`AuthError`] with a closed reason. Wrong `alg` (including `none`, `HS256`,
/// `RS256`) yields `signature` without deserializing claims (GW-1).
pub fn verify_token(
    token: &str,
    keys: &VerificationKeys,
    params: &VerifyParams,
) -> Result<VerifiedAccessToken, AuthError> {
    // A1 / GW-1: inspect unprotected header alg before any claim parse.
    reject_non_eddsa_header(token)?;

    let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError::signature())?;
    if header.alg != Algorithm::EdDSA {
        return Err(AuthError::signature());
    }
    let kid = header.kid.clone();
    let decoding_key = keys.select(kid.as_deref())?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.set_audience(std::slice::from_ref(&params.audience));
    validation.set_issuer(std::slice::from_ref(&params.issuer));
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);

    let data = decode::<AccessClaims>(token, decoding_key.as_ref(), &validation)
        .map_err(|e| map_jwt_error(&e))?;

    // `cnf` is required by protocol but not a registered JWT claim — checked here.
    if data.claims.cnf.jkt.is_empty() {
        return Err(AuthError::binding());
    }

    Ok(VerifiedAccessToken {
        claims: data.claims,
        kid,
    })
}

/// Parse only the JWT header segment and reject any `alg` other than `EdDSA`.
///
/// Deliberately does **not** touch the payload segment (GW-1).
fn reject_non_eddsa_header(token: &str) -> Result<(), AuthError> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or_else(AuthError::signature)?;
    // Require at least header.payload.signature shape before claim work.
    let _payload = parts.next().ok_or_else(AuthError::signature)?;
    let _sig = parts.next().ok_or_else(AuthError::signature)?;
    if parts.next().is_some() {
        return Err(AuthError::signature());
    }

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let padded = base64::engine::general_purpose::URL_SAFE;
    let bytes = engine
        .decode(header_b64)
        .or_else(|_| padded.decode(header_b64))
        .map_err(|_| AuthError::signature())?;
    let header: Value = serde_json::from_slice(&bytes).map_err(|_| AuthError::signature())?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(AuthError::signature)?;
    if alg != "EdDSA" {
        return Err(AuthError::signature());
    }
    Ok(())
}

fn map_jwt_error(err: &jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature => AuthError::expired(),
        // Everything else in the closed set maps to `signature` (incl. aud/iss).
        _ => AuthError::signature(),
    }
}
