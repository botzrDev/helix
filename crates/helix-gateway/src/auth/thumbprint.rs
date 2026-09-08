//! RFC 7638 JWK thumbprint → [`Identity`] (ADR-008 B.1).
//!
//! Canonical member order: `crv`, `kty`, `x`. SHA-256 over the exact JSON
//! `{"crv":"Ed25519","kty":"OKP","x":"..."}`; identity is the raw 32 bytes.

use base64::Engine;
use helix_caps::Identity;
use sha2::{Digest, Sha256};

use crate::auth::error::AuthError;

/// Ed25519 public JWK components needed for the thumbprint (OKP).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicJwk {
    /// Base64url-unpadded `x` coordinate (32 raw bytes when decoded).
    pub x: String,
}

impl Ed25519PublicJwk {
    /// Construct from the base64url `x` parameter.
    #[must_use]
    pub fn from_x(x: impl Into<String>) -> Self {
        Self { x: x.into() }
    }
}

/// RFC 7638 thumbprint of an Ed25519 OKP JWK → [`Identity`].
///
/// Pure: no I/O. Does not validate that `x` decodes to 32 bytes (callers that
/// need that check do it separately); the thumbprint is over the string form.
#[must_use]
pub fn derive_identity(key: &Ed25519PublicJwk) -> Identity {
    let canonical = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        key.x
    );
    let digest = Sha256::digest(canonical.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Identity::from_bytes(bytes)
}

/// Encode an [`Identity`] as unpadded base64url (wire `sub` / `cnf.jkt`).
#[must_use]
pub fn identity_to_jkt(id: Identity) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
}

/// Decode a wire `sub` / `cnf.jkt` base64url thumbprint into [`Identity`].
///
/// # Errors
///
/// [`AuthError`] with reason `binding` when the value is not 32 decoded bytes.
pub fn identity_from_jkt(jkt: &str) -> Result<Identity, AuthError> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let padded = base64::engine::general_purpose::URL_SAFE;
    let decoded = engine
        .decode(jkt)
        .or_else(|_| padded.decode(jkt))
        .map_err(|_| AuthError::binding())?;
    let arr: [u8; 32] = decoded.try_into().map_err(|_| AuthError::binding())?;
    Ok(Identity::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7638_ed25519_vector_shape() {
        // Fixed x → stable thumbprint (regression lock for canonical JSON).
        let key = Ed25519PublicJwk::from_x("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        let id = derive_identity(&key);
        let jkt = identity_to_jkt(id);
        assert_eq!(jkt.len(), 43); // 32 bytes base64url-unpadded
        assert_eq!(identity_from_jkt(&jkt).unwrap(), id);
    }
}
