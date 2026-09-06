//! Bind `sub` / `cnf.jkt` / optional proof-key thumbprint into [`Identity`].
//!
//! M5-02 / HLX-33 + M5-03 / HLX-34: `sub == cnf.jkt == derive_identity(proof)`
//! when a proof key is supplied. Bearer mode (`dpop = off`) passes
//! `proof_key = None` and only checks `sub == cnf.jkt`.

use helix_caps::Identity;

use crate::auth::error::AuthError;
use crate::auth::thumbprint::{derive_identity, identity_from_jkt, Ed25519PublicJwk};
use crate::auth::verify::AccessClaims;

/// Derive [`Identity`] from verified claims, optionally binding a `DPoP` key.
///
/// # Errors
///
/// [`AuthError`] with reason `binding` when any of the three disagree or a
/// thumbprint string is malformed.
pub fn bind_identity(
    claims: &AccessClaims,
    proof_key: Option<&Ed25519PublicJwk>,
) -> Result<Identity, AuthError> {
    if claims.sub != claims.cnf.jkt {
        return Err(AuthError::binding());
    }
    let identity = identity_from_jkt(&claims.sub)?;

    if let Some(key) = proof_key {
        let proof_id = derive_identity(key);
        if proof_id != identity {
            return Err(AuthError::binding());
        }
    }

    Ok(identity)
}
