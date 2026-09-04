//! Digest and JWK-thumbprint parsers.

use base64::Engine;
use helix_caps::{Identity, ToolDigest};

use crate::PolicyError;

/// Parse `sha256:` followed by 64 hex characters into a [`ToolDigest`].
///
/// # Errors
///
/// Returns [`PolicyError::BadDigest`] when the prefix or hex is wrong.
pub fn parse_tool_digest(alias: &str, value: &str) -> Result<ToolDigest, PolicyError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(PolicyError::BadDigest {
            alias: alias.to_owned(),
            reason: "missing sha256: prefix".into(),
        });
    };
    if hex.len() != 64 {
        return Err(PolicyError::BadDigest {
            alias: alias.to_owned(),
            reason: "expected 64 hex characters after sha256:".into(),
        });
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = core::str::from_utf8(chunk).map_err(|_| PolicyError::BadDigest {
            alias: alias.to_owned(),
            reason: "invalid utf-8 in hex".into(),
        })?;
        bytes[i] = u8::from_str_radix(s, 16).map_err(|_| PolicyError::BadDigest {
            alias: alias.to_owned(),
            reason: "invalid hex".into(),
        })?;
    }
    Ok(ToolDigest::from_bytes(bytes))
}

/// Parse an RFC 7638 JWK thumbprint (base64url, 32 bytes) into [`Identity`].
///
/// # Errors
///
/// Returns [`PolicyError::BadIdentity`] when decoding fails or the length is not 32.
pub fn parse_identity_thumbprint(name: &str, value: &str) -> Result<Identity, PolicyError> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let padded = base64::engine::general_purpose::URL_SAFE;
    let decoded = engine.decode(value).or_else(|_| padded.decode(value));
    let bytes = decoded.map_err(|_| PolicyError::BadIdentity {
        name: name.to_owned(),
        reason: "invalid base64url".into(),
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| PolicyError::BadIdentity {
        name: name.to_owned(),
        reason: "thumbprint is not 32 bytes".into(),
    })?;
    Ok(Identity::from_bytes(arr))
}

/// Encode 32 bytes as unpadded base64url (tests and docs).
#[must_use]
pub fn encode_thumbprint(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// True when `authority` is lowercase `host:port` with an explicit numeric port.
#[must_use]
pub fn authority_is_valid(authority: &str) -> bool {
    if authority.is_empty() || authority != authority.to_ascii_lowercase() {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
}

const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// True when `method` is one of the six defined HTTP method names (rule 9).
#[must_use]
pub fn method_is_valid(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Map a policy method name to [`helix_caps::Method`].
///
/// # Errors
///
/// [`PolicyError::UnknownMethod`] when the name is not one of the six.
pub fn parse_method(name: &str) -> Result<helix_caps::Method, PolicyError> {
    match name {
        "GET" => Ok(helix_caps::Method::Get),
        "HEAD" => Ok(helix_caps::Method::Head),
        "POST" => Ok(helix_caps::Method::Post),
        "PUT" => Ok(helix_caps::Method::Put),
        "PATCH" => Ok(helix_caps::Method::Patch),
        "DELETE" => Ok(helix_caps::Method::Delete),
        other => Err(PolicyError::UnknownMethod(other.to_owned())),
    }
}

/// Map a policy interface name to [`helix_caps::Interface`].
///
/// # Errors
///
/// [`PolicyError::UnknownInterface`] when the name is not one of the five.
pub fn parse_interface(name: &str) -> Result<helix_caps::Interface, PolicyError> {
    match name {
        "stdio" => Ok(helix_caps::Interface::Stdio),
        "clocks" => Ok(helix_caps::Interface::Clocks),
        "random" => Ok(helix_caps::Interface::Random),
        "filesystem" => Ok(helix_caps::Interface::Filesystem),
        "http_outbound" => Ok(helix_caps::Interface::HttpOutbound),
        other => Err(PolicyError::UnknownInterface(other.to_owned())),
    }
}

/// Map `read` / `read_write` to [`helix_caps::FileMode`].
///
/// # Errors
///
/// [`PolicyError::UnknownMode`] otherwise.
pub fn parse_mode(name: &str) -> Result<helix_caps::FileMode, PolicyError> {
    match name {
        "read" => Ok(helix_caps::FileMode::Read),
        "read_write" => Ok(helix_caps::FileMode::ReadWrite),
        other => Err(PolicyError::UnknownMode(other.to_owned())),
    }
}
