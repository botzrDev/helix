//! Identity, digest, request id, and interface bit names.

use crate::ulid_str;

/// RFC 7638 JWK thumbprint of the agent's Ed25519 public key: SHA-256 over
/// the canonical JSON `{"crv":"Ed25519","kty":"OKP","x":"..."}` (ADR-008 B.1).
/// The same 32 bytes as `sub` / `cnf.jkt` (base64url on the wire, raw here).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Identity([u8; 32]);

impl Identity {
    /// Construct from a raw 32-byte thumbprint.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw 32-byte thumbprint.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// SHA-256 of the bytes of a WebAssembly component.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct ToolDigest([u8; 32]);

impl ToolDigest {
    /// Construct from a raw 32-byte digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// ULID of an invocation. In-memory type is `u128`. Serializes as a
/// 26-character Crockford base32 ULID string via `#[serde(with = "ulid_str")]`
/// (ADR-008 A.5). Rejects integers and malformed base32 (CAPS-15).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RequestId(#[serde(with = "ulid_str")] u128);

impl RequestId {
    /// Construct from a raw ULID `u128`.
    #[must_use]
    pub const fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// Raw ULID as `u128`.
    #[must_use]
    pub fn as_u128(self) -> u128 {
        self.0
    }
}

/// Bit positions in the internal `CapabilitySet` interfaces bitset.
/// Append-only; never renumber. Bit 5 is unassigned: `Interface::Environment`
/// is deleted (ADR-008 A.5). When environment variables gain behavior they
/// get the next free bit and a ticket.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interface {
    /// wasi:cli stdin/stdout/stderr
    Stdio = 0,
    /// wasi:clocks monotonic and wall
    Clocks = 1,
    /// wasi:random
    Random = 2,
    /// wasi:filesystem, scoped by `files` and `dirs`
    Filesystem = 3,
    /// wasi:http outgoing-handler, scoped by `hosts`
    HttpOutbound = 4,
}

impl Interface {
    /// Bit mask for this interface in the internal `u64` bitset.
    #[must_use]
    pub const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }
}
