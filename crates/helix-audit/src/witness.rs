//! Witness object + sink emission (ADR-008 D.4 / ADR-009 D.2 / HLX-22).
//!
//! Body: `{ version, gateway_id, file_ulid, sequence, head_hash, wall_time_ns }`
//! as deterministic CBOR (integer keys 0–5). Object key:
//! `<gateway_id>/<file_ulid>/<sequence:020>`.

use crate::export::WitnessAttrs;
use crate::frame::HASH_LEN;
use crate::naming::{encode_ulid_bytes, hex_encode};
use crate::retention::RetentionEntry;
use crate::tags::HEADER_VERSION;
use minicbor::{Decoder, Encoder};
use serde_json::{json, Value as JsonValue};
use thiserror::Error;

/// CBOR map keys for a witness object.
///
/// ADR-009 D.2 names the fields but does not assign integer keys. Provisional
/// 0–5 in field order; HOLE until an amendment pins them.
pub mod witness_key {
    pub const VERSION: u8 = 0;
    pub const GATEWAY_ID: u8 = 1;
    pub const FILE_ULID: u8 = 2;
    pub const SEQUENCE: u8 = 3;
    pub const HEAD_HASH: u8 = 4;
    pub const WALL_TIME_NS: u8 = 5;
}

/// One witnessed chain head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub version: u8,
    pub gateway_id: String,
    pub file_ulid: [u8; 16],
    pub sequence: u64,
    pub head_hash: [u8; HASH_LEN],
    pub wall_time_ns: u64,
}

impl Witness {
    #[must_use]
    pub fn new(
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        sequence: u64,
        head_hash: [u8; HASH_LEN],
        wall_time_ns: u64,
    ) -> Self {
        Self {
            version: HEADER_VERSION,
            gateway_id: gateway_id.into(),
            file_ulid,
            sequence,
            head_hash,
            wall_time_ns,
        }
    }

    /// Object-store key relative to the sink base (no leading slash).
    #[must_use]
    pub fn object_key(&self) -> String {
        witness_object_key(&self.gateway_id, &self.file_ulid, self.sequence)
    }

    #[must_use]
    pub fn to_attrs(&self) -> WitnessAttrs {
        WitnessAttrs {
            gateway_id: self.gateway_id.clone(),
            file_ulid: self.file_ulid,
            sequence: self.sequence,
            head_hash: self.head_hash,
            wall_time_ns: self.wall_time_ns,
        }
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>, WitnessError> {
        let mut e = Encoder::new(Vec::with_capacity(96));
        e.map(6).map_err(|e| WitnessError::Encode(e.to_string()))?;
        e.u8(witness_key::VERSION)
            .map_err(|e| WitnessError::Encode(e.to_string()))?
            .u8(self.version)
            .map_err(|e| WitnessError::Encode(e.to_string()))?;
        e.u8(witness_key::GATEWAY_ID)
            .map_err(|e| WitnessError::Encode(e.to_string()))?
            .str(&self.gateway_id)
            .map_err(|e| WitnessError::Encode(e.to_string()))?;
        e.u8(witness_key::FILE_ULID)
            .map_err(|e| WitnessError::Encode(e.to_string()))?
            .bytes(&self.file_ulid)
            .map_err(|e| WitnessError::Encode(e.to_string()))?;
        e.u8(witness_key::SEQUENCE)
            .map_err(|e| WitnessError::Encode(e.to_string()))?
            .u64(self.sequence)
            .map_err(|e| WitnessError::Encode(e.to_string()))?;
        e.u8(witness_key::HEAD_HASH)
            .map_err(|e| WitnessError::Encode(e.to_string()))?
            .bytes(&self.head_hash)
            .map_err(|e| WitnessError::Encode(e.to_string()))?;
        e.u8(witness_key::WALL_TIME_NS)
            .map_err(|e| WitnessError::Encode(e.to_string()))?
            .u64(self.wall_time_ns)
            .map_err(|e| WitnessError::Encode(e.to_string()))?;
        Ok(e.into_writer())
    }

    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, WitnessError> {
        let mut d = Decoder::new(bytes);
        let len = d
            .map()
            .map_err(|e| WitnessError::Decode(e.to_string()))?
            .ok_or_else(|| WitnessError::Decode("indefinite map".into()))?;
        let mut version = None;
        let mut gateway_id = None;
        let mut file_ulid = None;
        let mut sequence = None;
        let mut head_hash = None;
        let mut wall_time_ns = None;
        for _ in 0..len {
            let key = d.u8().map_err(|e| WitnessError::Decode(e.to_string()))?;
            match key {
                witness_key::VERSION => {
                    version = Some(d.u8().map_err(|e| WitnessError::Decode(e.to_string()))?);
                }
                witness_key::GATEWAY_ID => {
                    gateway_id = Some(
                        d.str()
                            .map_err(|e| WitnessError::Decode(e.to_string()))?
                            .to_owned(),
                    );
                }
                witness_key::FILE_ULID => {
                    let b = d.bytes().map_err(|e| WitnessError::Decode(e.to_string()))?;
                    if b.len() != 16 {
                        return Err(WitnessError::Decode("file_ulid len".into()));
                    }
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    file_ulid = Some(a);
                }
                witness_key::SEQUENCE => {
                    sequence = Some(d.u64().map_err(|e| WitnessError::Decode(e.to_string()))?);
                }
                witness_key::HEAD_HASH => {
                    let b = d.bytes().map_err(|e| WitnessError::Decode(e.to_string()))?;
                    if b.len() != HASH_LEN {
                        return Err(WitnessError::Decode("head_hash len".into()));
                    }
                    let mut a = [0u8; HASH_LEN];
                    a.copy_from_slice(b);
                    head_hash = Some(a);
                }
                witness_key::WALL_TIME_NS => {
                    wall_time_ns = Some(d.u64().map_err(|e| WitnessError::Decode(e.to_string()))?);
                }
                _ => {
                    d.skip().map_err(|e| WitnessError::Decode(e.to_string()))?;
                }
            }
        }
        Ok(Self {
            version: version.ok_or_else(|| WitnessError::Decode("missing version".into()))?,
            gateway_id: gateway_id
                .ok_or_else(|| WitnessError::Decode("missing gateway_id".into()))?,
            file_ulid: file_ulid.ok_or_else(|| WitnessError::Decode("missing file_ulid".into()))?,
            sequence: sequence.ok_or_else(|| WitnessError::Decode("missing sequence".into()))?,
            head_hash: head_hash.ok_or_else(|| WitnessError::Decode("missing head_hash".into()))?,
            wall_time_ns: wall_time_ns
                .ok_or_else(|| WitnessError::Decode("missing wall_time_ns".into()))?,
        })
    }

    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        json!({
            "version": self.version,
            "gateway_id": self.gateway_id,
            "file_ulid": encode_ulid_bytes(&self.file_ulid),
            "sequence": self.sequence,
            "head_hash": hex_encode(&self.head_hash),
            "wall_time_ns": self.wall_time_ns,
        })
    }
}

/// Object key for a witness PUT/GET.
#[must_use]
pub fn witness_object_key(gateway_id: &str, file_ulid: &[u8; 16], sequence: u64) -> String {
    format!(
        "{}/{}/{:020}",
        gateway_id,
        encode_ulid_bytes(file_ulid),
        sequence
    )
}

/// Object key for a retention entry (HOLE: ADR names sink write, not key layout).
///
/// Provisional: `<gateway_id>/<file_ulid>/retention`.
#[must_use]
pub fn retention_object_key(entry: &RetentionEntry) -> String {
    format!(
        "{}/{}/retention",
        entry.gateway_id,
        encode_ulid_bytes(&entry.file_ulid)
    )
}

/// Payload queued for the witness sink (witness head or retention log entry).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkPayload {
    Witness(Witness),
    Retention(RetentionEntry),
}

impl SinkPayload {
    #[must_use]
    pub fn object_key(&self) -> String {
        match self {
            Self::Witness(w) => w.object_key(),
            Self::Retention(e) => retention_object_key(e),
        }
    }

    pub fn encode_cbor(&self) -> Result<Vec<u8>, WitnessError> {
        match self {
            Self::Witness(w) => w.encode_cbor(),
            Self::Retention(e) => e
                .encode_cbor()
                .map_err(|e| WitnessError::Encode(e.to_string())),
        }
    }

    #[must_use]
    pub fn as_witness(&self) -> Option<&Witness> {
        match self {
            Self::Witness(w) => Some(w),
            Self::Retention(_) => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("cbor encode: {0}")]
    Encode(String),
    #[error("cbor decode: {0}")]
    Decode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_cbor_round_trip_deterministic() {
        let w = Witness::new("gw-1", [7u8; 16], 42, [9u8; 32], 1_700_000_000_000);
        let a = w.encode_cbor().unwrap();
        let b = w.encode_cbor().unwrap();
        assert_eq!(a, b);
        let decoded = Witness::decode_cbor(&a).unwrap();
        assert_eq!(decoded, w);
        assert_eq!(
            w.object_key(),
            format!("gw-1/{}/{:020}", encode_ulid_bytes(&[7u8; 16]), 42)
        );
    }
}
