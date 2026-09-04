//! Retention log entry for deleted audit files (runbook §5 / ADR-008 D.4).
//!
//! Format only in this ticket. Emission to the witness sink is M3-05 / HLX-22.

use crate::frame::HASH_LEN;
use crate::naming::{encode_ulid_bytes, hex_encode};
use crate::tags::HEADER_VERSION;
use minicbor::Encoder;
use serde_json::{json, Value as JsonValue};
use thiserror::Error;

/// One retention-log entry recording a deleted file's final (head) hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionEntry {
    pub version: u8,
    pub gateway_id: String,
    pub file_ulid: [u8; 16],
    /// Final head hash of the deleted file (last frame hash, or header
    /// `prev_hash` if the file had no frames).
    pub final_hash: [u8; HASH_LEN],
    pub wall_time_ns: u64,
    /// Basename that was deleted (e.g. `helix-<ulid>.log`).
    pub file_name: String,
}

impl RetentionEntry {
    #[must_use]
    pub fn new(
        gateway_id: impl Into<String>,
        file_ulid: [u8; 16],
        final_hash: [u8; HASH_LEN],
        wall_time_ns: u64,
        file_name: impl Into<String>,
    ) -> Self {
        Self {
            version: HEADER_VERSION,
            gateway_id: gateway_id.into(),
            file_ulid,
            final_hash,
            wall_time_ns,
            file_name: file_name.into(),
        }
    }

    /// Deterministic CBOR map (integer keys 0–5). Sink emission is M3-05.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, RetentionError> {
        let mut e = Encoder::new(Vec::with_capacity(96));
        e.map(6)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        e.u8(0)
            .map_err(|e| RetentionError::Encode(e.to_string()))?
            .u8(self.version)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        e.u8(1)
            .map_err(|e| RetentionError::Encode(e.to_string()))?
            .str(&self.gateway_id)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        e.u8(2)
            .map_err(|e| RetentionError::Encode(e.to_string()))?
            .bytes(&self.file_ulid)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        e.u8(3)
            .map_err(|e| RetentionError::Encode(e.to_string()))?
            .bytes(&self.final_hash)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        e.u8(4)
            .map_err(|e| RetentionError::Encode(e.to_string()))?
            .u64(self.wall_time_ns)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        e.u8(5)
            .map_err(|e| RetentionError::Encode(e.to_string()))?
            .str(&self.file_name)
            .map_err(|e| RetentionError::Encode(e.to_string()))?;
        Ok(e.into_writer())
    }

    /// Operator-facing JSON form (also suitable for a future witness-sink body).
    #[must_use]
    pub fn to_json(&self) -> JsonValue {
        json!({
            "version": self.version,
            "gateway_id": self.gateway_id,
            "file_ulid": encode_ulid_bytes(&self.file_ulid),
            "final_hash": hex_encode(&self.final_hash),
            "wall_time_ns": self.wall_time_ns,
            "file_name": self.file_name,
        })
    }
}

#[derive(Debug, Error)]
pub enum RetentionError {
    #[error("cbor encode: {0}")]
    Encode(String),
}
