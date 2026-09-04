//! Frame layout: `u32 BE length || CBOR record || 32-byte prev_hash`.

use crate::record::{AuditRecord, RecordError};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const HASH_LEN: usize = 32;
pub const LENGTH_LEN: usize = 4;

/// One on-disk frame (decoded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub record: AuditRecord,
    /// `prev_hash` stored in this frame (hash of the previous frame's bytes).
    pub prev_hash: [u8; HASH_LEN],
    /// `sha256(length || record || prev_hash)` of this frame (head after append).
    pub frame_hash: [u8; HASH_LEN],
}

/// Encode a record into a frame using `prev_hash` of the previous frame.
pub fn encode_frame(
    record: &AuditRecord,
    prev_hash: &[u8; HASH_LEN],
) -> Result<(Vec<u8>, [u8; HASH_LEN]), FrameError> {
    let cbor = record.encode_cbor()?;
    let len = u32::try_from(cbor.len()).map_err(|_| FrameError::RecordTooLarge(cbor.len()))?;
    let mut frame = Vec::with_capacity(LENGTH_LEN + cbor.len() + HASH_LEN);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&cbor);
    frame.extend_from_slice(prev_hash);
    let frame_hash = hash_frame_bytes(&frame);
    Ok((frame, frame_hash))
}

/// Hash covering framing: `sha256(length || record || prev_hash)`.
#[must_use]
pub fn hash_frame_bytes(frame: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(frame);
    let dig = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&dig);
    out
}

/// Decode one frame starting at `buf[0]`. Returns `(frame, bytes_consumed)`.
pub fn decode_frame(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
    if buf.len() < LENGTH_LEN + HASH_LEN {
        return Err(FrameError::Truncated);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[..LENGTH_LEN]);
    let record_len = usize::try_from(u32::from_be_bytes(len_bytes)).expect("u32 fits usize");
    let total = LENGTH_LEN
        .checked_add(record_len)
        .and_then(|n| n.checked_add(HASH_LEN))
        .ok_or(FrameError::Truncated)?;
    if buf.len() < total {
        return Err(FrameError::Truncated);
    }
    let record_bytes = &buf[LENGTH_LEN..LENGTH_LEN + record_len];
    let mut prev_hash = [0u8; HASH_LEN];
    prev_hash.copy_from_slice(&buf[LENGTH_LEN + record_len..total]);
    let record = AuditRecord::decode_cbor(record_bytes)?;
    let frame_bytes = &buf[..total];
    let frame_hash = hash_frame_bytes(frame_bytes);
    Ok((
        Frame {
            record,
            prev_hash,
            frame_hash,
        },
        total,
    ))
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("truncated frame")]
    Truncated,
    #[error("record CBOR length {0} exceeds u32")]
    RecordTooLarge(usize),
}
