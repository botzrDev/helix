//! Hash-chain verification (AUD-1).

use crate::frame::{decode_frame, Frame, FrameError, HASH_LEN};
use crate::header::{FileHeader, HeaderError};
use thiserror::Error;

/// Result of verifying an audit log file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub header: FileHeader,
    pub frames: Vec<Frame>,
    /// Head hash after the last frame (or header `prev_hash` if empty).
    pub head_hash: [u8; HASH_LEN],
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error("frame decode failed at record index {index}: {source}")]
    FrameAt {
        index: usize,
        #[source]
        source: FrameError,
    },
    #[error(
        "chain break at record index {index}: expected prev_hash {expected:02x?}, found {found:02x?}"
    )]
    ChainBreak {
        index: usize,
        expected: [u8; HASH_LEN],
        found: [u8; HASH_LEN],
    },
    #[error("trailing bytes after last frame ({0} bytes)")]
    TrailingBytes(usize),
}

impl VerifyError {
    /// Record index at which verification failed, when applicable (AUD-1).
    #[must_use]
    pub fn break_index(&self) -> Option<usize> {
        match self {
            Self::FrameAt { index, .. } | Self::ChainBreak { index, .. } => Some(*index),
            _ => None,
        }
    }
}

/// Verify the chain in `file_bytes`. On a single-byte corruption, fails at the
/// exact record index whose framing / `prev_hash` no longer matches.
pub fn verify_file(file_bytes: &[u8]) -> Result<VerifyReport, VerifyError> {
    let (header, mut offset) = FileHeader::decode_cbor(file_bytes)?;
    let mut expected_prev = header.prev_hash;
    let mut frames = Vec::new();
    let mut index = 0usize;

    while offset < file_bytes.len() {
        if file_bytes.len() - offset < 4 {
            return Err(VerifyError::TrailingBytes(file_bytes.len() - offset));
        }
        let (frame, consumed) = match decode_frame(&file_bytes[offset..]) {
            Ok(v) => v,
            Err(FrameError::Truncated) => {
                return Err(VerifyError::TrailingBytes(file_bytes.len() - offset));
            }
            Err(source) => {
                return Err(VerifyError::FrameAt { index, source });
            }
        };

        if frame.prev_hash != expected_prev {
            return Err(VerifyError::ChainBreak {
                index,
                expected: expected_prev,
                found: frame.prev_hash,
            });
        }

        expected_prev = frame.frame_hash;
        offset += consumed;
        frames.push(frame);
        index += 1;
    }

    Ok(VerifyReport {
        header,
        frames,
        head_hash: expected_prev,
    })
}
