//! Hash-chain verification (AUD-1, AUD-3).

use crate::caps::sha256_32;
use crate::frame::{decode_frame, Frame, FrameError, HASH_LEN};
use crate::header::{FileHeader, HeaderError};
use crate::naming::{caps_rel_path, hex_encode, parse_log_file_name};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Result of verifying an audit log file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub header: FileHeader,
    pub frames: Vec<Frame>,
    /// Head hash after the last frame (or header `prev_hash` if empty).
    pub head_hash: [u8; HASH_LEN],
}

/// One file within a directory verification walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirFileReport {
    pub path: PathBuf,
    pub report: VerifyReport,
}

/// Result of verifying an audit directory (AUD-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirVerifyReport {
    pub files: Vec<DirFileReport>,
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
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no helix-*.log files in {0}")]
    EmptyDir(PathBuf),
    #[error(
        "rotation boundary break between {prev_file} and {next_file}: \
         expected header prev_hash {expected}, found {found}"
    )]
    BoundaryBreak {
        prev_file: PathBuf,
        next_file: PathBuf,
        expected: String,
        found: String,
    },
    #[error("missing caps side file for hash {caps_hash} (referenced by {log_file} record {index}): expected {expected_path}")]
    MissingCaps {
        caps_hash: String,
        log_file: PathBuf,
        index: usize,
        expected_path: PathBuf,
    },
    #[error(
        "caps side file hash mismatch for {caps_hash} (referenced by {log_file} record {index}):          file {path} content hashes to {actual}"
    )]
    CapsHashMismatch {
        caps_hash: String,
        log_file: PathBuf,
        index: usize,
        path: PathBuf,
        actual: String,
    },
}

impl VerifyError {
    /// Record index at which verification failed, when applicable (AUD-1).
    #[must_use]
    pub fn break_index(&self) -> Option<usize> {
        match self {
            Self::FrameAt { index, .. }
            | Self::ChainBreak { index, .. }
            | Self::MissingCaps { index, .. }
            | Self::CapsHashMismatch { index, .. } => Some(*index),
            _ => None,
        }
    }

    /// Operator-facing one-line summary of the first break.
    #[must_use]
    pub fn first_break_message(&self) -> String {
        self.to_string()
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

/// Walk `dir` for `helix-*.log` in ULID order; verify each chain and the
/// carry-forward `prev_hash` across file boundaries. Also checks that every
/// referenced `caps_hash` has a side file under `dir/caps/<hex>.cbor`
/// whose contents hash to that digest.
pub fn verify_dir(dir: &Path) -> Result<DirVerifyReport, VerifyError> {
    let mut entries = list_log_files(dir)?;
    if entries.is_empty() {
        return Err(VerifyError::EmptyDir(dir.to_path_buf()));
    }
    // ULID Crockford strings sort lexicographically in time order.
    entries.sort_by(|a, b| a.1.cmp(&b.1));

    let mut files = Vec::with_capacity(entries.len());
    let mut prev_head: Option<([u8; HASH_LEN], PathBuf)> = None;

    for (path, _ulid) in entries {
        let bytes = fs::read(&path)?;
        let report = verify_file(&bytes)?;

        if let Some((expected, prev_path)) = prev_head {
            if report.header.prev_hash != expected {
                return Err(VerifyError::BoundaryBreak {
                    prev_file: prev_path,
                    next_file: path.clone(),
                    expected: hex_encode(&expected),
                    found: hex_encode(&report.header.prev_hash),
                });
            }
        }

        for (index, frame) in report.frames.iter().enumerate() {
            if let Some(hash) = frame.record.caps_hash {
                let rel = caps_rel_path(&hash);
                let caps_path = dir.join(&rel);
                if !caps_path.is_file() {
                    return Err(VerifyError::MissingCaps {
                        caps_hash: hex_encode(&hash),
                        log_file: path.clone(),
                        index,
                        expected_path: caps_path,
                    });
                }
                let bytes = fs::read(&caps_path)?;
                let actual = sha256_32(&bytes);
                if actual != hash {
                    return Err(VerifyError::CapsHashMismatch {
                        caps_hash: hex_encode(&hash),
                        log_file: path.clone(),
                        index,
                        path: caps_path,
                        actual: hex_encode(&actual),
                    });
                }
            }
        }

        let head = report.head_hash;
        prev_head = Some((head, path.clone()));
        files.push(DirFileReport { path, report });
    }

    Ok(DirVerifyReport { files })
}

fn list_log_files(dir: &Path) -> Result<Vec<(PathBuf, String)>, VerifyError> {
    let mut out = Vec::new();
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if parse_log_file_name(name).is_some() {
            out.push((ent.path(), name.to_owned()));
        }
    }
    Ok(out)
}
