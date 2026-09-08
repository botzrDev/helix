//! `verify --witnesses` (ADR-008 D.4 / ADR-009 D.2).
//!
//! Walk local chain, fetch each witness, compare `(sequence, head_hash)`.
//! Mismatch = **tampering** (distinct from a chain break).
//!
//! A 412 on a rewritten sequence is an integrity signal: the immutable witness
//! that caused the 412 is what verify compares; when local head at that
//! sequence differs, we report tampering without requiring a second full
//! re-hash of the witness CBOR body beyond the stored `head_hash` field.

use crate::frame::HASH_LEN;
use crate::naming::{encode_ulid_bytes, hex_encode};
use crate::verify::{verify_dir, DirVerifyReport, VerifyError};
use crate::witness::Witness;
use crate::witness_sink::{SinkError, WitnessHttpClient};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Outcome of verifying local logs against off-host witnesses.
#[derive(Clone, Debug)]
pub struct WitnessVerifyReport {
    pub local: DirVerifyReport,
    pub witnesses_checked: usize,
}

#[derive(Debug, Error)]
pub enum WitnessVerifyError {
    #[error(transparent)]
    Local(#[from] VerifyError),
    #[error(transparent)]
    Sink(#[from] SinkError),
    #[error(
        "tampering at gateway={gateway_id} file_ulid={file_ulid} sequence={sequence}: \
         witness head_hash {witness_hash} != local head_hash {local_hash}"
    )]
    Tampering {
        gateway_id: String,
        file_ulid: String,
        sequence: u64,
        witness_hash: String,
        local_hash: String,
    },
    #[error(
        "tampering (witness conflict / immutable key) at key {key}: \
         local sequence {sequence} head_hash {local_hash} disagrees with witness {witness_hash}"
    )]
    ConflictTampering {
        key: String,
        sequence: u64,
        local_hash: String,
        witness_hash: String,
    },
    #[error("witness decode for key {key}: {source}")]
    WitnessDecode {
        key: String,
        #[source]
        source: crate::witness::WitnessError,
    },
    #[error("no witness objects under prefix {0}")]
    EmptyWitnesses(String),
}

impl WitnessVerifyError {
    #[must_use]
    pub fn is_tampering(&self) -> bool {
        matches!(
            self,
            Self::Tampering { .. } | Self::ConflictTampering { .. }
        )
    }

    #[must_use]
    pub fn first_break_message(&self) -> String {
        self.to_string()
    }
}

/// Verify `dir` locally, then check witnesses listed at `client` under
/// `gateway_id/` (or all keys if `gateway_id` is empty — inferred from logs).
pub async fn verify_dir_with_witnesses(
    dir: &Path,
    client: &WitnessHttpClient,
    gateway_id: Option<&str>,
) -> Result<WitnessVerifyReport, WitnessVerifyError> {
    let local = verify_dir(dir)?;
    let gw = gateway_id
        .map(str::to_owned)
        .or_else(|| {
            local
                .files
                .first()
                .map(|f| f.report.header.gateway_id.clone())
        })
        .unwrap_or_default();

    // Map (file_ulid, sequence) -> frame_hash (head after that record).
    let mut heads: HashMap<([u8; 16], u64), [u8; HASH_LEN]> = HashMap::new();
    for f in &local.files {
        let ulid = f.report.header.file_ulid;
        for frame in &f.report.frames {
            heads.insert((ulid, frame.record.sequence), frame.frame_hash);
        }
    }

    let prefix = if gw.is_empty() {
        String::new()
    } else {
        format!("{gw}/")
    };
    let keys = client.list_keys(&prefix).await?;
    // Filter to witness sequence keys (20-digit suffix), skip retention.
    let mut witness_keys: Vec<String> = keys
        .into_iter()
        .filter(|k| is_witness_sequence_key(k))
        .collect();
    witness_keys.sort();
    if witness_keys.is_empty() {
        return Err(WitnessVerifyError::EmptyWitnesses(prefix));
    }

    let mut checked = 0usize;
    for key in &witness_keys {
        let bytes = client.get_object(key).await?;
        let w =
            Witness::decode_cbor(&bytes).map_err(|source| WitnessVerifyError::WitnessDecode {
                key: key.clone(),
                source,
            })?;
        let Some(local_hash) = heads.get(&(w.file_ulid, w.sequence)) else {
            // Witness for unknown sequence — treat as tampering signal.
            return Err(WitnessVerifyError::Tampering {
                gateway_id: w.gateway_id,
                file_ulid: encode_ulid_bytes(&w.file_ulid),
                sequence: w.sequence,
                witness_hash: hex_encode(&w.head_hash),
                local_hash: "(missing local sequence)".into(),
            });
        };
        if *local_hash != w.head_hash {
            // Prefer ConflictTampering wording when this is the classic rewrite
            // case (immutable witness vs rechained local) — surfaces the 412
            // integrity story before operators dig into raw hash bytes.
            return Err(WitnessVerifyError::ConflictTampering {
                key: key.clone(),
                sequence: w.sequence,
                local_hash: hex_encode(local_hash),
                witness_hash: hex_encode(&w.head_hash),
            });
        }
        checked += 1;
    }

    Ok(WitnessVerifyReport {
        local,
        witnesses_checked: checked,
    })
}

fn is_witness_sequence_key(key: &str) -> bool {
    let Some((_, seq)) = key.rsplit_once('/') else {
        return false;
    };
    seq.len() == 20 && seq.chars().all(|c| c.is_ascii_digit())
}

/// Fetch listing body from an arbitrary URL (used by helix-ctl).
pub async fn list_and_get_prefix(
    client: &WitnessHttpClient,
    prefix: &str,
) -> Result<Vec<(String, Vec<u8>)>, SinkError> {
    let keys = client.list_keys(prefix).await?;
    let mut out = Vec::new();
    for k in keys {
        if !is_witness_sequence_key(&k) {
            continue;
        }
        let body = client.get_object(&k).await?;
        out.push((k, body));
    }
    Ok(out)
}
