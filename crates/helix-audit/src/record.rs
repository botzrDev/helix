//! `AuditRecord` and `Transition` with deterministic CBOR (RFC 8949 §4.2.1).

use crate::tags::{self, budget_usage, record_key, REASON_MAX_BYTES, RECORD_VERSION};
use minicbor::{Decoder, Encoder};
use thiserror::Error;

/// Four-uint budget/usage wire form (audit-record.md; not full `ResourceBudget`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceUsage {
    pub preempt_ticks: u64,
    pub wall_clock_ms: u64,
    pub memory_bytes: u64,
    pub output_bytes: u64,
}

impl ResourceUsage {
    #[must_use]
    pub const fn new(
        preempt_ticks: u64,
        wall_clock_ms: u64,
        memory_bytes: u64,
        output_bytes: u64,
    ) -> Self {
        Self {
            preempt_ticks,
            wall_clock_ms,
            memory_bytes,
            output_bytes,
        }
    }

    #[must_use]
    pub fn to_array(self) -> [u64; 4] {
        [
            self.preempt_ticks,
            self.wall_clock_ms,
            self.memory_bytes,
            self.output_bytes,
        ]
    }

    #[must_use]
    pub fn from_array(a: [u64; 4]) -> Self {
        Self {
            preempt_ticks: a[budget_usage::PREEMPT_TICKS],
            wall_clock_ms: a[budget_usage::WALL_CLOCK_MS],
            memory_bytes: a[budget_usage::MEMORY_BYTES],
            output_bytes: a[budget_usage::OUTPUT_BYTES],
        }
    }
}

/// Audit transition (field 5). Payloads that the state table attaches as
/// `{reason}` / `{kind}` / `{cause}` live in field 6 (`reason`), not a nested map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Transition {
    Received = tags::transition::RECEIVED,
    Authenticated = tags::transition::AUTHENTICATED,
    AuthFailed = tags::transition::AUTH_FAILED,
    Authorized = tags::transition::AUTHORIZED,
    Rejected = tags::transition::REJECTED,
    Denied = tags::transition::DENIED,
    DelegationRefused = tags::transition::DELEGATION_REFUSED,
    Granted = tags::transition::GRANTED,
    Provisioned = tags::transition::PROVISIONED,
    Running = tags::transition::RUNNING,
    Completed = tags::transition::COMPLETED,
    ToolError = tags::transition::TOOL_ERROR,
    Failed = tags::transition::FAILED,
    Killed = tags::transition::KILLED,
    Described = tags::transition::DESCRIBED,
}

impl Transition {
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this transition requires a synced (waiter) write before response.
    #[must_use]
    pub const fn is_synced(self) -> bool {
        matches!(
            self,
            Self::Granted | Self::Failed | Self::Completed | Self::ToolError | Self::Killed
        )
    }

    /// All v1 variants (AUD-5).
    #[must_use]
    pub const fn all() -> [Transition; 15] {
        [
            Self::Received,
            Self::Authenticated,
            Self::AuthFailed,
            Self::Authorized,
            Self::Rejected,
            Self::Denied,
            Self::DelegationRefused,
            Self::Granted,
            Self::Provisioned,
            Self::Running,
            Self::Completed,
            Self::ToolError,
            Self::Failed,
            Self::Killed,
            Self::Described,
        ]
    }

    pub fn from_tag(tag: u8) -> Result<Self, RecordError> {
        Ok(match tag {
            tags::transition::RECEIVED => Self::Received,
            tags::transition::AUTHENTICATED => Self::Authenticated,
            tags::transition::AUTH_FAILED => Self::AuthFailed,
            tags::transition::AUTHORIZED => Self::Authorized,
            tags::transition::REJECTED => Self::Rejected,
            tags::transition::DENIED => Self::Denied,
            tags::transition::DELEGATION_REFUSED => Self::DelegationRefused,
            tags::transition::GRANTED => Self::Granted,
            tags::transition::PROVISIONED => Self::Provisioned,
            tags::transition::RUNNING => Self::Running,
            tags::transition::COMPLETED => Self::Completed,
            tags::transition::TOOL_ERROR => Self::ToolError,
            tags::transition::FAILED => Self::Failed,
            tags::transition::KILLED => Self::Killed,
            tags::transition::DESCRIBED => Self::Described,
            other => return Err(RecordError::UnknownTransition(other)),
        })
    }
}

/// One audit log record (schema v1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub version: u8,
    pub request_id: [u8; 16],
    pub parent: Option<[u8; 16]>,
    pub identity: [u8; 32],
    pub digest: [u8; 32],
    pub transition: Transition,
    pub reason: String,
    pub caps_hash: Option<[u8; 32]>,
    pub budget: Option<ResourceUsage>,
    pub usage: Option<ResourceUsage>,
    pub wall_time_ns: u64,
    pub sequence: u64,
}

impl AuditRecord {
    /// Build a v1 record; truncates `reason` to [`REASON_MAX_BYTES`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: [u8; 16],
        parent: Option<[u8; 16]>,
        identity: [u8; 32],
        digest: [u8; 32],
        transition: Transition,
        reason: impl Into<String>,
        caps_hash: Option<[u8; 32]>,
        budget: Option<ResourceUsage>,
        usage: Option<ResourceUsage>,
        wall_time_ns: u64,
        sequence: u64,
    ) -> Self {
        let mut reason = reason.into();
        truncate_reason(&mut reason);
        Self {
            version: RECORD_VERSION,
            request_id,
            parent,
            identity,
            digest,
            transition,
            reason,
            caps_hash,
            budget,
            usage,
            wall_time_ns,
            sequence,
        }
    }

    /// Encode with RFC 8949 §4.2.1 Core Deterministic Encoding (integer keys
    /// ascending, definite lengths, shortest ints — via minicbor defaults).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, RecordError> {
        let buf = Vec::with_capacity(256);
        let mut e = Encoder::new(buf);
        // Always emit all 12 keys so re-encode is byte-identical after decode.
        e.map(12).map_err(|e| enc_err(&e))?;
        e.u8(record_key::VERSION)
            .map_err(|e| enc_err(&e))?
            .u8(self.version)
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::REQUEST_ID)
            .map_err(|e| enc_err(&e))?
            .bytes(&self.request_id)
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::PARENT).map_err(|e| enc_err(&e))?;
        match &self.parent {
            Some(p) => {
                e.bytes(p).map_err(|e| enc_err(&e))?;
            }
            None => {
                e.null().map_err(|e| enc_err(&e))?;
            }
        }
        e.u8(record_key::IDENTITY)
            .map_err(|e| enc_err(&e))?
            .bytes(&self.identity)
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::DIGEST)
            .map_err(|e| enc_err(&e))?
            .bytes(&self.digest)
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::TRANSITION)
            .map_err(|e| enc_err(&e))?
            .u8(self.transition.tag())
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::REASON)
            .map_err(|e| enc_err(&e))?
            .str(&self.reason)
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::CAPS_HASH).map_err(|e| enc_err(&e))?;
        match &self.caps_hash {
            Some(h) => {
                e.bytes(h).map_err(|e| enc_err(&e))?;
            }
            None => {
                e.null().map_err(|e| enc_err(&e))?;
            }
        }
        e.u8(record_key::BUDGET).map_err(|e| enc_err(&e))?;
        encode_usage_opt(&mut e, self.budget)?;
        e.u8(record_key::USAGE).map_err(|e| enc_err(&e))?;
        encode_usage_opt(&mut e, self.usage)?;
        e.u8(record_key::WALL_TIME_NS)
            .map_err(|e| enc_err(&e))?
            .u64(self.wall_time_ns)
            .map_err(|e| enc_err(&e))?;
        e.u8(record_key::SEQUENCE)
            .map_err(|e| enc_err(&e))?
            .u64(self.sequence)
            .map_err(|e| enc_err(&e))?;
        Ok(e.into_writer())
    }

    /// Decode a CBOR record map. Ignores unknown keys; rejects versions above
    /// [`RECORD_VERSION`].
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut d = Decoder::new(bytes);
        let len = d.map()?.ok_or(RecordError::IndefiniteMap)?;
        let mut version: Option<u8> = None;
        let mut request_id: Option<[u8; 16]> = None;
        let mut parent: Option<Option<[u8; 16]>> = None;
        let mut identity: Option<[u8; 32]> = None;
        let mut digest: Option<[u8; 32]> = None;
        let mut transition: Option<Transition> = None;
        let mut reason: Option<String> = None;
        let mut caps_hash: Option<Option<[u8; 32]>> = None;
        let mut budget: Option<Option<ResourceUsage>> = None;
        let mut usage: Option<Option<ResourceUsage>> = None;
        let mut wall_time_ns: Option<u64> = None;
        let mut sequence: Option<u64> = None;

        for _ in 0..len {
            let key = d.u8()?;
            match key {
                record_key::VERSION => {
                    version = Some(d.u8()?);
                }
                record_key::REQUEST_ID => {
                    request_id = Some(read_fixed(&mut d)?);
                }
                record_key::PARENT => {
                    parent = Some(read_opt_fixed(&mut d)?);
                }
                record_key::IDENTITY => {
                    identity = Some(read_fixed(&mut d)?);
                }
                record_key::DIGEST => {
                    digest = Some(read_fixed(&mut d)?);
                }
                record_key::TRANSITION => {
                    transition = Some(Transition::from_tag(d.u8()?)?);
                }
                record_key::REASON => {
                    let s = d.str()?.to_owned();
                    reason = Some(s);
                }
                record_key::CAPS_HASH => {
                    caps_hash = Some(read_opt_fixed(&mut d)?);
                }
                record_key::BUDGET => {
                    budget = Some(decode_usage_opt(&mut d)?);
                }
                record_key::USAGE => {
                    usage = Some(decode_usage_opt(&mut d)?);
                }
                record_key::WALL_TIME_NS => {
                    wall_time_ns = Some(d.u64()?);
                }
                record_key::SEQUENCE => {
                    sequence = Some(d.u64()?);
                }
                _ => {
                    d.skip()?;
                }
            }
        }

        let version = version.ok_or(RecordError::MissingField("version"))?;
        if version > RECORD_VERSION {
            return Err(RecordError::UnsupportedVersion(version));
        }
        let mut reason = reason.unwrap_or_default();
        truncate_reason(&mut reason);

        Ok(Self {
            version,
            request_id: request_id.ok_or(RecordError::MissingField("request_id"))?,
            parent: parent.ok_or(RecordError::MissingField("parent"))?,
            identity: identity.ok_or(RecordError::MissingField("identity"))?,
            digest: digest.ok_or(RecordError::MissingField("digest"))?,
            transition: transition.ok_or(RecordError::MissingField("transition"))?,
            reason,
            caps_hash: caps_hash.ok_or(RecordError::MissingField("caps_hash"))?,
            budget: budget.ok_or(RecordError::MissingField("budget"))?,
            usage: usage.ok_or(RecordError::MissingField("usage"))?,
            wall_time_ns: wall_time_ns.ok_or(RecordError::MissingField("wall_time_ns"))?,
            sequence: sequence.ok_or(RecordError::MissingField("sequence"))?,
        })
    }
}

fn truncate_reason(reason: &mut String) {
    if reason.len() <= REASON_MAX_BYTES {
        return;
    }
    let mut end = REASON_MAX_BYTES;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.truncate(end);
}

fn encode_usage_opt(
    e: &mut Encoder<Vec<u8>>,
    usage: Option<ResourceUsage>,
) -> Result<(), RecordError> {
    match usage {
        None => {
            e.null().map_err(|e| enc_err(&e))?;
        }
        Some(u) => {
            let a = u.to_array();
            e.array(budget_usage::LEN as u64).map_err(|e| enc_err(&e))?;
            for v in a {
                e.u64(v).map_err(|e| enc_err(&e))?;
            }
        }
    }
    Ok(())
}

fn enc_err(e: &minicbor::encode::Error<core::convert::Infallible>) -> RecordError {
    RecordError::Encode(e.to_string())
}

fn decode_usage_opt(d: &mut Decoder<'_>) -> Result<Option<ResourceUsage>, RecordError> {
    if d.datatype()? == minicbor::data::Type::Null {
        d.null()?;
        return Ok(None);
    }
    let n = d.array()?.ok_or(RecordError::IndefiniteArray)?;
    if n != budget_usage::LEN as u64 {
        return Err(RecordError::BadUsageLen(n));
    }
    let mut a = [0u64; 4];
    for slot in &mut a {
        *slot = d.u64()?;
    }
    Ok(Some(ResourceUsage::from_array(a)))
}

fn read_fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], RecordError> {
    let b = d.bytes()?;
    if b.len() != N {
        return Err(RecordError::BadBytesLen {
            expected: N,
            got: b.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(b);
    Ok(out)
}

fn read_opt_fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<Option<[u8; N]>, RecordError> {
    if d.datatype()? == minicbor::data::Type::Null {
        d.null()?;
        return Ok(None);
    }
    Ok(Some(read_fixed(d)?))
}

#[derive(Clone, Debug, Error)]
pub enum RecordError {
    #[error("cbor decode: {0}")]
    Decode(String),
    #[error("cbor encode: {0}")]
    Encode(String),
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("unsupported record version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown transition tag {0}")]
    UnknownTransition(u8),
    #[error("indefinite-length map rejected (deterministic encoding required)")]
    IndefiniteMap,
    #[error("indefinite-length array rejected")]
    IndefiniteArray,
    #[error("budget/usage array length {0}, expected 4")]
    BadUsageLen(u64),
    #[error("bytes length {got}, expected {expected}")]
    BadBytesLen { expected: usize, got: usize },
}

impl From<minicbor::decode::Error> for RecordError {
    fn from(e: minicbor::decode::Error) -> Self {
        Self::Decode(e.to_string())
    }
}
