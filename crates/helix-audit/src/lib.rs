//! Hash-chained, group-committed audit log (`helix-audit`).
//!
//! Encoding: RFC 8949 §4.2.1 deterministic CBOR via **minicbor** (integer keys
//! 0–11). Framing and group commit per ADR-008 D.1 / ADR-009 D.1 /
//! `interfaces/audit-record.md`.
//!
//! Caps side-file store is M3-04 / HLX-21 (not this crate revision).

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod frame;
pub mod header;
pub mod hook;
pub mod record;
pub mod tags;
pub mod verify;
pub mod writer;

pub use frame::{encode_frame, hash_frame_bytes, Frame, FrameError, HASH_LEN};
pub use header::{FileHeader, HeaderError};
pub use hook::{NoopSyncHook, SequenceStampHook, SyncHook};
pub use record::{AuditRecord, RecordError, ResourceUsage, Transition};
pub use tags::{GENESIS_PREV_HASH, HEADER_VERSION, REASON_MAX_BYTES, RECORD_VERSION};
pub use verify::{verify_file, VerifyError, VerifyReport};
pub use writer::{AuditWriter, AuditWriterRuntime, WriteReceipt, WriterError};
