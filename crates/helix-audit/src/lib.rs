//! Hash-chained, group-committed audit log (`helix-audit`).
//!
//! Encoding: RFC 8949 §4.2.1 deterministic CBOR via **minicbor** (integer keys
//! 0–11). Framing and group commit per ADR-008 D.1 / ADR-009 D.1 /
//! `interfaces/audit-record.md`. Rotation with header `prev_hash` carry-forward
//! (M3-02 / HLX-19).
//!
//! Caps side-file **writer/store** is M3-04 / HLX-21. This crate verifies that
//! referenced `caps/<hex>.cbor` files exist; fixtures may stub them.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod frame;
pub mod header;
pub mod hook;
pub mod json_out;
pub mod naming;
pub mod record;
pub mod retention;
pub mod tags;
pub mod verify;
pub mod writer;

pub use frame::{encode_frame, hash_frame_bytes, Frame, FrameError, HASH_LEN};
pub use header::{FileHeader, HeaderError};
pub use hook::{NoopSyncHook, SequenceStampHook, SyncHook};
pub use json_out::{cbor_to_json, record_to_json, transition_name, JsonOutError};
pub use naming::{
    caps_rel_path, decode_ulid_str, encode_ulid_bytes, hex_decode_32, hex_encode, log_file_name,
    parse_log_file_name, NamingError,
};
pub use record::{AuditRecord, RecordError, ResourceUsage, Transition};
pub use retention::{RetentionEntry, RetentionError};
pub use tags::{GENESIS_PREV_HASH, HEADER_VERSION, REASON_MAX_BYTES, RECORD_VERSION};
pub use verify::{
    verify_dir, verify_file, DirFileReport, DirVerifyReport, VerifyError, VerifyReport,
};
pub use writer::{
    default_ulid_source, AuditWriter, AuditWriterRuntime, UlidSource, WriteReceipt, WriterError,
};
