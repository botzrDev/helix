//! Hash-chained, group-committed audit log (`helix-audit`).
//!
//! Encoding: RFC 8949 §4.2.1 deterministic CBOR via **minicbor** (integer keys
//! 0–11). Framing and group commit per ADR-008 D.1 / ADR-009 D.1 /
//! `interfaces/audit-record.md`. Rotation with header `prev_hash` carry-forward
//! (M3-02 / HLX-19). `OTel` tail exporter (M3-03 / HLX-20, ADR-005).
//!
//! Caps side-file store (M3-04 / HLX-21): content-addressed
//! `caps/<hex>.cbor` via [`caps::CapsStore`]. Verify checks presence and that
//! `sha256(side file) == caps_hash`.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod caps;
pub mod export;
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

pub use caps::{
    capability_set_to_json, decode_capability_set, encode_capability_set, sha256_32, CapsStore,
    CapsStoreError,
};
pub use export::{
    AuditExporterRuntime, ExportError, ExportMetrics, ExportSink, ExportedEvent,
    ExportedInvocation, OtelExportSink, RecordingSink, WitnessAttrs, INVOCATION_SPAN_NAME,
    WITNESS_SPAN_NAME,
};
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
