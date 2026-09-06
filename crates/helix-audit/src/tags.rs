//! Provisional integer tags owned by M3 (HLX-18).
//!
//! ADR-009 D.1 / `interfaces/audit-record.md` assign record map keys 0–11 but
//! leave transition small-int tags and budget/usage array element names
//! unnamed. This module is the provisional assignment; do not invent beyond
//! what AUD-5 round-trip of every variant/field needs. Later M3 tickets may
//! amend with a one-line ADR note.

/// CBOR map keys for `AuditRecord` (ADR-009 D.1 — normative).
pub mod record_key {
    pub const VERSION: u8 = 0;
    pub const REQUEST_ID: u8 = 1;
    pub const PARENT: u8 = 2;
    pub const IDENTITY: u8 = 3;
    pub const DIGEST: u8 = 4;
    pub const TRANSITION: u8 = 5;
    pub const REASON: u8 = 6;
    pub const CAPS_HASH: u8 = 7;
    pub const BUDGET: u8 = 8;
    pub const USAGE: u8 = 9;
    pub const WALL_TIME_NS: u8 = 10;
    pub const SEQUENCE: u8 = 11;
}

/// File header CBOR map keys.
///
/// HOLE: ADR-009 D.1 names `version`, `file_ulid`, `gateway_id`, `prev_hash`
/// but does not assign integer keys, CBOR types, or widths. Provisional ints
/// below; M3 owns the assignment until an amendment pins them.
pub mod header_key {
    pub const VERSION: u8 = 0;
    pub const FILE_ULID: u8 = 1;
    pub const GATEWAY_ID: u8 = 2;
    pub const PREV_HASH: u8 = 3;
}

/// Transition small-int tags (field 5).
///
/// HOLE: name→integer map not in ADR-008 F.1 or ADR-009 D.1; `state-machine.md`
/// says helix-audit (M3) assigns them. Order follows the invoke table then
/// `Described`.
pub mod transition {
    pub const RECEIVED: u8 = 0;
    pub const AUTHENTICATED: u8 = 1;
    pub const AUTH_FAILED: u8 = 2;
    pub const AUTHORIZED: u8 = 3;
    pub const REJECTED: u8 = 4;
    pub const DENIED: u8 = 5;
    pub const DELEGATION_REFUSED: u8 = 6;
    pub const GRANTED: u8 = 7;
    pub const PROVISIONED: u8 = 8;
    pub const RUNNING: u8 = 9;
    pub const COMPLETED: u8 = 10;
    pub const TOOL_ERROR: u8 = 11;
    pub const FAILED: u8 = 12;
    pub const KILLED: u8 = 13;
    pub const DESCRIBED: u8 = 14;
}

/// Budget / usage array element indices (fields 8 and 9).
///
/// HOLE: ADR-009 D.1 says "array of 4 uints" without naming elements.
/// Adjacent WIT `resource-usage` order is used: preempt-ticks, wall-clock-ms,
/// memory-bytes, output-bytes. Tree-bound fields on `ResourceBudget` are NOT
/// in this array (audit-record.md).
pub mod budget_usage {
    pub const PREEMPT_TICKS: usize = 0;
    pub const WALL_CLOCK_MS: usize = 1;
    pub const MEMORY_BYTES: usize = 2;
    pub const OUTPUT_BYTES: usize = 3;
    pub const LEN: usize = 4;
}

/// Maximum UTF-8 byte length of `reason` (ADR-008 D.2).
pub const REASON_MAX_BYTES: usize = 256;

/// Current record schema version.
pub const RECORD_VERSION: u8 = 1;

/// Current file header version.
pub const HEADER_VERSION: u8 = 1;

/// Genesis / first-file `prev_hash` (32 zero bytes). Ticket + ADR-005 genesis.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];
