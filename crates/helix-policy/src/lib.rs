//! `helix-policy`: TOML policy load, validation, snapshot holder, and lookup.
//!
//! M2-01 (HLX-14): parse into [`PolicyFile`], structural pass (rules 1, 3, 4,
//! 6–12), host resolve (rules 2 and 5) into an interned [`PolicySnapshot`].
//! M2-02 (HLX-15): [`PolicyHolder`] (`ArcSwap`), [`PolicyGuard`] per request
//! tree, `policy()` lookup, sync reload, stale-snapshot age check.
//! M2-03 (HLX-16): pure [`effective`] composition — caps attenuation, budget
//! `is_within`/`min`, depth/fan-out checks, wire interning against the guard.
//! M2-04 (HLX-17): operator helpers for `helix-ctl policy check` / `explain` /
//! `reload` ([`tooling`]).
//!
//! No `runtime::delegate` / wasmtime (M4-08).
//!
//! Cites: `policy-format.md` §§1–5, ADR-008 A.2/A.3/A.4/C.1/C.2/C.3/E.1,
//! ADR-009 A.1/A.3/B.1/E.1.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod effective;
mod error;
mod file;
mod fs;
mod guard;
mod ids;
mod resolve;
mod store;
mod tooling;
mod validate;

pub use effective::{
    check_depth, check_fanout, effective_budget, effective_caps, intern_against,
    intern_against_guard, DelegationRefuse,
};
pub use error::PolicyError;
pub use file::{
    BudgetTable, DirGrantTable, FileGrantTable, GrantTable, HostGrantTable, PolicyFile,
};
pub use fs::{Fs, FsError, MapFs, PanicFs, PathKind, StdFs};
pub use guard::{
    AliasDigestError, PolicyGuard, PolicyHolder, DEFAULT_MAX_SNAPSHOT_AGE_S, STALE_SNAPSHOT_REASON,
};
pub use ids::{encode_thumbprint, parse_identity_thumbprint, parse_tool_digest};
pub use resolve::{resolve_host, PolicySnapshot, ResolvedGrant};
pub use store::{ArtifactStore, DirArtifactStore, MemoryArtifactStore};
pub use tooling::{
    caps_budget_wire_json, check_policy, explain_grant_json, format_policy_errors,
    load_snapshot_for_explain, send_sighup, CheckPasses, CheckReport, GrantListing, PathGrantLine,
};
pub use validate::{validate_structural, validate_structural_with_fs};
