//! `helix-policy`: TOML policy load, validation, snapshot holder, and lookup.
//!
//! M2-01 (HLX-14): parse into [`PolicyFile`], structural pass (rules 1, 3, 4,
//! 6–12), host resolve (rules 2 and 5) into an interned [`PolicySnapshot`].
//! M2-02 (HLX-15): [`PolicyHolder`] (`ArcSwap`), [`PolicyGuard`] per request
//! tree, `policy()` lookup, sync reload, stale-snapshot age check.
//!
//! No `helix-ctl` (HLX-17). No delegation composition (HLX-16).
//!
//! Cites: `policy-format.md` §§1–4, ADR-008 A.2/A.3/C.1/C.2/C.3/E.1,
//! ADR-009 A.1/B.1/E.1.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod file;
mod fs;
mod guard;
mod ids;
mod resolve;
mod store;
mod validate;

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
pub use store::{ArtifactStore, MemoryArtifactStore};
pub use validate::{validate_structural, validate_structural_with_fs};
