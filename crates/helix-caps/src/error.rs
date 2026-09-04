//! Construction and attenuation errors for `helix-caps`.

use std::path::PathBuf;

use crate::Interface;

/// Why construction or attenuation was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapsError {
    /// A `files` or `dirs` entry was relative or contained `..`.
    #[error("file grant path is not canonical: {0}")]
    NonCanonicalPath(PathBuf),
    /// Duplicate path, directory root, or authority.
    #[error("duplicate grant: {0}")]
    Duplicate(String),
    /// Grants present for an interface whose bit is clear.
    #[error("grants present for unlinked interface {0:?}")]
    OrphanGrant(Interface),
    /// Requested set is not a subset of the parent.
    #[error("requested set exceeds parent: {0}")]
    Escalation(String),
    /// Method name not in the six-value `Method` enum (CAPS-12).
    #[error("unknown method: {0}")]
    UnknownMethod(String),
    /// Interface name not in the defined `Interface` variants (CAPS-12).
    #[error("unknown interface: {0}")]
    UnknownInterface(String),
    /// Path or authority is not in the snapshot intern table (ADR-008 A.3).
    #[error("not interned: {0}")]
    NotInterned(String),
}
