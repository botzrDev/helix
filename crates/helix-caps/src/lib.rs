//! `helix-caps`: the single source of truth for authority in HELIX.
//!
//! Implementation of `interfaces/helix-caps-api.rs` for M1-01 (HLX-10):
//! types, checked construction, serde `try_from`, `Interner`, `ResourceBudget`.
//! Lattice operations are deferred to HLX-11.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod budget;
mod capability;
mod error;
mod grants;
mod ids;
mod interner;
mod ulid_str;

pub use budget::ResourceBudget;
pub use capability::CapabilitySet;
pub use error::CapsError;
pub use grants::{DirGrant, FileGrant, FileMode, HostGrant, Method, MethodMask};
pub use ids::{Identity, Interface, RequestId, ToolDigest};
pub use interner::{AuthorityId, Interner, PathId};

#[cfg(test)]
mod tests;
