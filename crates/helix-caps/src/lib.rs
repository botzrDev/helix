//! `helix-caps`: the single source of truth for authority in HELIX.
//!
//! Implementation of `interfaces/helix-caps-api.rs`. Doc comments on public
//! items match that contract word for word where applicable (HLX-12 / M1-03).
//!
//! M1-01 (HLX-10): types, checked construction, serde `try_from`, `Interner`,
//! `ResourceBudget`. M1-02 (HLX-11): lattice operations `is_subset_of`,
//! `attenuate`, `meet`, `has`, `EMPTY`. M1-03 (HLX-12): Miri in CI (ST-5) and
//! docs.rs-quality rustdoc. M1-04 (HLX-13): CAPS-11 through CAPS-15.
//!
//! Lattice vs non-lattice: [`CapabilitySet`] (with [`DirGrant`] prefix rules)
//! forms the authority lattice. [`ResourceBudget`] is a sibling ceiling and
//! is not a lattice element. [`Interner`] is snapshot infrastructure for
//! path/authority ids, not a lattice element.

#![forbid(unsafe_code)]
#![deny(warnings, missing_docs)]

mod budget;
mod capability;
mod error;
mod grants;
mod ids;
mod interner;
mod lattice;
mod ulid_str;

pub use budget::ResourceBudget;
pub use capability::CapabilitySet;
pub use error::CapsError;
pub use grants::{DirGrant, FileGrant, FileMode, HostGrant, Method, MethodMask};
pub use ids::{Identity, Interface, RequestId, ToolDigest};
pub use interner::{AuthorityId, Interner, PathId};

#[cfg(test)]
mod tests;
