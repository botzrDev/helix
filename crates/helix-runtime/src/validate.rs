//! Payload validation reused by `helix:delegate` (HLX-35 / M5-04).
//!
//! Thin re-export of [`helix_policy::input_schema`] so runtime and gateway share
//! one implementation (`validate::payload`).

pub use helix_policy::input_schema::{validate as payload, PathError, Schema};
