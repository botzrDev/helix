//! HELIX wasmtime runtime: engine, artifact cache, `InstancePre` pool,
//! bit-driven capability linking, and filesystem grants
//! (M4-01 / HLX-24, M4-02 / HLX-25, M4-03 / HLX-26).
//!
//! Compilation never happens on the request path (ADR-006). Artifacts are
//! serialized at `helix-ctl tool register` and deserialized at startup.
//!
//! **Capability linking (HLX-25):** [`link::link`] projects a
//! [`helix_caps::CapabilitySet`] into a wasmtime [`wasmtime::component::Linker`].
//! Interfaces whose bit is clear are not added; unlinked imports fail at
//! provision with [`error::RuntimeError::Provision`] (`-32004`).
//!
//! **Filesystem grants (HLX-26):** [`fs`] opens each `FileGrant` / `DirGrant`
//! with `O_NOFOLLOW` and installs cap-std preopens on [`host::WasiHost`]. Host
//! path strings never cross into the guest.
//!
//! **Registration linker template (HLX-24):** `InstancePre` values used for
//! `signature` at register/load are still built with
//! `define_unknown_imports_as_traps` so registration does not require a
//! request-scoped capability set. Request-path provision uses [`link::link`].
//!
//! Safety (ST-4 / ADR-006): this crate is the workspace exception to
//! `#![forbid(unsafe_code)]`. The single permitted `unsafe` site is
//! [`artifact::deserialize_component`] (`Component::deserialize`), confined to
//! `artifact.rs` (module-level allow for the deserialize call).

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod artifact;
pub mod config;
pub mod engine;
pub mod error;
pub mod fs;
pub mod host;
pub mod link;
pub mod pool;
pub mod register;
pub mod signature;

pub use artifact::{
    artifact_paths, digest_hex, digest_of_bytes, load_artifact_dir, write_artifact, ArtifactPaths,
    LoadedArtifact,
};
pub use config::RuntimeConfig;
pub use engine::build_engine;
pub use error::RuntimeError;
pub use fs::{
    apply_filesystem_grants, guest_preopen_name, open_dir_nofollow, open_file_nofollow,
    FileGrantStages, FsGrantError,
};
pub use host::WasiHost;
pub use link::{link, link_with_names, linked_names, provision_pre};
pub use pool::{InstancePool, PooledPre};
pub use register::{
    format_register_output, register_wasm, reregister_all, RegisterOutcome, ReregisterReport,
};
pub use signature::{read_signature, ToolSignatureInfo};

/// Metric name: histogram of instantiate latency (seconds).
pub const METRIC_INSTANTIATE_SECONDS: &str = "helix_instantiate_seconds";

/// Metric name: gauge of live pooled instances.
pub const METRIC_POOL_IN_USE: &str = "helix_pool_in_use";
