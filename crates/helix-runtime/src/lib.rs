//! HELIX wasmtime runtime: engine, artifact cache, and `InstancePre` pool (M4-01 / HLX-24).
//!
//! Compilation never happens on the request path (ADR-006). Artifacts are
//! serialized at `helix-ctl tool register` and deserialized at startup.
//!
//! **M4-01 linker template:** `InstancePre` values are built against a linker
//! that stubs unknown imports as traps (`define_unknown_imports_as_traps`).
//! Capability-aware linking (`link(&CapabilitySet)`) is HLX-25. WASI host
//! implementations are later M4 tickets.
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
pub use pool::{InstancePool, PooledPre};
pub use register::{
    format_register_output, register_wasm, reregister_all, RegisterOutcome, ReregisterReport,
};
pub use signature::{read_signature, ToolSignatureInfo};

/// Metric name: histogram of instantiate latency (seconds).
pub const METRIC_INSTANTIATE_SECONDS: &str = "helix_instantiate_seconds";

/// Metric name: gauge of live pooled instances.
pub const METRIC_POOL_IN_USE: &str = "helix_pool_in_use";
