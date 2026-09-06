//! HELIX wasmtime runtime: engine, artifact cache, `InstancePre` pool,
//! bit-driven capability linking, filesystem grants, resource limits,
//! cancellation, HTTP outbound, soak/pool accounting, and `helix:delegate`
//! (M4-01…M4-08 / HLX-24…HLX-31) plus payload schema validation reused from
//! the gateway path (HLX-35).
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
//! **Limits (HLX-27):** [`limits::HelixLimiter`] caps linear memory and table
//! growth; [`preempt::EpochTicker`] advances the engine epoch every 1 ms;
//! [`bounded::BoundedWriter`] enforces `output_bytes` (S4); [`invoke`] owns the
//! fresh Store, epoch deadline, and terminal-record drop guard (D3).
//!
//! **Cancellation (HLX-28):** [`cancel::spawn_cancellable`] is the sole
//! `tokio::spawn` site (ST-2 / ADR-003). Every host call clones a request
//! [`tokio_util::sync::CancellationToken`]; wall-clock cancel yields
//! [`error::KillCause::WallClock`] (`-32011`); dropping
//! [`cancel::RequestLifecycle`] aborts children with
//! [`error::KillCause::ParentDropped`] (`-32014`). Child `JoinSet` scaffolding
//! awaits `helix:delegate` (HLX-31).
//!
//! **HTTP outbound (HLX-30):** [`http`] enforces `HostGrant` authority + method
//! before any socket opens (`HTTP-request-denied`); outbound calls select against
//! the request token so tarpits become [`error::KillCause::WallClock`].
//!
//! **Soak / pool accounting (HLX-29):** [`pool::InstancePool::acquire`] holds a
//! slot for each invocation (`helix_pool_in_use`); RT-10 asserts 10,000 sequential
//! `trivial.wasm` runs via [`invoke::run_limited_pooled`] return the gauge to zero
//! with ≤ 5 % RSS growth and no FD growth. BENCH-7 (100k at c=64) is deferred to
//! M7-01.
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
//!
//! BENCH-8 (preempt kill latency p99 ≤ 12 ms at `preempt_ticks = 10`) is
//! informational until M7-01. BENCH-7 (RSS after 100k at c=64) is deferred to
//! M7-01 (RT-10 covers the 10k sequential gate).

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod admission;
pub mod artifact;
pub mod bounded;
pub mod cancel;
pub mod config;
pub mod delegate;
pub mod engine;
pub mod error;
pub mod fs;
pub mod host;
pub mod http;
pub mod invoke;
pub mod limits;
pub mod link;
pub mod pool;
pub mod preempt;
pub mod register;
pub mod signature;
pub mod validate;

pub use admission::{IdentityPermit, IdentitySemaphore};
pub use artifact::{
    artifact_paths, digest_hex, digest_of_bytes, load_artifact_dir, write_artifact, ArtifactPaths,
    LoadedArtifact,
};
pub use bounded::{BoundedWriter, BoundedWriterError};
pub use cancel::{
    host_select, record_parent_dropped_kill, record_wall_clock_kill, run_with_wall_clock,
    spawn_cancellable, stub_blocking_host, ChildJoinSet, RequestLifecycle,
    METRIC_KILL_PARENT_DROPPED, METRIC_KILL_WALL_CLOCK,
};
pub use config::RuntimeConfig;
pub use delegate::{
    add_delegate_to_linker, host_delegate, ChildAuditRecord, DelegateError, DelegateHostView,
    DelegationAudit, DelegationCtx, DelegationSuccess, HostDelegationRequest, HostToolRef,
    MapToolResolver, NopDelegationAudit, RecordingDelegationAudit, RefusalRecord, ToolResolver,
    METRIC_CHILD_STORE_CREATED,
};
pub use engine::build_engine;
pub use error::{InvokeError, KillCause, RuntimeError, Usage};
pub use fs::{
    apply_filesystem_grants, guest_preopen_name, open_dir_nofollow, open_file_nofollow,
    FileGrantStages, FsGrantError,
};
pub use host::WasiHost;
pub use http::{
    check_host_grant, helix_method, host_http_get_status, normalize_authority,
    send_request_with_grants, HostGrantTable, HostHttpError, WALL_CLOCK_TRAP_MSG,
};
pub use invoke::{
    deliver_output, invoke, invoke_pooled, invoke_with_cancel, invoke_with_cancel_pooled,
    preempt_deadline_ticks, run_limited, run_limited_pooled, InvokeHost, InvokeSuccess, NopHook,
    RecordingHook, TerminalGuard, TerminalHook, TerminalKind, TerminalRecord, METRIC_KILL_MEMORY,
    METRIC_KILL_OUTPUT,
};
pub use limits::{HelixLimiter, DEFAULT_TABLE_ELEMENTS};
pub use link::{link, link_with_names, linked_names, provision_pre, provision_pre_with_delegate};
pub use pool::{InstancePool, PoolGuard, PooledPre};
pub use preempt::{
    default_preempt_ticks, record_preempt_kill, EpochTicker, EPOCH_TICK_MS, METRIC_KILL_EPOCH,
    METRIC_KILL_PREEMPT,
};
pub use register::{
    format_register_output, register_wasm, reregister_all, RegisterOutcome, ReregisterReport,
};
pub use signature::{read_signature, ToolSignatureInfo};
pub use validate::{
    payload as validate_payload, PathError as PayloadPathError, Schema as PayloadSchema,
};

/// Metric name: histogram of instantiate latency (seconds).
pub const METRIC_INSTANTIATE_SECONDS: &str = "helix_instantiate_seconds";

/// Metric name: gauge of live pooled instances.
pub const METRIC_POOL_IN_USE: &str = "helix_pool_in_use";
