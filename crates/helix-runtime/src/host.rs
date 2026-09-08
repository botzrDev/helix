//! Per-request WASI host state for capability-linked instantiation.

use helix_caps::CapabilitySet;
use tokio_util::sync::CancellationToken;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::error::KillCause;
use crate::fs::{apply_filesystem_grants, FileGrantStages, FsGrantError};

/// Store data satisfying [`WasiView`] for bit-driven linking.
///
/// Environment variables are never populated (B10): the builder is left without
/// `env` entries. Sockets are never linked (see [`crate::link`]).
///
/// Filesystem preopens come from [`CapabilitySet`] file/dir grants (HLX-26).
///
/// Every host function clones [`Self::cancellation_token`] and
/// `tokio::select!`s against it (HLX-28 / L1). Blocking host ops use
/// [`crate::cancel::host_select`].
pub struct WasiHost {
    ctx: WasiCtx,
    table: ResourceTable,
    /// `FileGrant` staging directories; must outlive `ctx` preopens.
    #[allow(dead_code)]
    file_stages: FileGrantStages,
    /// Request-scoped cancellation (cloned into every host call).
    cancel: CancellationToken,
}

impl std::fmt::Debug for WasiHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasiHost")
            .field("file_stages", &self.file_stages.len())
            .field("cancelled", &self.cancel.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl WasiHost {
    /// Empty WASI context: no env, no preopens, null stdio; fresh cancel token.
    #[must_use]
    pub fn empty() -> Self {
        Self::empty_with_token(CancellationToken::new())
    }

    /// Empty WASI context with an explicit request token.
    #[must_use]
    pub fn empty_with_token(cancel: CancellationToken) -> Self {
        // Deliberately no `.env(...)` / `.envs(...)` — B10.
        let ctx = WasiCtxBuilder::new()
            .allow_blocking_current_thread(true)
            .build();
        Self {
            ctx,
            table: ResourceTable::new(),
            file_stages: FileGrantStages::default(),
            cancel,
        }
    }

    /// Build host state from `caps`, installing `FileGrant` / `DirGrant` preopens.
    ///
    /// When the filesystem bit is clear, no preopens are installed (even if
    /// grants were somehow present, [`CapabilitySet::new`] rejects orphans).
    ///
    /// # Errors
    ///
    /// [`FsGrantError::CapabilityDenied`] when a grant path is a symlink or
    /// cannot be opened with `O_NOFOLLOW`.
    pub fn from_capability_set(caps: &CapabilitySet) -> Result<Self, FsGrantError> {
        Self::from_capability_set_with_token(caps, CancellationToken::new())
    }

    /// Like [`Self::from_capability_set`] with an explicit request token.
    ///
    /// # Errors
    ///
    /// [`FsGrantError::CapabilityDenied`] when a grant path is a symlink or
    /// cannot be opened with `O_NOFOLLOW`.
    pub fn from_capability_set_with_token(
        caps: &CapabilitySet,
        cancel: CancellationToken,
    ) -> Result<Self, FsGrantError> {
        // Deliberately no `.env(...)` / `.envs(...)` — B10.
        let mut builder = WasiCtxBuilder::new();
        // Sync host open path for tests and request-path FS without requiring
        // a multi-thread tokio reactor for every openat.
        builder.allow_blocking_current_thread(true);
        let stages = apply_filesystem_grants(&mut builder, caps)?;
        Ok(Self {
            ctx: builder.build(),
            table: ResourceTable::new(),
            file_stages: stages,
            cancel,
        })
    }

    /// Clone of the request [`CancellationToken`] for host functions.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Replace the cancellation token (used when binding a Store to a request).
    pub fn set_cancellation_token(&mut self, cancel: CancellationToken) {
        self.cancel = cancel;
    }

    /// Kill cause preferred when this host's token is cancelled mid-call.
    ///
    /// Root requests treat cancel as wall-clock; child contexts override via
    /// [`crate::cancel::RequestLifecycle`] reason before calling host ops.
    #[must_use]
    pub fn cancel_kill_cause(&self) -> KillCause {
        KillCause::WallClock
    }
}

impl WasiView for WasiHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}
