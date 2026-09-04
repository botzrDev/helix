//! Per-request WASI host state for capability-linked instantiation.

use helix_caps::CapabilitySet;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::fs::{apply_filesystem_grants, FileGrantStages, FsGrantError};

/// Store data satisfying [`WasiView`] for bit-driven linking.
///
/// Environment variables are never populated (B10): the builder is left without
/// `env` entries. Sockets are never linked (see [`crate::link`]).
///
/// Filesystem preopens come from [`CapabilitySet`] file/dir grants (HLX-26).
pub struct WasiHost {
    ctx: WasiCtx,
    table: ResourceTable,
    /// `FileGrant` staging directories; must outlive `ctx` preopens.
    #[allow(dead_code)]
    file_stages: FileGrantStages,
}

impl std::fmt::Debug for WasiHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasiHost")
            .field("file_stages", &self.file_stages.len())
            .finish_non_exhaustive()
    }
}

impl WasiHost {
    /// Empty WASI context: no env, no preopens, null stdio.
    #[must_use]
    pub fn empty() -> Self {
        // Deliberately no `.env(...)` / `.envs(...)` — B10.
        let ctx = WasiCtxBuilder::new()
            .allow_blocking_current_thread(true)
            .build();
        Self {
            ctx,
            table: ResourceTable::new(),
            file_stages: FileGrantStages::default(),
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
        })
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
