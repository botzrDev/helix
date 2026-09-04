//! Per-request WASI host state for capability-linked instantiation.

use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Store data satisfying [`WasiView`] for bit-driven linking.
///
/// Environment variables are never populated (B10): the builder is left without
/// `env` entries. Sockets are never linked (see [`crate::link`]).
pub struct WasiHost {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl std::fmt::Debug for WasiHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WasiHost { .. }")
    }
}

impl WasiHost {
    /// Empty WASI context: no env, no preopens, null stdio.
    #[must_use]
    pub fn empty() -> Self {
        // Deliberately no `.env(...)` / `.envs(...)` — B10.
        let ctx = WasiCtxBuilder::new().build();
        Self {
            ctx,
            table: ResourceTable::new(),
        }
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
