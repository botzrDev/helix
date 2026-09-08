//! Per-request WASI host state for capability-linked instantiation.

use helix_caps::{CapabilitySet, Interface, MethodMask};
use tokio_util::sync::CancellationToken;
use wasmtime::component::ResourceTable;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::{HttpResult, WasiHttpCtx, WasiHttpView};

use crate::error::KillCause;
use crate::fs::{apply_filesystem_grants, FileGrantStages, FsGrantError};
use crate::http::{send_request_with_grants, HostGrantTable};

/// Store data satisfying [`WasiView`] / [`WasiHttpView`] for bit-driven linking.
///
/// Environment variables are never populated (B10): the builder is left without
/// `env` entries. Sockets are never linked (see [`crate::link`]).
///
/// Filesystem preopens come from [`CapabilitySet`] file/dir grants (HLX-26).
/// HTTP host grants are resolved into [`HostGrantTable`] (HLX-30).
///
/// Every host function clones [`Self::cancellation_token`] and
/// `tokio::select!`s against it (HLX-28 / L1). Blocking host ops use
/// [`crate::cancel::host_select`] / [`crate::http::send_request_with_grants`].
pub struct WasiHost {
    ctx: WasiCtx,
    table: ResourceTable,
    http: WasiHttpCtx,
    hosts: HostGrantTable,
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
            .field("host_grants", &self.hosts.entries().len())
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
            http: WasiHttpCtx::new(),
            hosts: HostGrantTable::empty(),
            file_stages: FileGrantStages::default(),
            cancel,
        }
    }

    /// Build host state from `caps`, installing FS preopens and HTTP grants.
    ///
    /// # Errors
    ///
    /// [`FsGrantError::CapabilityDenied`] when a grant path is a symlink or
    /// cannot be opened with `O_NOFOLLOW`.
    /// [`FsGrantError::MissingInternerPath`] when host/file ids cannot be resolved.
    pub fn from_capability_set(caps: &CapabilitySet) -> Result<Self, FsGrantError> {
        Self::from_capability_set_with_token(caps, CancellationToken::new())
    }

    /// Like [`Self::from_capability_set`] with an explicit request token.
    ///
    /// # Errors
    ///
    /// Same as [`Self::from_capability_set`].
    pub fn from_capability_set_with_token(
        caps: &CapabilitySet,
        cancel: CancellationToken,
    ) -> Result<Self, FsGrantError> {
        // Deliberately no `.env(...)` / `.envs(...)` — B10.
        let mut builder = WasiCtxBuilder::new();
        builder.allow_blocking_current_thread(true);
        let stages = apply_filesystem_grants(&mut builder, caps)?;
        let hosts = resolve_host_grants(caps)?;
        Ok(Self {
            ctx: builder.build(),
            table: ResourceTable::new(),
            http: WasiHttpCtx::new(),
            hosts,
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

    /// Resolved HTTP host grants for this sandbox.
    #[must_use]
    pub fn host_grants(&self) -> &HostGrantTable {
        &self.hosts
    }

    /// Kill cause preferred when this host's token is cancelled mid-call.
    #[must_use]
    pub fn cancel_kill_cause(&self) -> KillCause {
        KillCause::WallClock
    }
}

fn resolve_host_grants(caps: &CapabilitySet) -> Result<HostGrantTable, FsGrantError> {
    if !caps.has(Interface::HttpOutbound) || caps.hosts().is_empty() {
        return Ok(HostGrantTable::empty());
    }
    let intern = caps.interner();
    if intern.is_empty() {
        return Err(FsGrantError::MissingInternerPath);
    }
    let mut entries: Vec<(String, MethodMask)> = Vec::with_capacity(caps.hosts().len());
    for g in caps.hosts() {
        let authority = intern.authority(g.authority()).to_ascii_lowercase();
        entries.push((authority, g.methods()));
    }
    Ok(HostGrantTable::from_entries(entries))
}

impl WasiView for WasiHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for WasiHost {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http
    }

    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        send_request_with_grants(&self.hosts, &self.cancel, request, config)
    }
}
