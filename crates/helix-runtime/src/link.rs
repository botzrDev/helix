//! Bit-driven `link(&CapabilitySet) -> Linker` (HLX-25 / M4-02).
//!
//! Pure projection of [`CapabilitySet`] into a wasmtime component [`Linker`]:
//! interfaces whose bit is clear are **not** added. Instantiating a component
//! that imports an unlinked interface fails closed at provision (`-32004`).
//!
//! # Safety property S1
//!
//! A sandbox never holds a capability absent from its set. Enforced by
//! construction; asserted with `debug_assert!` that every linked WASI
//! interface name maps to a set bit.
//!
//! # Never linked
//!
//! - `wasi:cli/environment` — no `Interface::Environment` (ADR-008 A.5).
//! - `wasi:sockets/*` — never added (`unlinked.wasm` fixtures).
//!
//! # Host shapes
//!
//! - **Filesystem** (bit set): `wasi:filesystem` linked; preopens installed by
//!   [`crate::host::WasiHost::from_capability_set`] (HLX-26 / cap-std, `O_NOFOLLOW`).
//! - **HTTP outbound** (bit set): `wasi:http` via wasmtime-wasi-http with
//!   [`crate::http`] `HostGrant` enforcement (HLX-30).

use helix_caps::{CapabilitySet, Interface};
use wasmtime::component::{HasData, Linker};
use wasmtime::Engine;
use wasmtime_wasi::p2::bindings::sync;
use wasmtime_wasi::p2::bindings::{cli, clocks, filesystem, random};
use wasmtime_wasi::random::WasiRandomCtx;
use wasmtime_wasi::{WasiCtxView, WasiView};

use crate::error::RuntimeError;

/// Marker so generated `add_to_linker` receives [`WasiCtxView`].
struct HelixWasi;

impl HasData for HelixWasi {
    type Data<'a> = WasiCtxView<'a>;
}

struct HelixRandom;

impl HasData for HelixRandom {
    type Data<'a> = &'a mut WasiRandomCtx;
}

struct HelixIo;

impl HasData for HelixIo {
    type Data<'a> = &'a mut wasmtime::component::ResourceTable;
}

/// Pure projection: WASI instance names `link` binds for `caps` (RT-12).
///
/// Semver suffixes are omitted; wasmtime resolves compatible versions.
#[must_use]
pub fn linked_names(caps: &CapabilitySet) -> Vec<&'static str> {
    let mut out = Vec::new();
    if caps.has(Interface::Stdio) {
        out.extend([
            "wasi:cli/stdin",
            "wasi:cli/stdout",
            "wasi:cli/stderr",
            "wasi:cli/exit",
        ]);
    }
    if caps.has(Interface::Clocks) {
        out.extend(["wasi:clocks/wall-clock", "wasi:clocks/monotonic-clock"]);
    }
    if caps.has(Interface::Random) {
        out.extend([
            "wasi:random/random",
            "wasi:random/insecure",
            "wasi:random/insecure-seed",
        ]);
    }
    if caps.has(Interface::Filesystem) {
        out.extend(["wasi:filesystem/types", "wasi:filesystem/preopens"]);
    }
    if caps.has(Interface::HttpOutbound) {
        out.extend(["wasi:http/types", "wasi:http/outgoing-handler"]);
    }
    out
}

fn assert_s1(caps: &CapabilitySet, names: &[&str]) {
    for name in names {
        if let Some(bit) = interface_for_name(name) {
            debug_assert!(
                caps.has(bit),
                "S1 violated: linked {name} requires {bit:?} bit"
            );
        }
    }
    debug_assert!(
        !names.iter().any(|n| n.contains("environment")),
        "environment must never be linked (ADR-008 A.5)"
    );
    debug_assert!(
        !names.iter().any(|n| n.starts_with("wasi:sockets/")),
        "sockets must never be linked"
    );
}

fn interface_for_name(name: &str) -> Option<Interface> {
    if name.starts_with("wasi:cli/stdin")
        || name.starts_with("wasi:cli/stdout")
        || name.starts_with("wasi:cli/stderr")
        || name.starts_with("wasi:cli/exit")
    {
        Some(Interface::Stdio)
    } else if name.starts_with("wasi:clocks/") {
        Some(Interface::Clocks)
    } else if name.starts_with("wasi:random/") {
        Some(Interface::Random)
    } else if name.starts_with("wasi:filesystem/") {
        Some(Interface::Filesystem)
    } else if name.starts_with("wasi:http/") {
        Some(Interface::HttpOutbound)
    } else {
        None
    }
}

/// Build a component [`Linker`] from `caps` only (pure function of the set).
///
/// # Errors
///
/// Returns [`RuntimeError::Provision`] when a host binding fails to register.
pub fn link<T>(engine: &Engine, caps: &CapabilitySet) -> Result<Linker<T>, RuntimeError>
where
    T: WasiView + wasmtime_wasi_http::WasiHttpView + 'static,
{
    let (linker, _) = link_with_names(engine, caps)?;
    Ok(linker)
}

/// Like [`link`], also returning bound WASI instance names (RT-12).
///
/// # Errors
///
/// Returns [`RuntimeError::Provision`] when a host binding fails to register.
pub fn link_with_names<T>(
    engine: &Engine,
    caps: &CapabilitySet,
) -> Result<(Linker<T>, Vec<&'static str>), RuntimeError>
where
    T: WasiView + wasmtime_wasi_http::WasiHttpView + 'static,
{
    let names = linked_names(caps);
    assert_s1(caps, &names);

    let mut linker = Linker::<T>::new(engine);

    if caps.has(Interface::Stdio)
        || caps.has(Interface::Filesystem)
        || caps.has(Interface::HttpOutbound)
    {
        add_io_sync(&mut linker)?;
    }
    if caps.has(Interface::Stdio) {
        add_stdio(&mut linker)?;
    }
    if caps.has(Interface::Clocks) {
        add_clocks(&mut linker)?;
    }
    if caps.has(Interface::Random) {
        add_random(&mut linker)?;
    }
    if caps.has(Interface::Filesystem) {
        add_filesystem(&mut linker)?;
    }
    if caps.has(Interface::HttpOutbound) {
        add_http(&mut linker)?;
    }

    assert_s1(caps, &names);
    Ok((linker, names))
}

/// `instantiate_pre` against [`link`]; map failures to provision (`-32004`).
///
/// # Errors
///
/// [`RuntimeError::Provision`] with [`RuntimeError::GATEWAY_CODE`].
pub fn provision_pre<T>(
    engine: &Engine,
    component: &wasmtime::component::Component,
    caps: &CapabilitySet,
) -> Result<wasmtime::component::InstancePre<T>, RuntimeError>
where
    T: WasiView + wasmtime_wasi_http::WasiHttpView + 'static,
{
    let linker = link::<T>(engine, caps)?;
    linker.instantiate_pre(component).map_err(|err| {
        RuntimeError::provision(format!(
            "unlinked or mismatched import during capability projection: {err}"
        ))
    })
}

fn add_io_sync<T: WasiView>(linker: &mut Linker<T>) -> Result<(), RuntimeError> {
    wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker::<T, HelixIo>(linker, |t| {
        t.ctx().table
    })
    .map_err(|e| RuntimeError::provision(format!("link wasi:io/error: {e}")))?;
    sync::io::poll::add_to_linker::<T, HelixIo>(linker, |t| t.ctx().table)
        .map_err(|e| RuntimeError::provision(format!("link wasi:io/poll: {e}")))?;
    sync::io::streams::add_to_linker::<T, HelixIo>(linker, |t| t.ctx().table)
        .map_err(|e| RuntimeError::provision(format!("link wasi:io/streams: {e}")))?;
    Ok(())
}

fn add_stdio<T: WasiView>(linker: &mut Linker<T>) -> Result<(), RuntimeError> {
    let options = cli::exit::LinkOptions::default();
    cli::exit::add_to_linker::<T, HelixWasi>(linker, &options, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link wasi:cli/exit: {e}")))?;
    cli::stdin::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link wasi:cli/stdin: {e}")))?;
    cli::stdout::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link wasi:cli/stdout: {e}")))?;
    cli::stderr::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link wasi:cli/stderr: {e}")))?;
    Ok(())
}

fn add_clocks<T: WasiView>(linker: &mut Linker<T>) -> Result<(), RuntimeError> {
    clocks::wall_clock::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link wall-clock: {e}")))?;
    clocks::monotonic_clock::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link monotonic-clock: {e}")))?;
    Ok(())
}

fn add_random<T: WasiView>(linker: &mut Linker<T>) -> Result<(), RuntimeError> {
    random::random::add_to_linker::<T, HelixRandom>(linker, |t| t.ctx().ctx.random())
        .map_err(|e| RuntimeError::provision(format!("link wasi:random/random: {e}")))?;
    random::insecure::add_to_linker::<T, HelixRandom>(linker, |t| t.ctx().ctx.random())
        .map_err(|e| RuntimeError::provision(format!("link wasi:random/insecure: {e}")))?;
    random::insecure_seed::add_to_linker::<T, HelixRandom>(linker, |t| t.ctx().ctx.random())
        .map_err(|e| RuntimeError::provision(format!("link wasi:random/insecure-seed: {e}")))?;
    Ok(())
}

fn add_filesystem<T: WasiView>(linker: &mut Linker<T>) -> Result<(), RuntimeError> {
    filesystem::preopens::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link filesystem/preopens: {e}")))?;
    sync::filesystem::types::add_to_linker::<T, HelixWasi>(linker, T::ctx)
        .map_err(|e| RuntimeError::provision(format!("link filesystem/types: {e}")))?;
    Ok(())
}

fn add_http<T>(linker: &mut Linker<T>) -> Result<(), RuntimeError>
where
    T: wasmtime_wasi_http::WasiHttpView + 'static,
{
    wasmtime_wasi_http::add_only_http_to_linker_sync(linker)
        .map_err(|e| RuntimeError::provision(format!("link wasi:http: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use helix_caps::CapabilitySet;

    #[test]
    fn empty_caps_links_nothing() {
        assert!(linked_names(&CapabilitySet::EMPTY).is_empty());
    }

    #[test]
    fn stdio_bit_excludes_http_sockets_env() {
        let caps = CapabilitySet::new(&[Interface::Stdio], vec![], vec![], vec![]).unwrap();
        let names = linked_names(&caps);
        assert!(names.contains(&"wasi:cli/stdin"));
        assert!(!names.iter().any(|n| n.starts_with("wasi:http/")));
        assert!(!names.iter().any(|n| n.starts_with("wasi:sockets/")));
        assert!(!names.iter().any(|n| n.contains("environment")));
    }
}
