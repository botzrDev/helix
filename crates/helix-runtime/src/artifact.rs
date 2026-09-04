//! Artifact cache: serialize / deserialize compiled components (ADR-006).
//!
//! Layout under `runtime.artifact_dir` (0700):
//! - `<hex>.wasm` — original component bytes (for `reregister-all`)
//! - `<hex>.cwasm` — `Component::serialize` output (version-bound)
//!
//! Matches [`helix_policy::DirArtifactStore`] path conventions.

#![allow(unsafe_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use helix_caps::ToolDigest;
use sha2::{Digest, Sha256};
use wasmtime::component::{Component, Linker};
use wasmtime::Engine;

use crate::error::RuntimeError;
use crate::pool::PooledPre;
use crate::signature::{self, ToolSignatureInfo};

/// Paths for one digest in the artifact directory.
#[derive(Debug, Clone)]
pub struct ArtifactPaths {
    /// Original `.wasm` component bytes.
    pub wasm: PathBuf,
    /// Serialized `.cwasm` precompiled artifact.
    pub cwasm: PathBuf,
}

/// A component loaded from the cache plus its `InstancePre` (M4-01 template).
#[derive(Debug)]
pub struct LoadedArtifact {
    /// Content digest of the original wasm bytes.
    pub digest: ToolDigest,
    /// Signature metadata read at load (best-effort; may be absent).
    pub signature: Option<ToolSignatureInfo>,
    /// Pre-instantiation against the M4-01 trapping-import linker.
    pub pre: PooledPre,
}

/// Hex-lowercase of a digest's 32 bytes.
#[must_use]
pub fn digest_hex(digest: &ToolDigest) -> String {
    let mut out = String::with_capacity(64);
    for b in digest.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `ToolDigest = sha256(component bytes)` (ADR-002).
#[must_use]
pub fn digest_of_bytes(bytes: &[u8]) -> ToolDigest {
    let hash = Sha256::digest(bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    ToolDigest::from_bytes(arr)
}

/// Path pair for `digest` under `artifact_dir`.
#[must_use]
pub fn artifact_paths(artifact_dir: &Path, digest: &ToolDigest) -> ArtifactPaths {
    let hex = digest_hex(digest);
    ArtifactPaths {
        wasm: artifact_dir.join(format!("{hex}.wasm")),
        cwasm: artifact_dir.join(format!("{hex}.cwasm")),
    }
}

/// Ensure `dir` exists with mode `0700`.
///
/// # Errors
///
/// I/O failures creating or chmod'ing the directory.
pub fn ensure_artifact_dir(dir: &Path) -> Result<(), RuntimeError> {
    fs::create_dir_all(dir).map_err(|source| RuntimeError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(dir, perms).map_err(|source| RuntimeError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Compile `wasm_bytes`, serialize, and write `{hex}.wasm` + `{hex}.cwasm`.
///
/// # Errors
///
/// Compile, serialize, or I/O failures.
pub fn write_artifact(
    engine: &Engine,
    artifact_dir: &Path,
    wasm_bytes: &[u8],
) -> Result<(ToolDigest, u128, Component), RuntimeError> {
    ensure_artifact_dir(artifact_dir)?;
    let digest = digest_of_bytes(wasm_bytes);
    let paths = artifact_paths(artifact_dir, &digest);

    let start = Instant::now();
    let component = Component::new(engine, wasm_bytes).map_err(RuntimeError::from)?;
    let elapsed_ms = start.elapsed().as_millis();
    let serialized = component.serialize().map_err(RuntimeError::from)?;

    write_mode_0600(&paths.wasm, wasm_bytes)?;
    write_mode_0600(&paths.cwasm, &serialized)?;

    Ok((digest, elapsed_ms, component))
}

fn write_mode_0600(path: &Path, bytes: &[u8]) -> Result<(), RuntimeError> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut file = opts.open(path).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Deserialize a precompiled component — **the single permitted `unsafe`**.
///
/// # Safety
///
/// `bytes` must be the output of [`Component::serialize`] (or
/// `Engine::precompile_component`) for a compatible wasmtime / engine config.
/// Callers only pass bytes read from Helix's artifact directory written by
/// [`write_artifact`] / `reregister-all`. A version-mismatched artifact returns
/// [`Err`] with a clear message (RT-11); it must never be deferred to request time.
///
/// # Errors
///
/// Version mismatch, corrupt ELF, or other deserialize failures.
pub fn deserialize_component(engine: &Engine, bytes: &[u8]) -> Result<Component, RuntimeError> {
    // SAFETY: bytes originate from Component::serialize under Helix control;
    // wasmtime validates the image header and rejects incompatible versions.
    let component = unsafe { Component::deserialize(engine, bytes) }.map_err(|err| {
        RuntimeError::Wasmtime(format!(
            "failed to load precompiled artifact at startup (re-run `helix-ctl tool reregister-all` after a wasmtime upgrade): {err}"
        ))
    })?;
    Ok(component)
}

/// Build an `InstancePre` against the M4-01 linker template (trapping stubs).
///
/// # Errors
///
/// Linker / type-check failures.
pub fn build_instance_pre(
    engine: &Engine,
    component: &Component,
) -> Result<PooledPre, RuntimeError> {
    let mut linker = Linker::new(engine);
    linker
        .define_unknown_imports_as_traps(component)
        .map_err(RuntimeError::from)?;
    let pre = linker
        .instantiate_pre(component)
        .map_err(RuntimeError::from)?;
    Ok(PooledPre::new(pre))
}

/// Load every `*.cwasm` in `artifact_dir`, deserialize, build `InstancePre`s.
///
/// Fails closed on the first bad artifact (RT-11).
///
/// # Errors
///
/// I/O or deserialize / link failures.
pub fn load_artifact_dir(
    engine: &Engine,
    artifact_dir: &Path,
) -> Result<Vec<LoadedArtifact>, RuntimeError> {
    if !artifact_dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries = fs::read_dir(artifact_dir).map_err(|source| RuntimeError::Io {
        path: artifact_dir.to_path_buf(),
        source,
    })?;
    let mut cwasm_files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|ext| ext == "cwasm")
        })
        .collect();
    cwasm_files.sort();

    for path in cwasm_files {
        let bytes = fs::read(&path).map_err(|source| RuntimeError::Io {
            path: path.clone(),
            source,
        })?;
        let hex_stem = path.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            RuntimeError::Artifact(format!("bad artifact name: {}", path.display()))
        })?;
        let digest = parse_hex_digest(hex_stem)?;
        let component = deserialize_component(engine, &bytes)?;
        let pre = build_instance_pre(engine, &component)?;
        let signature = signature::read_signature(engine, &pre).ok();
        out.push(LoadedArtifact {
            digest,
            signature,
            pre,
        });
    }
    Ok(out)
}

fn parse_hex_digest(hex: &str) -> Result<ToolDigest, RuntimeError> {
    if hex.len() != 64 {
        return Err(RuntimeError::Artifact(format!(
            "artifact stem must be 64 hex chars, got {hex:?}"
        )));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| RuntimeError::Artifact(format!("invalid hex in artifact stem: {hex}")))?;
        bytes[i] = u8::from_str_radix(s, 16)
            .map_err(|_| RuntimeError::Artifact(format!("invalid hex in artifact stem: {hex}")))?;
    }
    Ok(ToolDigest::from_bytes(bytes))
}
