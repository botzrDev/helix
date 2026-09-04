//! Content-addressed `CapabilitySet` side-file store (ADR-008 D.2 / ADR-009 D.1).
//!
//! Path: `audit/caps/<hex sha256>.cbor`. Content is deterministic CBOR of the
//! `CapabilitySet` with paths and authorities resolved to strings (not intern
//! ids). `caps_hash = sha256(those bytes)`.
//!
//! Write-once: create-never-modify; directory does not rotate.
//!
//! ## CBOR schema (`CapabilitySet` side file)
//!
//! ADR-009 D.1 requires deterministic CBOR with string paths/authorities but
//! does **not** assign integer keys for the `CapabilitySet` map (unlike the
//! audit record). This module uses the string-keyed shape that already mirrors
//! `CapabilitySetWire` / `gateway-protocol.md` §5:
//!
//! ```text
//! {
//!   "dirs":  [ { "mode": <text>, "path": <text> }, ... ],
//!   "files": [ { "mode": <text>, "path": <text> }, ... ],
//!   "hosts": [ { "authority": <text>, "methods": [<text>, ...] }, ... ],
//!   "interfaces": [<text>, ...],
//! }
//! ```
//!
//! Top-level map keys are emitted in deterministic UTF-8 byte order
//! (`dirs` < `files` < `hosts` < `interfaces`). Nested grant maps use
//! (`mode` < `path`) and (`authority` < `methods`). Arrays of grants are
//! sorted by path / authority string so equal `CapabilitySet`s (string-wise)
//! produce identical bytes regardless of intern-table id assignment.
//!
//! Wire name tables match serde on helix-caps (`snake_case` interfaces/modes,
//! `UPPERCASE` methods).
//!
//! ## RT-13 dual hashes
//!
//! `Granted` carries one `caps_hash` (record key 7) plus inline `budget`.
//! ADR-008 D.2 / RT-13 say `DelegationRefused` / escalation records carry **both**
//! requested and available hashes. Record schema only names singular key 7
//! (`bytes32 | null`). [`CapsStore::ensure_pair`] writes both side files and
//! returns both hashes; how the second hash is placed on the CBOR record is a
//! HOLE deferred to gateway/`runtime::delegate` wiring (do not invent a key).

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use helix_caps::{
    CapabilitySet, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner, Method,
    MethodMask,
};
use minicbor::Encoder;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::frame::HASH_LEN;
use crate::naming::{caps_rel_path, hex_encode};

/// Errors from encoding, hashing, or the write-once caps store.
#[derive(Debug, Error)]
pub enum CapsStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cbor encode: {0}")]
    Encode(String),
    #[error("cbor decode: {0}")]
    Decode(String),
    #[error("path is not utf-8: {0}")]
    NonUtf8Path(String),
    #[error("intern id not resolvable (CapabilitySet missing Interner binding): {0}")]
    UnresolvedId(String),
    #[error("unknown interface wire name: {0}")]
    UnknownInterface(String),
    #[error("unknown file mode wire name: {0}")]
    UnknownMode(String),
    #[error("unknown method wire name: {0}")]
    UnknownMethod(String),
    #[error("caps side file already exists with different content for hash {hash} at {path}")]
    ContentConflict { hash: String, path: PathBuf },
    #[error("caps side file hash mismatch: expected {expected}, content hashes to {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("indefinite-length CBOR rejected")]
    Indefinite,
    #[error("unexpected CBOR structure: {0}")]
    Structure(String),
}

/// Write-once store under `{audit_dir}/caps/`.
#[derive(Debug)]
pub struct CapsStore {
    /// Absolute or relative audit directory (parent of `caps/`).
    audit_dir: PathBuf,
    /// Hashes written (or observed) this process.
    seen: HashSet<[u8; HASH_LEN]>,
}

impl CapsStore {
    /// Open (or create) the caps directory under `audit_dir`.
    pub fn open(audit_dir: impl Into<PathBuf>) -> Result<Self, CapsStoreError> {
        let audit_dir = audit_dir.into();
        let caps = audit_dir.join("caps");
        fs::create_dir_all(&caps)?;
        Ok(Self {
            audit_dir,
            seen: HashSet::new(),
        })
    }

    /// Audit directory this store was opened on.
    #[must_use]
    pub fn audit_dir(&self) -> &Path {
        &self.audit_dir
    }

    /// Absolute path for a caps hash: `{audit_dir}/caps/<hex>.cbor`.
    #[must_use]
    pub fn path_for(&self, hash: &[u8; HASH_LEN]) -> PathBuf {
        self.audit_dir.join(caps_rel_path(hash))
    }

    /// Deterministic CBOR bytes for `set` (paths/authorities as strings).
    pub fn encode(set: &CapabilitySet) -> Result<Vec<u8>, CapsStoreError> {
        encode_capability_set(set)
    }

    /// `sha256(encode(set))`.
    pub fn hash(set: &CapabilitySet) -> Result<[u8; HASH_LEN], CapsStoreError> {
        let bytes = encode_capability_set(set)?;
        Ok(sha256_32(&bytes))
    }

    /// Decode side-file CBOR into a [`CapabilitySet`] (re-interns paths).
    pub fn decode(bytes: &[u8]) -> Result<CapabilitySet, CapsStoreError> {
        decode_capability_set(bytes)
    }

    /// Ensure `set` is stored; return its content hash.
    ///
    /// First time a hash is seen in this process: create the file (never
    /// modify). If the file already exists with identical bytes (e.g. after
    /// restart), treat as success. Conflicting content is an error.
    pub fn ensure(&mut self, set: &CapabilitySet) -> Result<[u8; HASH_LEN], CapsStoreError> {
        let bytes = encode_capability_set(set)?;
        let hash = sha256_32(&bytes);
        self.ensure_bytes(&hash, &bytes)?;
        Ok(hash)
    }

    /// Write both requested and available side files (RT-13). Returns
    /// `(requested_hash, available_hash)`.
    ///
    /// HOLE: record schema key 7 is a single `caps_hash`; callers must decide
    /// how to attach the second hash until an ADR amendment names it.
    pub fn ensure_pair(
        &mut self,
        requested: &CapabilitySet,
        available: &CapabilitySet,
    ) -> Result<([u8; HASH_LEN], [u8; HASH_LEN]), CapsStoreError> {
        let req = self.ensure(requested)?;
        let avail = self.ensure(available)?;
        Ok((req, avail))
    }

    /// Write precomputed CBOR bytes under `hash` (create-never-modify).
    pub fn ensure_bytes(
        &mut self,
        hash: &[u8; HASH_LEN],
        bytes: &[u8],
    ) -> Result<(), CapsStoreError> {
        let content_hash = sha256_32(bytes);
        if &content_hash != hash {
            return Err(CapsStoreError::HashMismatch {
                expected: hex_encode(hash),
                actual: hex_encode(&content_hash),
            });
        }
        if self.seen.contains(hash) {
            return Ok(());
        }
        let path = self.path_for(hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::read(&path)?;
                if existing.as_slice() != bytes {
                    return Err(CapsStoreError::ContentConflict {
                        hash: hex_encode(hash),
                        path,
                    });
                }
            }
            Err(e) => return Err(CapsStoreError::Io(e)),
        }
        self.seen.insert(*hash);
        Ok(())
    }

    /// True if this process has already ensured `hash` (not a disk probe).
    #[must_use]
    pub fn seen_in_process(&self, hash: &[u8; HASH_LEN]) -> bool {
        self.seen.contains(hash)
    }
}

/// Encode `set` as deterministic CBOR for the caps side file.
pub fn encode_capability_set(set: &CapabilitySet) -> Result<Vec<u8>, CapsStoreError> {
    let interner = set.interner();
    if (!set.files().is_empty() || !set.dirs().is_empty() || !set.hosts().is_empty())
        && interner.is_empty()
    {
        return Err(CapsStoreError::UnresolvedId(
            "grants present but Interner is empty; bind via with_interner or wire build".into(),
        ));
    }

    let mut files: Vec<(String, FileMode)> = set
        .files()
        .iter()
        .copied()
        .map(|g| {
            let p = resolve_path(interner, g)?;
            Ok((p, g.mode()))
        })
        .collect::<Result<_, CapsStoreError>>()?;
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut dirs: Vec<(String, FileMode)> = set
        .dirs()
        .iter()
        .copied()
        .map(|g| {
            let p = resolve_dir(interner, g)?;
            Ok((p, g.mode()))
        })
        .collect::<Result<_, CapsStoreError>>()?;
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hosts: Vec<(String, Vec<&'static str>)> = set
        .hosts()
        .iter()
        .copied()
        .map(|g| {
            let a = resolve_authority(interner, g);
            let methods = g.methods().methods().into_iter().map(method_name).collect();
            (a, methods)
        })
        .collect();
    hosts.sort_by(|a, b| a.0.cmp(&b.0));

    let mut interfaces: Vec<&'static str> = Vec::new();
    for i in [
        Interface::Stdio,
        Interface::Clocks,
        Interface::Random,
        Interface::Filesystem,
        Interface::HttpOutbound,
    ] {
        if set.has(i) {
            interfaces.push(interface_name(i));
        }
    }

    let buf = Vec::with_capacity(256);
    let mut e = Encoder::new(buf);
    // Always emit all four keys (dirs, files, hosts, interfaces) in sorted order.
    e.map(4).map_err(|e| enc_err(&e))?;

    e.str("dirs").map_err(|e| enc_err(&e))?;
    e.array(u64::try_from(dirs.len()).unwrap_or(u64::MAX))
        .map_err(|e| enc_err(&e))?;
    for (path, mode) in &dirs {
        encode_path_mode(&mut e, path, *mode)?;
    }

    e.str("files").map_err(|e| enc_err(&e))?;
    e.array(u64::try_from(files.len()).unwrap_or(u64::MAX))
        .map_err(|e| enc_err(&e))?;
    for (path, mode) in &files {
        encode_path_mode(&mut e, path, *mode)?;
    }

    e.str("hosts").map_err(|e| enc_err(&e))?;
    e.array(u64::try_from(hosts.len()).unwrap_or(u64::MAX))
        .map_err(|e| enc_err(&e))?;
    for (authority, methods) in &hosts {
        e.map(2).map_err(|e| enc_err(&e))?;
        e.str("authority")
            .map_err(|e| enc_err(&e))?
            .str(authority)
            .map_err(|e| enc_err(&e))?;
        e.str("methods").map_err(|e| enc_err(&e))?;
        e.array(u64::try_from(methods.len()).unwrap_or(u64::MAX))
            .map_err(|e| enc_err(&e))?;
        for m in methods {
            e.str(m).map_err(|e| enc_err(&e))?;
        }
    }

    e.str("interfaces").map_err(|e| enc_err(&e))?;
    e.array(u64::try_from(interfaces.len()).unwrap_or(u64::MAX))
        .map_err(|e| enc_err(&e))?;
    for name in &interfaces {
        e.str(name).map_err(|e| enc_err(&e))?;
    }

    Ok(e.into_writer())
}

fn encode_path_mode(
    e: &mut Encoder<Vec<u8>>,
    path: &str,
    mode: FileMode,
) -> Result<(), CapsStoreError> {
    e.map(2).map_err(|e| enc_err(&e))?;
    e.str("mode")
        .map_err(|e| enc_err(&e))?
        .str(mode_name(mode))
        .map_err(|e| enc_err(&e))?;
    e.str("path")
        .map_err(|e| enc_err(&e))?
        .str(path)
        .map_err(|e| enc_err(&e))?;
    Ok(())
}

/// Decode caps side-file CBOR into a [`CapabilitySet`].
pub fn decode_capability_set(bytes: &[u8]) -> Result<CapabilitySet, CapsStoreError> {
    use minicbor::Decoder;

    let mut d = Decoder::new(bytes);
    let n = d
        .map()
        .map_err(|e| CapsStoreError::Decode(e.to_string()))?
        .ok_or(CapsStoreError::Indefinite)?;

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut files: Vec<(String, FileMode)> = Vec::new();
    let mut dirs: Vec<(String, FileMode)> = Vec::new();
    let mut hosts: Vec<(String, Vec<Method>)> = Vec::new();

    for _ in 0..n {
        let key = d
            .str()
            .map_err(|e| CapsStoreError::Decode(e.to_string()))?
            .to_owned();
        match key.as_str() {
            "interfaces" => {
                let len = d
                    .array()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                    .ok_or(CapsStoreError::Indefinite)?;
                for _ in 0..len {
                    let name = d.str().map_err(|e| CapsStoreError::Decode(e.to_string()))?;
                    interfaces.push(parse_interface(name)?);
                }
            }
            "files" => {
                let len = d
                    .array()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                    .ok_or(CapsStoreError::Indefinite)?;
                for _ in 0..len {
                    files.push(decode_path_mode(&mut d)?);
                }
            }
            "dirs" => {
                let len = d
                    .array()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                    .ok_or(CapsStoreError::Indefinite)?;
                for _ in 0..len {
                    dirs.push(decode_path_mode(&mut d)?);
                }
            }
            "hosts" => {
                let len = d
                    .array()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                    .ok_or(CapsStoreError::Indefinite)?;
                for _ in 0..len {
                    hosts.push(decode_host(&mut d)?);
                }
            }
            other => {
                // Ignore unknown keys (forward compatible), but skip value.
                let _ = other;
                d.skip()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?;
            }
        }
    }

    if d.position() != bytes.len() {
        return Err(CapsStoreError::Structure(format!(
            "trailing {} bytes",
            bytes.len() - d.position()
        )));
    }

    let mut interner = Interner::new();
    let file_grants: Vec<FileGrant> = files
        .iter()
        .map(|(p, m)| FileGrant::new(interner.intern_path(Path::new(p)), *m))
        .collect();
    let dir_grants: Vec<DirGrant> = dirs
        .iter()
        .map(|(p, m)| DirGrant::new(interner.intern_path(Path::new(p)), *m))
        .collect();
    let host_grants: Vec<HostGrant> = hosts
        .iter()
        .map(|(a, methods)| HostGrant::new(interner.intern_authority(a), MethodMask::new(methods)))
        .collect();

    let set = CapabilitySet::new(&interfaces, file_grants, dir_grants, host_grants)
        .map_err(|e| CapsStoreError::Structure(e.to_string()))?;
    Ok(set.with_interner(interner))
}

fn decode_path_mode(d: &mut minicbor::Decoder<'_>) -> Result<(String, FileMode), CapsStoreError> {
    let n = d
        .map()
        .map_err(|e| CapsStoreError::Decode(e.to_string()))?
        .ok_or(CapsStoreError::Indefinite)?;
    let mut path: Option<String> = None;
    let mut mode: Option<FileMode> = None;
    for _ in 0..n {
        let key = d.str().map_err(|e| CapsStoreError::Decode(e.to_string()))?;
        match key {
            "path" => {
                path = Some(
                    d.str()
                        .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                        .to_owned(),
                );
            }
            "mode" => {
                let m = d.str().map_err(|e| CapsStoreError::Decode(e.to_string()))?;
                mode = Some(parse_mode(m)?);
            }
            _ => {
                d.skip()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?;
            }
        }
    }
    Ok((
        path.ok_or_else(|| CapsStoreError::Structure("grant missing path".into()))?,
        mode.ok_or_else(|| CapsStoreError::Structure("grant missing mode".into()))?,
    ))
}

fn decode_host(d: &mut minicbor::Decoder<'_>) -> Result<(String, Vec<Method>), CapsStoreError> {
    let n = d
        .map()
        .map_err(|e| CapsStoreError::Decode(e.to_string()))?
        .ok_or(CapsStoreError::Indefinite)?;
    let mut authority: Option<String> = None;
    let mut methods: Option<Vec<Method>> = None;
    for _ in 0..n {
        let key = d.str().map_err(|e| CapsStoreError::Decode(e.to_string()))?;
        match key {
            "authority" => {
                authority = Some(
                    d.str()
                        .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                        .to_owned(),
                );
            }
            "methods" => {
                let len = d
                    .array()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?
                    .ok_or(CapsStoreError::Indefinite)?;
                let mut m = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
                for _ in 0..len {
                    let name = d.str().map_err(|e| CapsStoreError::Decode(e.to_string()))?;
                    m.push(parse_method(name)?);
                }
                methods = Some(m);
            }
            _ => {
                d.skip()
                    .map_err(|e| CapsStoreError::Decode(e.to_string()))?;
            }
        }
    }
    Ok((
        authority.ok_or_else(|| CapsStoreError::Structure("host missing authority".into()))?,
        methods.ok_or_else(|| CapsStoreError::Structure("host missing methods".into()))?,
    ))
}

/// JSON view of a decoded `CapabilitySet` (for `helix-ctl audit caps`).
#[must_use]
pub fn capability_set_to_json(set: &CapabilitySet) -> serde_json::Value {
    use serde_json::{json, Value};

    let interner = set.interner();
    let interfaces: Vec<Value> = [
        Interface::Stdio,
        Interface::Clocks,
        Interface::Random,
        Interface::Filesystem,
        Interface::HttpOutbound,
    ]
    .into_iter()
    .filter(|i| set.has(*i))
    .map(|i| Value::String(interface_name(i).to_owned()))
    .collect();

    let files: Vec<Value> = set
        .files()
        .iter()
        .filter_map(|g| {
            let path = interner.path(g.path()).to_str()?.to_owned();
            Some(json!({ "path": path, "mode": mode_name(g.mode()) }))
        })
        .collect();
    let dirs: Vec<Value> = set
        .dirs()
        .iter()
        .filter_map(|g| {
            let path = interner.path(g.root()).to_str()?.to_owned();
            Some(json!({ "path": path, "mode": mode_name(g.mode()) }))
        })
        .collect();
    let hosts: Vec<Value> = set
        .hosts()
        .iter()
        .map(|g| {
            let authority = interner.authority(g.authority()).to_owned();
            let methods: Vec<Value> = g
                .methods()
                .methods()
                .into_iter()
                .map(|m| Value::String(method_name(m).to_owned()))
                .collect();
            json!({ "authority": authority, "methods": methods })
        })
        .collect();

    json!({
        "interfaces": interfaces,
        "files": files,
        "dirs": dirs,
        "hosts": hosts,
    })
}

#[must_use]
pub fn sha256_32(bytes: &[u8]) -> [u8; HASH_LEN] {
    let dig = Sha256::digest(bytes);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&dig);
    out
}

fn resolve_path(interner: &Interner, g: FileGrant) -> Result<String, CapsStoreError> {
    let p = interner.path(g.path());
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| CapsStoreError::NonUtf8Path(p.display().to_string()))
}

fn resolve_dir(interner: &Interner, g: DirGrant) -> Result<String, CapsStoreError> {
    let p = interner.path(g.root());
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| CapsStoreError::NonUtf8Path(p.display().to_string()))
}

fn resolve_authority(interner: &Interner, g: HostGrant) -> String {
    interner.authority(g.authority()).to_owned()
}

fn interface_name(i: Interface) -> &'static str {
    match i {
        Interface::Stdio => "stdio",
        Interface::Clocks => "clocks",
        Interface::Random => "random",
        Interface::Filesystem => "filesystem",
        Interface::HttpOutbound => "http_outbound",
    }
}

fn mode_name(m: FileMode) -> &'static str {
    match m {
        FileMode::Read => "read",
        FileMode::ReadWrite => "read_write",
    }
}

fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
    }
}

fn parse_interface(name: &str) -> Result<Interface, CapsStoreError> {
    Ok(match name {
        "stdio" => Interface::Stdio,
        "clocks" => Interface::Clocks,
        "random" => Interface::Random,
        "filesystem" => Interface::Filesystem,
        "http_outbound" => Interface::HttpOutbound,
        other => return Err(CapsStoreError::UnknownInterface(other.to_owned())),
    })
}

fn parse_mode(name: &str) -> Result<FileMode, CapsStoreError> {
    Ok(match name {
        "read" => FileMode::Read,
        "read_write" => FileMode::ReadWrite,
        other => return Err(CapsStoreError::UnknownMode(other.to_owned())),
    })
}

fn parse_method(name: &str) -> Result<Method, CapsStoreError> {
    Ok(match name {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        "PUT" => Method::Put,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        other => return Err(CapsStoreError::UnknownMethod(other.to_owned())),
    })
}

fn enc_err(e: &minicbor::encode::Error<core::convert::Infallible>) -> CapsStoreError {
    CapsStoreError::Encode(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_caps::{FileGrant, FileMode, HostGrant, Interface, Interner, Method, MethodMask};

    fn sample_set() -> CapabilitySet {
        let mut interner = Interner::new();
        let p1 = interner.intern_path(Path::new("/srv/data/a.csv"));
        let p2 = interner.intern_path(Path::new("/srv/inbox"));
        let a1 = interner.intern_authority("api.example.com:443");
        CapabilitySet::new(
            &[
                Interface::Filesystem,
                Interface::HttpOutbound,
                Interface::Stdio,
            ],
            vec![FileGrant::new(p1, FileMode::Read)],
            vec![DirGrant::new(p2, FileMode::ReadWrite)],
            vec![HostGrant::new(
                a1,
                MethodMask::new(&[Method::Get, Method::Post]),
            )],
        )
        .unwrap()
        .with_interner(interner)
    }

    #[test]
    fn equal_sets_same_bytes_and_hash() {
        let a = sample_set();
        // Rebuild with different intern order / ids.
        let mut interner = Interner::new();
        let _noise = interner.intern_path(Path::new("/unrelated"));
        let a1 = interner.intern_authority("api.example.com:443");
        let p2 = interner.intern_path(Path::new("/srv/inbox"));
        let p1 = interner.intern_path(Path::new("/srv/data/a.csv"));
        let b = CapabilitySet::new(
            &[
                Interface::Stdio,
                Interface::Filesystem,
                Interface::HttpOutbound,
            ],
            vec![FileGrant::new(p1, FileMode::Read)],
            vec![DirGrant::new(p2, FileMode::ReadWrite)],
            vec![HostGrant::new(
                a1,
                MethodMask::new(&[Method::Post, Method::Get]),
            )],
        )
        .unwrap()
        .with_interner(interner);

        assert_eq!(a, b);
        let ea = encode_capability_set(&a).unwrap();
        let eb = encode_capability_set(&b).unwrap();
        assert_eq!(ea, eb, "equal sets must produce identical CBOR");
        assert_eq!(sha256_32(&ea), sha256_32(&eb));
    }

    #[test]
    fn round_trip_byte_identical() {
        let set = sample_set();
        let bytes = encode_capability_set(&set).unwrap();
        let decoded = decode_capability_set(&bytes).unwrap();
        assert_eq!(decoded, set);
        let re = encode_capability_set(&decoded).unwrap();
        assert_eq!(re, bytes);
    }

    #[test]
    fn empty_set_stable() {
        let a = CapabilitySet::EMPTY;
        let b = CapabilitySet::EMPTY;
        let ea = encode_capability_set(&a).unwrap();
        let eb = encode_capability_set(&b).unwrap();
        assert_eq!(ea, eb);
        // Map with four empty arrays — not 0xa0.
        assert_ne!(ea, vec![0xa0]);
        let decoded = decode_capability_set(&ea).unwrap();
        assert_eq!(decoded, CapabilitySet::EMPTY);
    }
}
