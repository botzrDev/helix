//! Filesystem grants via cap-std / `O_NOFOLLOW` (HLX-26 / M4-03).
//!
//! # Model (ADR-008 A.2, PRD §5.3)
//!
//! - **`DirGrant`**: one cap-std preopen at `canonical_root`. Guest paths resolve
//!   inside that root; `..` and escaping symlinks are refused at open (cap-std).
//! - **`FileGrant`**: open the file with `openat` relative to its parent
//!   descriptor using `O_NOFOLLOW` (via cap-std `FollowSymlinks::No`); expose a
//!   private staging directory containing only that file as a preopen under the
//!   documented guest parent path so siblings are invisible (RT-2).
//!
//! Host path strings never appear in the guest: preopen names are the
//! documented guest paths derived from grant paths; the guest only sees those
//! names and relative opens beneath them.
//!
//! # Open-time enforcement
//!
//! Grant roots/files are opened with `O_NOFOLLOW` before installation. A symlink
//! at the grant path is [`FsGrantError::CapabilityDenied`] (RT-3).
//!
//! wasmtime-wasi 36 only accepts ambient path preopens (`preopened_dir`), so
//! after the `O_NOFOLLOW` preflight we re-open via that API. The narrow TOCTOU
//! window is documented as a hole vs installing the already-opened FD.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use helix_caps::{CapabilitySet, FileMode, Interface};
use tempfile::TempDir;
use thiserror::Error;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

/// Errors while projecting filesystem grants into a WASI context.
#[derive(Debug, Error)]
pub enum FsGrantError {
    /// Open refused: symlink at grant path, missing path, or mode mismatch.
    ///
    /// Tools should map this to `invoke-error::capability-denied`.
    #[error("capability denied: {reason}")]
    CapabilityDenied {
        /// Human-readable denial reason (operator log / tool message).
        reason: String,
    },

    /// I/O while opening or staging a grant.
    #[error("filesystem grant io at {path}: {source}")]
    Io {
        /// Path involved.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// Capability set is missing path strings (empty interner).
    #[error("capability set has no interner entry for filesystem grant id")]
    MissingInternerPath,

    /// Filesystem interface bit clear while grants were present.
    #[error("filesystem interface bit is clear")]
    FilesystemBitClear,
}

impl FsGrantError {
    /// True when the tool should surface `capability-denied`.
    #[must_use]
    pub const fn is_capability_denied(&self) -> bool {
        matches!(self, Self::CapabilityDenied { .. })
    }

    fn denied(reason: impl Into<String>) -> Self {
        Self::CapabilityDenied {
            reason: reason.into(),
        }
    }

    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Staging directories that must outlive the [`wasmtime_wasi::WasiCtx`] preopens.
#[derive(Debug, Default)]
pub struct FileGrantStages {
    dirs: Vec<TempDir>,
}

impl FileGrantStages {
    /// Number of live `FileGrant` staging directories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.dirs.len()
    }

    /// True when no `FileGrant` staging dirs are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty()
    }
}

/// Guest path under which a grant is preopened (documented to tool authors).
///
/// - `DirGrant`: the canonical root itself (absolute path string).
/// - `FileGrant`: the parent of the canonical file path (absolute path string);
///   the basename is the only entry inside the staging preopen.
#[must_use]
pub fn guest_preopen_name(host_grant_path: &Path, is_file: bool) -> PathBuf {
    if is_file {
        match host_grant_path.parent() {
            Some(parent) => parent.to_path_buf(),
            None => PathBuf::from("/"),
        }
    } else {
        host_grant_path.to_path_buf()
    }
}

fn file_mode_perms(mode: FileMode) -> (DirPerms, FilePerms) {
    // FileGrant staging dirs are never mutable (no create of siblings).
    match mode {
        FileMode::Read => (DirPerms::READ, FilePerms::READ),
        FileMode::ReadWrite => (DirPerms::READ, FilePerms::READ | FilePerms::WRITE),
    }
}

fn dir_mode_perms(mode: FileMode) -> (DirPerms, FilePerms) {
    match mode {
        FileMode::Read => (DirPerms::READ, FilePerms::READ),
        FileMode::ReadWrite => (
            DirPerms::READ | DirPerms::MUTATE,
            FilePerms::READ | FilePerms::WRITE,
        ),
    }
}

/// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` (Linux).
const O_DIRECTORY_NOFOLLOW: i32 = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Open a directory at `path` with `O_NOFOLLOW`. Refuses symlinks (RT-3).
///
/// # Errors
///
/// [`FsGrantError::CapabilityDenied`] when `path` is a symlink or not a directory.
pub fn open_dir_nofollow(path: &Path) -> Result<std::fs::File, FsGrantError> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY_NOFOLLOW)
        .open(path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(FsGrantError::denied(format!(
            "dir grant path not found: {}",
            path.display()
        ))),
        Err(e) if is_symlink_nofollow_error(&e) || is_symlink_path(path) => {
            Err(FsGrantError::denied(format!(
                "dir grant path is a symlink or escape (O_NOFOLLOW): {}",
                path.display()
            )))
        }
        Err(e) => Err(FsGrantError::io(path, e)),
    }
}

/// Open `file_path` via `openat` relative to its parent with `O_NOFOLLOW`.
///
/// Mode is `Read` or `ReadWrite`; never create or truncate.
///
/// # Errors
///
/// [`FsGrantError::CapabilityDenied`] when the path is a symlink or missing.
pub fn open_file_nofollow(
    file_path: &Path,
    mode: FileMode,
) -> Result<cap_std::fs::File, FsGrantError> {
    let parent = file_path.parent().ok_or_else(|| {
        FsGrantError::denied(format!("file grant has no parent: {}", file_path.display()))
    })?;
    let name = file_path.file_name().ok_or_else(|| {
        FsGrantError::denied(format!(
            "file grant has no basename: {}",
            file_path.display()
        ))
    })?;

    let parent_fd = open_dir_nofollow(parent)?;
    let dir = cap_std::fs::Dir::from_std_file(parent_fd);

    let mut opts = cap_std::fs::OpenOptions::new();
    opts.read(true);
    if mode == FileMode::ReadWrite {
        opts.write(true);
    }
    // Final-component symlink → fail (O_NOFOLLOW). No create / truncate.
    opts.follow(FollowSymlinks::No);

    match dir.open_with(name, &opts) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(FsGrantError::denied(format!(
            "file grant path not found: {}",
            file_path.display()
        ))),
        Err(e) if is_symlink_nofollow_error(&e) || is_symlink_path(file_path) => {
            Err(FsGrantError::denied(format!(
                "file grant path is a symlink (O_NOFOLLOW): {}",
                file_path.display()
            )))
        }
        Err(e) => Err(FsGrantError::io(file_path, e)),
    }
}

fn is_symlink_path(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_symlink(),
        Err(_) => false,
    }
}

fn is_symlink_nofollow_error(e: &io::Error) -> bool {
    // Linux: ELOOP when O_NOFOLLOW hits a symlink.
    e.raw_os_error() == Some(libc::ELOOP)
        || e.to_string().to_ascii_lowercase().contains("symbolic link")
}

/// Stage a `FileGrant`: hardlink (or copy) the verified file into a private dir.
fn stage_file_grant(file_path: &Path, mode: FileMode) -> Result<TempDir, FsGrantError> {
    // Verify with O_NOFOLLOW open first (holds the security line for RT-3).
    let opened = open_file_nofollow(file_path, mode)?;
    drop(opened);

    let stage = TempDir::new().map_err(|e| FsGrantError::io(file_path, e))?;
    // Restrict staging dir (0700).
    let perms = fs::Permissions::from_mode(0o700);
    fs::set_permissions(stage.path(), perms).map_err(|e| FsGrantError::io(stage.path(), e))?;

    let basename = file_path.file_name().ok_or_else(|| {
        FsGrantError::denied(format!(
            "file grant has no basename: {}",
            file_path.display()
        ))
    })?;
    let dest = stage.path().join(basename);

    match fs::hard_link(file_path, &dest) {
        Ok(()) => Ok(stage),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            fs::copy(file_path, &dest).map_err(|err| FsGrantError::io(file_path, err))?;
            Ok(stage)
        }
        Err(e) => Err(FsGrantError::io(file_path, e)),
    }
}

/// Apply `caps` filesystem grants to `builder`.
///
/// Returns staging dirs that **must** be stored alongside the built `WasiCtx`
/// so `FileGrant` hardlinks remain valid for the lifetime of the store.
///
/// # Errors
///
/// [`FsGrantError::CapabilityDenied`] when a grant path is a symlink or missing.
/// [`FsGrantError::MissingInternerPath`] when ids cannot be resolved.
pub fn apply_filesystem_grants(
    builder: &mut WasiCtxBuilder,
    caps: &CapabilitySet,
) -> Result<FileGrantStages, FsGrantError> {
    if !caps.has(Interface::Filesystem) {
        if caps.files().is_empty() && caps.dirs().is_empty() {
            return Ok(FileGrantStages::default());
        }
        return Err(FsGrantError::FilesystemBitClear);
    }

    let intern = caps.interner();
    if (!caps.files().is_empty() || !caps.dirs().is_empty()) && intern.is_empty() {
        return Err(FsGrantError::MissingInternerPath);
    }

    let mut stages = FileGrantStages::default();

    for grant in caps.dirs() {
        let root = intern.path(grant.root());
        // Preflight O_NOFOLLOW (RT-3). Drop FD; wasmtime re-opens ambiently.
        let fd = open_dir_nofollow(root)?;
        drop(fd);

        let (dir_perms, file_perms) = dir_mode_perms(grant.mode());
        let guest = guest_preopen_name(root, false);
        let guest_str = guest.to_string_lossy();
        builder
            .preopened_dir(root, guest_str.as_ref(), dir_perms, file_perms)
            .map_err(|e| {
                FsGrantError::denied(format!(
                    "dir grant preopen refused for {}: {e}",
                    root.display()
                ))
            })?;
    }

    for grant in caps.files() {
        let path = intern.path(grant.path());
        let stage = stage_file_grant(path, grant.mode())?;
        let (dir_perms, file_perms) = file_mode_perms(grant.mode());

        let guest = guest_preopen_name(path, true);
        let guest_str = guest.to_string_lossy();
        builder
            .preopened_dir(stage.path(), guest_str.as_ref(), dir_perms, file_perms)
            .map_err(|e| {
                FsGrantError::denied(format!(
                    "file grant preopen refused for {}: {e}",
                    path.display()
                ))
            })?;
        stages.dirs.push(stage);
    }

    Ok(stages)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn open_dir_nofollow_refuses_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        symlink(&real, &link).unwrap();
        let err = open_dir_nofollow(&link).unwrap_err();
        assert!(err.is_capability_denied(), "{err}");
    }

    #[test]
    fn open_file_nofollow_refuses_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real.txt");
        fs::write(&real, b"ok").unwrap();
        let link = tmp.path().join("link.txt");
        symlink(&real, &link).unwrap();
        let err = open_file_nofollow(&link, FileMode::Read).unwrap_err();
        assert!(err.is_capability_denied(), "{err}");
    }

    #[test]
    fn open_file_nofollow_reads_regular() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.txt");
        fs::write(&file, b"hello").unwrap();
        let f = open_file_nofollow(&file, FileMode::Read).unwrap();
        drop(f);
    }
}
