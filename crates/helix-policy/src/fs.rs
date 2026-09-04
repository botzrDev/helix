//! Minimal filesystem seam for the host resolve pass (rule 5).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Kind returned by [`Fs::path_kind`] (`lstat`; does not follow the leaf).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Something else (fifo, socket, device).
    Other,
}

/// I/O failure from [`Fs`].
#[derive(Debug)]
pub struct FsError {
    /// Path that failed.
    pub path: PathBuf,
    /// Human-readable reason.
    pub message: String,
}

impl FsError {
    /// Construct from a path and message.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for FsError {}

/// Host filesystem used only by [`crate::resolve_host`].
///
/// Structural validation must never call this trait (POL-7).
pub trait Fs {
    /// `lstat` the path: kind of the leaf without following a symlink.
    ///
    /// # Errors
    ///
    /// Missing path or permission failure.
    fn path_kind(&self, path: &Path) -> Result<PathKind, FsError>;

    /// Canonicalize. Follows the host's realpath rules; callers must reject
    /// symlink components first.
    ///
    /// # Errors
    ///
    /// Path cannot be canonicalized.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError>;
}

/// Mock that panics on every call. POL-7 injects this into the structural pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct PanicFs;

impl Fs for PanicFs {
    fn path_kind(&self, path: &Path) -> Result<PathKind, FsError> {
        panic!(
            "helix-policy structural pass must not touch Fs (path_kind {})",
            path.display()
        );
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError> {
        panic!(
            "helix-policy structural pass must not touch Fs (canonicalize {})",
            path.display()
        );
    }
}

/// In-memory `Fs` for tests. No directory walking (no expansion).
#[derive(Debug, Default, Clone)]
pub struct MapFs {
    entries: BTreeMap<PathBuf, PathKind>,
}

impl MapFs {
    /// Empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a path's kind. Returns `self` for chaining.
    #[must_use]
    pub fn insert(mut self, path: impl AsRef<Path>, kind: PathKind) -> Self {
        self.entries.insert(path.as_ref().to_path_buf(), kind);
        self
    }
}

impl Fs for MapFs {
    fn path_kind(&self, path: &Path) -> Result<PathKind, FsError> {
        self.entries
            .get(path)
            .copied()
            .ok_or_else(|| FsError::new(path, "not in MapFs"))
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError> {
        match self.entries.get(path) {
            Some(PathKind::File | PathKind::Directory) => Ok(path.to_path_buf()),
            Some(PathKind::Symlink) => Err(FsError::new(path, "symlink")),
            Some(PathKind::Other) => Err(FsError::new(path, "not a file or directory")),
            None => Err(FsError::new(path, "not in MapFs")),
        }
    }
}

/// Real `std::fs` implementation (`lstat` + `canonicalize`).
#[derive(Debug, Default, Clone, Copy)]
pub struct StdFs;

impl Fs for StdFs {
    fn path_kind(&self, path: &Path) -> Result<PathKind, FsError> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| io_err(path, &e))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            Ok(PathKind::Symlink)
        } else if ft.is_file() {
            Ok(PathKind::File)
        } else if ft.is_dir() {
            Ok(PathKind::Directory)
        } else {
            Ok(PathKind::Other)
        }
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf, FsError> {
        std::fs::canonicalize(path).map_err(|e| io_err(path, &e))
    }
}

fn io_err(path: &Path, err: &io::Error) -> FsError {
    FsError::new(path, err.to_string())
}
