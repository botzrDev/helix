//! Snapshot-scoped path and authority intern table (ADR-008 A.3).

use std::path::{Component, Path, PathBuf};

use crate::CapsError;

/// Snapshot-scoped intern id of a canonical path (ADR-008 A.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PathId(u32);

impl PathId {
    /// Raw intern id.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Snapshot-scoped intern id of a `host:port` authority (ADR-008 A.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AuthorityId(u32);

impl AuthorityId {
    /// Raw intern id.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug)]
struct PathEntry {
    path: PathBuf,
    /// Ancestors from immediate parent up to root (does not include self).
    parent_chain: Vec<PathId>,
}

/// Snapshot-scoped intern table. helix-policy builds one at load.
/// `helix-ctl run --caps` may build a throwaway (ADR-009 E.2).
///
/// Prefix containment for `DirGrant` is precomputed: the table stores each
/// path's parent chain as ids, so containment is an id comparison, not a
/// memcmp (ADR-008 A.3).
///
/// Serialization of a `CapabilitySet` resolves ids back to strings against
/// this table. Deserialization interns against the table the caller supplies.
/// A path or authority that does not exist in the snapshot cannot be interned.
///
/// How the table is threaded through `Deserialize` is not specified in
/// ADR-008 A.3 (no `DeserializeSeed` / thread-local / `from_wire` named).
/// M1 chooses the mechanism: a successful `CapabilitySet` deserialization
/// owns a throwaway [`Interner`] built from the wire paths so JSON
/// round-trips resolve without an external snapshot (CAPS-9).
#[derive(Clone, Debug)]
pub struct Interner {
    paths: Vec<PathEntry>,
    authorities: Vec<String>,
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    /// Empty table (const-friendly for [`crate::CapabilitySet::EMPTY`]).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            paths: Vec::new(),
            authorities: Vec::new(),
        }
    }

    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::empty()
    }

    /// Intern a canonical path, growing the table. Used at policy load and
    /// when building a throwaway table. Parent chain is recorded here.
    ///
    /// Paths must already be absolute and free of `..` / `.` components;
    /// callers that accept untrusted strings should use
    /// [`validate_canonical_path`] first. This method does not perform I/O.
    ///
    /// # Panics
    ///
    /// Panics if the path table would exceed `u32::MAX` entries.
    pub fn intern_path(&mut self, path: &Path) -> PathId {
        if let Some(id) = self.get_path(path) {
            return id;
        }
        let parent_chain = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                let parent_id = self.intern_path(parent);
                let mut chain = vec![parent_id];
                chain.extend_from_slice(self.parent_chain(parent_id));
                chain
            }
            _ => Vec::new(),
        };
        let id = PathId(u32::try_from(self.paths.len()).expect("path intern table fits in u32"));
        self.paths.push(PathEntry {
            path: path.to_path_buf(),
            parent_chain,
        });
        id
    }

    /// Intern a lowercase `host:port` with explicit port, growing the table.
    ///
    /// # Panics
    ///
    /// Panics if the authority table would exceed `u32::MAX` entries.
    pub fn intern_authority(&mut self, authority: &str) -> AuthorityId {
        if let Some(id) = self.get_authority(authority) {
            return id;
        }
        let id = AuthorityId(
            u32::try_from(self.authorities.len()).expect("authority table fits in u32"),
        );
        self.authorities.push(authority.to_owned());
        id
    }

    /// Lookup only. `None` if the path was never interned in this snapshot.
    #[must_use]
    pub fn get_path(&self, path: &Path) -> Option<PathId> {
        self.paths
            .iter()
            .enumerate()
            .find_map(|(i, e)| (e.path == path).then_some(PathId(u32::try_from(i).ok()?)))
    }

    /// Lookup only. `None` if the authority was never interned in this snapshot.
    #[must_use]
    pub fn get_authority(&self, authority: &str) -> Option<AuthorityId> {
        self.authorities
            .iter()
            .enumerate()
            .find_map(|(i, a)| (a == authority).then_some(AuthorityId(u32::try_from(i).ok()?)))
    }

    /// Resolve an id back to the canonical path.
    ///
    /// # Panics
    ///
    /// Panics if `id` was not minted by this table.
    #[must_use]
    pub fn path(&self, id: PathId) -> &Path {
        &self.paths[id.0 as usize].path
    }

    /// Resolve an id back to the authority string.
    ///
    /// # Panics
    ///
    /// Panics if `id` was not minted by this table.
    #[must_use]
    pub fn authority(&self, id: AuthorityId) -> &str {
        &self.authorities[id.0 as usize]
    }

    /// Precomputed parent chain of `id` as intern ids (ADR-008 A.3).
    #[must_use]
    pub fn parent_chain(&self, id: PathId) -> &[PathId] {
        &self.paths[id.0 as usize].parent_chain
    }

    /// True if `ancestor` is an ancestor-or-equal of `descendant`.
    /// `/a/b` does not contain `/a/bc`. `/` contains everything (CAPS-13).
    #[must_use]
    pub fn is_prefix(&self, ancestor: PathId, descendant: PathId) -> bool {
        if ancestor == descendant {
            return true;
        }
        if self.path(ancestor) == Path::new("/") {
            return true;
        }
        self.parent_chain(descendant).contains(&ancestor)
    }
}

/// Reject relative paths and `..` / `.` components (CAPS-8). No I/O.
pub fn validate_canonical_path(path: &Path) -> Result<(), CapsError> {
    if !path.is_absolute() {
        return Err(CapsError::NonCanonicalPath(path.to_path_buf()));
    }
    for c in path.components() {
        match c {
            Component::Normal(_) | Component::RootDir => {}
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(CapsError::NonCanonicalPath(path.to_path_buf()));
            }
        }
    }
    Ok(())
}

/// Reject authorities that are not lowercase `host:port` with an explicit port.
pub fn validate_authority(authority: &str) -> Result<(), CapsError> {
    if authority.is_empty() || authority != authority.to_ascii_lowercase() {
        return Err(CapsError::NotInterned(authority.to_owned()));
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(CapsError::NotInterned(authority.to_owned()));
    };
    if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(CapsError::NotInterned(authority.to_owned()));
    }
    Ok(())
}
