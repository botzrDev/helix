//! File, directory, and host grants plus HTTP method masks.

use crate::{AuthorityId, PathId};

/// Access mode for a file or directory grant. `ReadWrite` is a superset of `Read`.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    /// Open read-only.
    Read,
    /// Open read-write, no create, no truncate.
    ReadWrite,
}

/// HTTP methods that may appear in a `MethodMask`. An unknown method string
/// in policy or on the wire is a fatal error (ADR-008 A.1, CAPS-12).
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

impl Method {
    const fn bit(self) -> u8 {
        match self {
            Self::Get => 1 << 0,
            Self::Head => 1 << 1,
            Self::Post => 1 << 2,
            Self::Put => 1 << 3,
            Self::Patch => 1 << 4,
            Self::Delete => 1 << 5,
        }
    }
}

/// Bitmask of HTTP methods. Bit order: GET=0, HEAD=1, POST=2, PUT=3, PATCH=4, DELETE=5.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MethodMask(u8);

impl MethodMask {
    /// From a slice of defined methods. Duplicate methods are idempotent.
    #[must_use]
    pub fn new(methods: &[Method]) -> MethodMask {
        let mut bits = 0u8;
        for m in methods {
            bits |= m.bit();
        }
        Self(bits)
    }

    /// Raw bits.
    #[must_use]
    pub fn bits(self) -> u8 {
        self.0
    }

    /// True if `self` grants nothing that `other` does not:
    /// `self.bits() & !other.bits() == 0`.
    #[must_use]
    pub fn is_subset_of(self, other: MethodMask) -> bool {
        self.0 & !other.0 == 0
    }

    /// Methods set in this mask, in bit order (for wire encoding).
    pub(crate) fn methods(self) -> Vec<Method> {
        const ALL: [Method; 6] = [
            Method::Get,
            Method::Head,
            Method::Post,
            Method::Put,
            Method::Patch,
            Method::Delete,
        ];
        ALL.into_iter().filter(|m| self.0 & m.bit() != 0).collect()
    }
}

/// A single file the sandbox may open.
///
/// Invariant (reworded, ADR-008 A.2): `canonical_path` is absolute and
/// contained no symlink components when helix-policy resolved it at load
/// time. This is a precondition established by the loader, not a property
/// the type can maintain. RT-3 holds the line at open time.
///
/// In memory the path is a `PathId` into the snapshot `Interner` (ADR-008 A.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FileGrant {
    path: PathId,
    mode: FileMode,
}

impl FileGrant {
    /// Construct from interned path and mode. Does not canonicalize.
    #[must_use]
    pub fn new(path: PathId, mode: FileMode) -> FileGrant {
        Self { path, mode }
    }

    /// Interned canonical path.
    #[must_use]
    pub fn path(&self) -> PathId {
        self.path
    }

    /// Permitted mode.
    #[must_use]
    pub fn mode(&self) -> FileMode {
        self.mode
    }
}

/// A directory the sandbox may open. One `DirGrant` is one cap-std preopen.
/// The runtime does not expand directories (ADR-008 A.2).
///
/// Sorted and deduplicated by root. Subset is prefix containment: a
/// `DirGrant` in self is covered by a `DirGrant` in other whose root is an
/// ancestor-or-equal path and whose mode is greater-or-equal. A `FileGrant`
/// in self is covered either by a matching `FileGrant` in other or by a
/// `DirGrant` in other whose root is an ancestor of the file path, with the
/// same mode rule.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct DirGrant {
    root: PathId,
    mode: FileMode,
}

impl DirGrant {
    /// Construct from interned root and mode. Does not canonicalize.
    #[must_use]
    pub fn new(root: PathId, mode: FileMode) -> DirGrant {
        Self { root, mode }
    }

    /// Interned canonical directory root.
    #[must_use]
    pub fn root(&self) -> PathId {
        self.root
    }

    /// Permitted mode.
    #[must_use]
    pub fn mode(&self) -> FileMode {
        self.mode
    }
}

/// A single network authority the sandbox may reach.
///
/// Invariant: `authority` is lowercase `host:port` with an explicit port.
/// In memory the authority is an `AuthorityId` (ADR-008 A.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct HostGrant {
    authority: AuthorityId,
    methods: MethodMask,
}

impl HostGrant {
    /// Construct from interned authority and method mask.
    #[must_use]
    pub fn new(authority: AuthorityId, methods: MethodMask) -> HostGrant {
        Self { authority, methods }
    }

    /// Interned authority.
    #[must_use]
    pub fn authority(&self) -> AuthorityId {
        self.authority
    }

    /// Allowed methods.
    #[must_use]
    pub fn methods(&self) -> MethodMask {
        self.methods
    }
}
