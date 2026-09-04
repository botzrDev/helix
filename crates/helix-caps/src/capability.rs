//! `CapabilitySet` with checked construction and serde `try_from` (ADR-008 A.1).
//!
//! Forms the authority lattice under `is_subset_of` (HLX-11). Budget remains
//! outside the lattice (ADR-008 A.4).

use std::path::PathBuf;

use crate::interner::{validate_authority, validate_canonical_path};
use crate::{
    CapsError, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner, Method, MethodMask,
};

/// The complete authority available to one sandbox for one invocation.
///
/// Invariants (checked by `CapabilitySet::new`, asserted in debug builds
/// on every method):
/// - `files` is sorted ascending and contains no duplicate path id.
/// - `dirs` is sorted ascending and contains no duplicate root id.
/// - `hosts` is sorted ascending and contains no duplicate authority id.
/// - If `Interface::Filesystem` is clear, `files` and `dirs` are empty.
/// - If `Interface::HttpOutbound` is clear, `hosts` is empty.
///
/// `CapabilitySet` forms a lattice under `is_subset_of`. The property tests
/// verify reflexivity, antisymmetry, and transitivity, generating `dirs`
/// (CAPS-1 through CAPS-6 as extended by ADR-008 A.2). Budget is not in
/// the lattice.
///
/// There is exactly one way to obtain a `CapabilitySet`: `new`. Deserialize
/// is `#[serde(try_from = "CapabilitySetWire")]`. `CapabilitySetWire` is
/// private and mirrors the wire encoding (interface names, path strings,
/// authority strings, method names). Conversion interns then calls `new`.
/// A wire value that `new` would reject is a deserialization error
/// (CAPS-11). `interfaces` is deserialized from names only; a bit outside
/// the defined `Interface` variants is unrepresentable. `new` takes
/// `&[Interface]`, never a raw `u64` (ADR-008 A.1).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "CapabilitySetWire", into = "CapabilitySetWire")]
pub struct CapabilitySet {
    interfaces: u64,
    files: Vec<FileGrant>,
    dirs: Vec<DirGrant>,
    hosts: Vec<HostGrant>,
    /// M1 choice for ADR-008 A.3 threading hole: owned table so serialize can
    /// resolve `PathId` / `AuthorityId` back to strings without a call-site
    /// `DeserializeSeed`. Populated by wire conversion; empty for `EMPTY` and
    /// for sets built solely via [`Self::new`] with externally minted ids.
    #[serde(skip)]
    interner: Interner,
}

impl PartialEq for CapabilitySet {
    fn eq(&self, other: &Self) -> bool {
        if self.interfaces != other.interfaces {
            return false;
        }
        if self.files.len() != other.files.len()
            || self.dirs.len() != other.dirs.len()
            || self.hosts.len() != other.hosts.len()
        {
            return false;
        }
        for (a, b) in self.files.iter().zip(other.files.iter()) {
            if a.mode() != b.mode() {
                return false;
            }
            if self.interner.path(a.path()) != other.interner.path(b.path()) {
                return false;
            }
        }
        for (a, b) in self.dirs.iter().zip(other.dirs.iter()) {
            if a.mode() != b.mode() {
                return false;
            }
            if self.interner.path(a.root()) != other.interner.path(b.root()) {
                return false;
            }
        }
        for (a, b) in self.hosts.iter().zip(other.hosts.iter()) {
            if a.methods() != b.methods() {
                return false;
            }
            if self.interner.authority(a.authority()) != other.interner.authority(b.authority()) {
                return false;
            }
        }
        true
    }
}

impl Eq for CapabilitySet {}

/// Private wire form. Mirrors JSON (section 5 of `gateway-protocol.md`) and
/// the caps side-file CBOR with paths and authorities as strings.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CapabilitySetWire {
    interfaces: Vec<Interface>,
    files: Vec<FileGrantWire>,
    dirs: Vec<DirGrantWire>,
    hosts: Vec<HostGrantWire>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct FileGrantWire {
    path: PathBuf,
    mode: FileMode,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct DirGrantWire {
    path: PathBuf,
    mode: FileMode,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct HostGrantWire {
    authority: String,
    methods: Vec<Method>,
}

impl CapabilitySet {
    /// The empty set: no interfaces, no grants. Bottom of the lattice.
    pub const EMPTY: CapabilitySet = CapabilitySet {
        interfaces: 0,
        files: Vec::new(),
        dirs: Vec::new(),
        hosts: Vec::new(),
        interner: Interner::empty(),
    };

    /// Validates invariants, sorts and deduplicates, and returns the set.
    /// Never panics. Takes `&[Interface]`, never a raw `u64`.
    ///
    /// Duplicate path / root / authority ids are rejected ([`CapsError::Duplicate`]).
    /// Path-string checks (relative, `..`) run when grants are built from the
    /// wire form via [`TryFrom<CapabilitySetWire>`] / JSON deserialize; PathId-based
    /// `new` cannot see path strings and therefore checks id-level duplicates
    /// and orphan grants only.
    ///
    /// # Errors
    ///
    /// Returns [`CapsError::Duplicate`] when two grants share a path, root, or
    /// authority id, and [`CapsError::OrphanGrant`] when grants are present for
    /// an interface whose bit is clear.
    pub fn new(
        interfaces: &[Interface],
        mut files: Vec<FileGrant>,
        mut dirs: Vec<DirGrant>,
        mut hosts: Vec<HostGrant>,
    ) -> Result<CapabilitySet, CapsError> {
        let mut bits = 0u64;
        for i in interfaces {
            bits |= i.bit();
        }

        files.sort_unstable();
        dirs.sort_unstable();
        hosts.sort_unstable();

        for w in files.windows(2) {
            if w[0].path() == w[1].path() {
                return Err(CapsError::Duplicate(format!(
                    "path id {}",
                    w[0].path().as_u32()
                )));
            }
        }
        for w in dirs.windows(2) {
            if w[0].root() == w[1].root() {
                return Err(CapsError::Duplicate(format!(
                    "dir id {}",
                    w[0].root().as_u32()
                )));
            }
        }
        for w in hosts.windows(2) {
            if w[0].authority() == w[1].authority() {
                return Err(CapsError::Duplicate(format!(
                    "authority id {}",
                    w[0].authority().as_u32()
                )));
            }
        }

        let has_fs = bits & Interface::Filesystem.bit() != 0;
        let has_http = bits & Interface::HttpOutbound.bit() != 0;
        if !has_fs && (!files.is_empty() || !dirs.is_empty()) {
            return Err(CapsError::OrphanGrant(Interface::Filesystem));
        }
        if !has_http && !hosts.is_empty() {
            return Err(CapsError::OrphanGrant(Interface::HttpOutbound));
        }

        Ok(Self {
            interfaces: bits,
            files,
            dirs,
            hosts,
            interner: Interner::empty(),
        })
    }

    /// Attach a snapshot interner used to resolve ids on serialize / equality.
    /// Used by tests and by policy load once the snapshot table exists.
    #[must_use]
    pub fn with_interner(mut self, interner: Interner) -> Self {
        self.interner = interner;
        self
    }

    /// Snapshot interner owned by this set (empty unless built from wire or
    /// bound via [`Self::with_interner`]).
    #[must_use]
    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    /// Internal interfaces bitset. No public setter.
    #[must_use]
    pub fn interfaces_bits(&self) -> u64 {
        debug_assert!(self.invariants_hold());
        self.interfaces
    }

    /// Sorted file grants.
    #[must_use]
    pub fn files(&self) -> &[FileGrant] {
        debug_assert!(self.invariants_hold());
        &self.files
    }

    /// Sorted directory grants.
    #[must_use]
    pub fn dirs(&self) -> &[DirGrant] {
        debug_assert!(self.invariants_hold());
        &self.dirs
    }

    /// Sorted host grants.
    #[must_use]
    pub fn hosts(&self) -> &[HostGrant] {
        debug_assert!(self.invariants_hold());
        &self.hosts
    }

    /// True if the bit for `i` is set.
    #[must_use]
    pub fn has(&self, i: Interface) -> bool {
        debug_assert!(self.invariants_hold());
        self.interfaces & i.bit() != 0
    }

    pub(crate) fn invariants_hold(&self) -> bool {
        let has_fs = self.interfaces & Interface::Filesystem.bit() != 0;
        let has_http = self.interfaces & Interface::HttpOutbound.bit() != 0;
        self.files.windows(2).all(|w| w[0].path() < w[1].path())
            && self.dirs.windows(2).all(|w| w[0].root() < w[1].root())
            && self
                .hosts
                .windows(2)
                .all(|w| w[0].authority() < w[1].authority())
            && (has_fs || (self.files.is_empty() && self.dirs.is_empty()))
            && (has_http || self.hosts.is_empty())
    }
}

impl TryFrom<CapabilitySetWire> for CapabilitySet {
    type Error = CapsError;

    fn try_from(wire: CapabilitySetWire) -> Result<CapabilitySet, CapsError> {
        for f in &wire.files {
            validate_canonical_path(&f.path)?;
        }
        for d in &wire.dirs {
            validate_canonical_path(&d.path)?;
        }
        for h in &wire.hosts {
            validate_authority(&h.authority)?;
        }

        let mut interner = Interner::new();
        let files = wire
            .files
            .iter()
            .map(|f| FileGrant::new(interner.intern_path(&f.path), f.mode))
            .collect();
        let dirs = wire
            .dirs
            .iter()
            .map(|d| DirGrant::new(interner.intern_path(&d.path), d.mode))
            .collect();
        let hosts = wire
            .hosts
            .iter()
            .map(|h| {
                HostGrant::new(
                    interner.intern_authority(&h.authority),
                    MethodMask::new(&h.methods),
                )
            })
            .collect();

        let set = CapabilitySet::new(&wire.interfaces, files, dirs, hosts)?;
        Ok(set.with_interner(interner))
    }
}

impl From<CapabilitySet> for CapabilitySetWire {
    fn from(set: CapabilitySet) -> Self {
        let files = set
            .files
            .iter()
            .map(|f| FileGrantWire {
                path: set.interner.path(f.path()).to_path_buf(),
                mode: f.mode(),
            })
            .collect();
        let dirs = set
            .dirs
            .iter()
            .map(|d| DirGrantWire {
                path: set.interner.path(d.root()).to_path_buf(),
                mode: d.mode(),
            })
            .collect();
        let hosts = set
            .hosts
            .iter()
            .map(|h| HostGrantWire {
                authority: set.interner.authority(h.authority()).to_owned(),
                methods: h.methods().methods(),
            })
            .collect();
        let mut interfaces = Vec::new();
        for i in [
            Interface::Stdio,
            Interface::Clocks,
            Interface::Random,
            Interface::Filesystem,
            Interface::HttpOutbound,
        ] {
            if set.interfaces & i.bit() != 0 {
                interfaces.push(i);
            }
        }
        Self {
            interfaces,
            files,
            dirs,
            hosts,
        }
    }
}
