//! `helix-caps`: the single source of truth for authority in HELIX.
//!
//! This file is the API contract. Implementation must match these signatures
//! and doc comments exactly; the doc comments state invariants that are
//! tested by property tests in `tests/lattice.rs`.
//!
//! This is a spec sketch under `interfaces/`. It is not a workspace crate
//! and must not be added to `Cargo.toml` members. The M1 crate
//! `crates/helix-caps` implements it.
//!
//! Dependencies permitted: `serde`, `serde_json` (dev only), `proptest`
//! (dev only). No tokio, no wasmtime, no I/O. `Interner` stays serde-only.
//!
//! Shape: ADR-008 Part A, ADR-008 B.1, ADR-009 E.2. Pre-rewrite public
//! fields, `Budget` inside `CapabilitySet`, and `Interface::Environment`
//! are withdrawn.

#![forbid(unsafe_code)]
#![deny(warnings, missing_docs)]

use std::path::{Path, PathBuf};

/// RFC 7638 JWK thumbprint of the agent's Ed25519 public key: SHA-256 over
/// the canonical JSON `{"crv":"Ed25519","kty":"OKP","x":"..."}` (ADR-008 B.1).
/// The same 32 bytes as `sub` / `cnf.jkt` (base64url on the wire, raw here).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Identity([u8; 32]);

impl Identity {
    /// Raw 32-byte thumbprint.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32];
}

/// SHA-256 of the bytes of a WebAssembly component.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct ToolDigest([u8; 32]);

impl ToolDigest {
    /// Raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32];
}

/// ULID of an invocation. In-memory type is `u128`. Serializes as a
/// 26-character Crockford base32 ULID string via `#[serde(with = "ulid_str")]`
/// (ADR-008 A.5). Rejects integers and malformed base32 (CAPS-15).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
#[serde(with = "ulid_str")]
pub struct RequestId(u128);

impl RequestId {
    /// Raw ULID as `u128`.
    #[must_use]
    pub fn as_u128(self) -> u128;
}

/// Bit positions in the internal `CapabilitySet` interfaces bitset.
/// Append-only; never renumber. Bit 5 is unassigned: `Interface::Environment`
/// is deleted (ADR-008 A.5). When environment variables gain behavior they
/// get the next free bit and a ticket.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interface {
    /// wasi:cli stdin/stdout/stderr
    Stdio = 0,
    /// wasi:clocks monotonic and wall
    Clocks = 1,
    /// wasi:random
    Random = 2,
    /// wasi:filesystem, scoped by `files` and `dirs`
    Filesystem = 3,
    /// wasi:http outgoing-handler, scoped by `hosts`
    HttpOutbound = 4,
}

/// Access mode for a file or directory grant. `ReadWrite` is a superset of `Read`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize)]
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

/// Snapshot-scoped intern id of a canonical path (ADR-008 A.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PathId(u32);

impl PathId {
    /// Raw intern id.
    #[must_use]
    pub fn as_u32(self) -> u32;
}

/// Snapshot-scoped intern id of a `host:port` authority (ADR-008 A.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AuthorityId(u32);

impl AuthorityId {
    /// Raw intern id.
    #[must_use]
    pub fn as_u32(self) -> u32;
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
/// M1 chooses the mechanism. The invariant is: construction always goes
/// through `CapabilitySet::new`.
pub struct Interner {
    // private
}

impl Interner {
    /// Empty table.
    #[must_use]
    pub fn new() -> Interner;

    /// Intern a canonical path, growing the table. Used at policy load and
    /// when building a throwaway table. Parent chain is recorded here.
    pub fn intern_path(&mut self, path: &Path) -> PathId;

    /// Intern a lowercase `host:port` with explicit port, growing the table.
    pub fn intern_authority(&mut self, authority: &str) -> AuthorityId;

    /// Lookup only. `None` if the path was never interned in this snapshot.
    #[must_use]
    pub fn get_path(&self, path: &Path) -> Option<PathId>;

    /// Lookup only. `None` if the authority was never interned in this snapshot.
    #[must_use]
    pub fn get_authority(&self, authority: &str) -> Option<AuthorityId>;

    /// Resolve an id back to the canonical path.
    #[must_use]
    pub fn path(&self, id: PathId) -> &Path;

    /// Resolve an id back to the authority string.
    #[must_use]
    pub fn authority(&self, id: AuthorityId) -> &str;

    /// Precomputed parent chain of `id` as intern ids (ADR-008 A.3).
    #[must_use]
    pub fn parent_chain(&self, id: PathId) -> &[PathId];

    /// True if `ancestor` is an ancestor-or-equal of `descendant`.
    /// `/a/b` does not contain `/a/bc`. `/` contains everything (CAPS-13).
    #[must_use]
    pub fn is_prefix(&self, ancestor: PathId, descendant: PathId) -> bool;
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
    pub fn new(path: PathId, mode: FileMode) -> FileGrant;

    /// Interned canonical path.
    #[must_use]
    pub fn path(&self) -> PathId;

    /// Permitted mode.
    #[must_use]
    pub fn mode(&self) -> FileMode;
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
    pub fn new(root: PathId, mode: FileMode) -> DirGrant;

    /// Interned canonical directory root.
    #[must_use]
    pub fn root(&self) -> PathId;

    /// Permitted mode.
    #[must_use]
    pub fn mode(&self) -> FileMode;
}

/// Bitmask of HTTP methods. Bit order: GET=0, HEAD=1, POST=2, PUT=3, PATCH=4, DELETE=5.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MethodMask(u8);

impl MethodMask {
    /// From a slice of defined methods. Duplicate methods are idempotent.
    #[must_use]
    pub fn new(methods: &[Method]) -> MethodMask;

    /// Raw bits.
    #[must_use]
    pub fn bits(self) -> u8;

    /// True if `self` grants nothing that `other` does not:
    /// `self.bits() & !other.bits() == 0`.
    #[must_use]
    pub fn is_subset_of(self, other: MethodMask) -> bool;
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
    pub fn new(authority: AuthorityId, methods: MethodMask) -> HostGrant;

    /// Interned authority.
    #[must_use]
    pub fn authority(&self) -> AuthorityId;

    /// Allowed methods.
    #[must_use]
    pub fn methods(&self) -> MethodMask;
}

/// Resource ceilings for one invocation. Sibling of `CapabilitySet`; not a
/// lattice element (ADR-008 A.4). Does not participate in `is_subset_of` or
/// `meet`.
///
/// Field list matches landed WIT `resource-budget` (ADR-009 A.2): the original
/// four ceilings plus the three tree/admission bounds. `epoch_ticks` is
/// renamed `preempt_ticks` (ADR-008 E.1).
///
/// Policy defaults (not constructor defaults unless M1 pins them): 
/// `max_delegation_depth = 2`, `max_children = 8`,
/// `max_concurrent_instances = 32`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResourceBudget {
    preempt_ticks: u32,
    wall_clock_ms: u32,
    memory_bytes: u64,
    output_bytes: u32,
    max_delegation_depth: u32,
    max_children: u32,
    max_concurrent_instances: u32,
}

impl ResourceBudget {
    /// Construct from components. No lattice check.
    #[must_use]
    pub fn new(
        preempt_ticks: u32,
        wall_clock_ms: u32,
        memory_bytes: u64,
        output_bytes: u32,
        max_delegation_depth: u32,
        max_children: u32,
        max_concurrent_instances: u32,
    ) -> ResourceBudget;

    /// Guest preemption deadline in milliseconds (tick is pinned at 1 ms).
    #[must_use]
    pub fn preempt_ticks(&self) -> u32;
    /// Hard deadline including host calls, in milliseconds.
    #[must_use]
    pub fn wall_clock_ms(&self) -> u32;
    /// Linear memory ceiling in bytes.
    #[must_use]
    pub fn memory_bytes(&self) -> u64;
    /// Maximum result size returned to the caller.
    #[must_use]
    pub fn output_bytes(&self) -> u32;
    /// Depth counted from the root request.
    #[must_use]
    pub fn max_delegation_depth(&self) -> u32;
    /// Fan-out per parent, counted in the parent's JoinSet.
    #[must_use]
    pub fn max_children(&self) -> u32;
    /// Live instances attributable to one Identity on one gateway.
    #[must_use]
    pub fn max_concurrent_instances(&self) -> u32;

    /// Componentwise `self[i] <= ceiling[i]` for every field. Reflexive and
    /// transitive (CAPS-14).
    #[must_use]
    pub fn is_within(&self, ceiling: &ResourceBudget) -> bool;

    /// Componentwise greatest lower bound (CAPS-14).
    #[must_use]
    pub fn min(&self, other: &ResourceBudget) -> ResourceBudget;
}

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
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "CapabilitySetWire")]
pub struct CapabilitySet {
    interfaces: u64,
    files: Vec<FileGrant>,
    dirs: Vec<DirGrant>,
    hosts: Vec<HostGrant>,
}

/// Private wire form. Mirrors JSON (section 5 of `gateway-protocol.md`) and
/// the caps side-file CBOR with paths and authorities as strings.
struct CapabilitySetWire {
    interfaces: Vec<Interface>,
    files: Vec<FileGrantWire>,
    dirs: Vec<DirGrantWire>,
    hosts: Vec<HostGrantWire>,
}

struct FileGrantWire {
    path: PathBuf,
    mode: FileMode,
}

struct DirGrantWire {
    path: PathBuf,
    mode: FileMode,
}

struct HostGrantWire {
    authority: String,
    methods: Vec<Method>,
}

/// Why construction or attenuation was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapsError {
    /// A `files` or `dirs` entry was relative or contained `..`.
    #[error("file grant path is not canonical: {0}")]
    NonCanonicalPath(PathBuf),
    /// Duplicate path, directory root, or authority.
    #[error("duplicate grant: {0}")]
    Duplicate(String),
    /// Grants present for an interface whose bit is clear.
    #[error("grants present for unlinked interface {0:?}")]
    OrphanGrant(Interface),
    /// Requested set is not a subset of the parent.
    #[error("requested set exceeds parent: {0}")]
    Escalation(String),
    /// Method name not in the six-value `Method` enum (CAPS-12).
    #[error("unknown method: {0}")]
    UnknownMethod(String),
    /// Interface name not in the defined `Interface` variants (CAPS-12).
    #[error("unknown interface: {0}")]
    UnknownInterface(String),
    /// Path or authority is not in the snapshot intern table (ADR-008 A.3).
    #[error("not interned: {0}")]
    NotInterned(String),
}

impl CapabilitySet {
    /// The empty set: no interfaces, no grants. Bottom of the lattice.
    pub const EMPTY: CapabilitySet = /* ... */;

    /// Validates invariants, sorts and deduplicates, and returns the set.
    /// Never panics. Takes `&[Interface]`, never a raw `u64`.
    pub fn new(
        interfaces: &[Interface],
        files: Vec<FileGrant>,
        dirs: Vec<DirGrant>,
        hosts: Vec<HostGrant>,
    ) -> Result<CapabilitySet, CapsError>;

    /// Internal interfaces bitset. No public setter.
    #[must_use]
    pub fn interfaces_bits(&self) -> u64;

    /// Sorted file grants.
    #[must_use]
    pub fn files(&self) -> &[FileGrant];

    /// Sorted directory grants.
    #[must_use]
    pub fn dirs(&self) -> &[DirGrant];

    /// Sorted host grants.
    #[must_use]
    pub fn hosts(&self) -> &[HostGrant];

    /// True if `self` grants nothing that `other` does not.
    ///
    /// Complexity: O(|files| + |dirs| + |hosts|) with a merge walk that
    /// consults `dirs` for uncovered files (ADR-008 A.2). Pure. After
    /// intern, a merge of two sorted u32 slices (ADR-008 A.3).
    ///
    /// Definition:
    /// - `self.interfaces & !other.interfaces == 0`
    /// - every `FileGrant` in `self` is covered either by a `FileGrant` in
    ///   `other` with the same path id and `self.mode <= other.mode`, or by
    ///   a `DirGrant` in `other` whose root is an ancestor of the file path,
    ///   with the same mode rule
    /// - every `DirGrant` in `self` is covered by a `DirGrant` in `other`
    ///   whose root is an ancestor-or-equal path and whose mode is
    ///   greater-or-equal
    /// - every `HostGrant` in `self` has a match in `other` with the same
    ///   authority id and `self.methods` subset of `other.methods`
    ///
    /// Budget is not consulted.
    #[must_use]
    pub fn is_subset_of(&self, other: &CapabilitySet) -> bool;

    /// Returns `requested` if and only if `requested.is_subset_of(parent)`.
    /// This is the entire authority-side delegation policy. Pure.
    /// Resource composition is `ResourceBudget::is_within`, separately.
    pub fn attenuate(parent: &CapabilitySet, requested: &CapabilitySet)
        -> Result<CapabilitySet, CapsError>;

    /// Greatest lower bound. Used to compute the effective set when a policy
    /// grant and a delegation request both apply. Pure.
    ///
    /// Meet of two `DirGrant`s is the more specific root when one contains
    /// the other, and absent otherwise. Meet of a `FileGrant` with a covering
    /// `DirGrant` is the `FileGrant` with the lesser mode (ADR-008 A.2).
    #[must_use]
    pub fn meet(&self, other: &CapabilitySet) -> CapabilitySet;

    /// True if the bit for `i` is set.
    #[must_use]
    pub fn has(&self, i: Interface) -> bool;
}

impl TryFrom<CapabilitySetWire> for CapabilitySet {
    type Error = CapsError;
    fn try_from(wire: CapabilitySetWire) -> Result<CapabilitySet, CapsError>;
}

/// Serde helper: encodes `RequestId` as a Crockford base32 ULID string.
mod ulid_str { /* ... */ }
