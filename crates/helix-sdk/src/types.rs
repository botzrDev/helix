//! Portable WIT-aligned types for delegation requests (ADR-009 A.2).

/// File open mode on a delegated grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    /// Read-only.
    Read,
    /// Read-write.
    ReadWrite,
}

/// A file grant the parent may request for a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileGrant {
    /// Canonical absolute path.
    pub canonical_path: String,
    /// Access mode.
    pub mode: FileMode,
}

/// HTTP host grant (`methods` is a `MethodMask` bitset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGrant {
    /// Authority (host[:port]).
    pub authority: String,
    /// `MethodMask`: GET=0 … DELETE=5.
    pub methods: u8,
}

/// Lattice grants the parent may request for a child (WIT `capability-set`).
///
/// Budget is a sibling and is not a field of this record (ADR-008 A.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    /// Bitset over Interface (stdio=0, clocks=1, random=2, filesystem=3, http-outbound=4).
    pub interfaces: u64,
    /// File grants.
    pub files: Vec<FileGrant>,
    /// Host grants.
    pub hosts: Vec<HostGrant>,
}

/// Resource ceilings for a child (WIT `resource-budget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudget {
    /// Epoch preempt interval in milliseconds (ticker pinned at 1 ms).
    pub preempt_ticks: u32,
    /// Wall-clock limit in milliseconds.
    pub wall_clock_ms: u32,
    /// Memory ceiling in bytes.
    pub memory_bytes: u64,
    /// Output byte cap.
    pub output_bytes: u32,
    /// Max delegation depth for the child subtree.
    pub max_delegation_depth: u32,
    /// Max concurrent children in the child's `JoinSet`.
    pub max_children: u32,
    /// Per-identity concurrency contribution.
    pub max_concurrent_instances: u32,
}

/// Observed usage returned with a successful child result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Epoch ticks consumed.
    pub preempt_ticks: u32,
    /// Wall-clock milliseconds consumed.
    pub wall_clock_ms: u32,
    /// Peak memory bytes.
    pub memory_bytes: u64,
    /// Output bytes produced.
    pub output_bytes: u32,
}

/// Child tool reference resolved against the parent's snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRef {
    /// Policy alias.
    Alias(String),
    /// Raw tool digest bytes.
    Digest(Vec<u8>),
}

/// Kill cause for `delegate-error::child-killed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillCause {
    /// Epoch preempt.
    Preempted,
    /// Wall-clock budget.
    WallClock,
    /// Memory budget.
    Memory,
    /// Output budget.
    Output,
    /// Parent dropped / cancelled.
    ParentDropped,
}
