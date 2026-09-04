//! Resource ceilings sibling of `CapabilitySet` (ADR-008 A.4).

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
    ) -> ResourceBudget {
        Self {
            preempt_ticks,
            wall_clock_ms,
            memory_bytes,
            output_bytes,
            max_delegation_depth,
            max_children,
            max_concurrent_instances,
        }
    }

    /// Guest preemption deadline in milliseconds (tick is pinned at 1 ms).
    #[must_use]
    pub fn preempt_ticks(&self) -> u32 {
        self.preempt_ticks
    }
    /// Hard deadline including host calls, in milliseconds.
    #[must_use]
    pub fn wall_clock_ms(&self) -> u32 {
        self.wall_clock_ms
    }
    /// Linear memory ceiling in bytes.
    #[must_use]
    pub fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }
    /// Maximum result size returned to the caller.
    #[must_use]
    pub fn output_bytes(&self) -> u32 {
        self.output_bytes
    }
    /// Depth counted from the root request.
    #[must_use]
    pub fn max_delegation_depth(&self) -> u32 {
        self.max_delegation_depth
    }
    /// Fan-out per parent, counted in the parent's `JoinSet`.
    #[must_use]
    pub fn max_children(&self) -> u32 {
        self.max_children
    }
    /// Live instances attributable to one Identity on one gateway.
    #[must_use]
    pub fn max_concurrent_instances(&self) -> u32 {
        self.max_concurrent_instances
    }

    /// Componentwise `self[i] <= ceiling[i]` for every field. Reflexive and
    /// transitive (CAPS-14).
    #[must_use]
    pub fn is_within(&self, ceiling: &ResourceBudget) -> bool {
        self.preempt_ticks <= ceiling.preempt_ticks
            && self.wall_clock_ms <= ceiling.wall_clock_ms
            && self.memory_bytes <= ceiling.memory_bytes
            && self.output_bytes <= ceiling.output_bytes
            && self.max_delegation_depth <= ceiling.max_delegation_depth
            && self.max_children <= ceiling.max_children
            && self.max_concurrent_instances <= ceiling.max_concurrent_instances
    }

    /// Componentwise greatest lower bound (CAPS-14).
    #[must_use]
    pub fn min(&self, other: &ResourceBudget) -> ResourceBudget {
        Self {
            preempt_ticks: self.preempt_ticks.min(other.preempt_ticks),
            wall_clock_ms: self.wall_clock_ms.min(other.wall_clock_ms),
            memory_bytes: self.memory_bytes.min(other.memory_bytes),
            output_bytes: self.output_bytes.min(other.output_bytes),
            max_delegation_depth: self.max_delegation_depth.min(other.max_delegation_depth),
            max_children: self.max_children.min(other.max_children),
            max_concurrent_instances: self
                .max_concurrent_instances
                .min(other.max_concurrent_instances),
        }
    }
}
