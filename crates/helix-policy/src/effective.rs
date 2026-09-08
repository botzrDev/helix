//! Pure delegation composition (M2-03 / HLX-16).
//!
//! Authority: [`effective_caps`] = `attenuate(parent, meet(child_policy, requested))`.
//! Resources: [`effective_budget`] requires the requested (or ADR-009 default) budget
//! to be [`ResourceBudget::is_within`] both ceilings; result is the componentwise
//! [`ResourceBudget::min`]. Depth and fan-out helpers return
//! [`DelegationRefuse::Depth`] / [`DelegationRefuse::Fanout`] for
//! `DelegationRefused{reason}` audit rows. Wire capability sets are rematerialized
//! against the request guard's intern table; a path or authority absent from the
//! snapshot is [`DelegationRefuse::Escalation`].
//!
//! Enforcement site is `runtime::delegate` (M4-08 / HLX-31). Decision logic lives
//! here so POL-6 and bound unit tests need no wasmtime.
//!
//! Cites: `policy-format.md` §3, ADR-008 A.3/A.4, ADR-009 A.1/A.2/A.3, test-plan POL-6.

use helix_caps::{
    CapabilitySet, CapsError, DirGrant, FileGrant, HostGrant, Interface, Interner, ResourceBudget,
};

use crate::PolicyGuard;

/// Why a child delegation was refused (`DelegationRefused{reason}` / `delegate-error`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationRefuse {
    /// Requested authority or budget exceeds a parent/policy ceiling, or a wire
    /// path/authority is absent from the snapshot intern table (ADR-008 A.3).
    #[error("delegation escalation: {0}")]
    Escalation(String),
    /// `max_delegation_depth` would be exceeded (ADR-008 A.4 / ADR-009 A.3).
    #[error("delegation refused: depth")]
    Depth,
    /// `max_children` would be exceeded (`JoinSet::len()` at call time).
    #[error("delegation refused: fanout")]
    Fanout,
}

impl DelegationRefuse {
    /// Stable reason string for audit `DelegationRefused{reason}` and WIT mapping.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Escalation(_) => "escalation",
            Self::Depth => "depth",
            Self::Fanout => "fanout",
        }
    }
}

const INTERFACES: [Interface; 5] = [
    Interface::Stdio,
    Interface::Clocks,
    Interface::Random,
    Interface::Filesystem,
    Interface::HttpOutbound,
];

/// Child effective authority:
/// `attenuate(parent_effective, meet(child_policy, requested))`.
///
/// Pure. Both the child's policy grant and the parent's effective set bound the
/// result (policy-format §3, ADR-009 A.1).
///
/// # Errors
///
/// [`DelegationRefuse::Escalation`] when the meet is not a subset of `parent_effective`.
pub fn effective_caps(
    parent_effective: &CapabilitySet,
    child_policy: &CapabilitySet,
    requested: &CapabilitySet,
) -> Result<CapabilitySet, DelegationRefuse> {
    let meet = child_policy.meet(requested);
    CapabilitySet::attenuate(parent_effective, &meet).map_err(caps_to_refuse)
}

/// Compose resource ceilings for a delegated child (ADR-008 A.4).
///
/// - When `requested_budget` is `Some`, it must be [`ResourceBudget::is_within`]
///   both `child_policy_budget` and `parent_budget`; the result is the
///   componentwise [`ResourceBudget::min`] of the three (equal to the request
///   when the checks pass).
/// - When `requested_budget` is `None`, the result is
///   `min(parent_budget, child_policy_budget)` (ADR-009 A.2: absent budget on
///   the host import).
///
/// # Errors
///
/// [`DelegationRefuse::Escalation`] when a present request exceeds either ceiling.
pub fn effective_budget(
    parent_budget: &ResourceBudget,
    child_policy_budget: &ResourceBudget,
    requested_budget: Option<&ResourceBudget>,
) -> Result<ResourceBudget, DelegationRefuse> {
    match requested_budget {
        None => Ok(parent_budget.min(child_policy_budget)),
        Some(requested) => {
            if !requested.is_within(child_policy_budget) || !requested.is_within(parent_budget) {
                return Err(DelegationRefuse::Escalation(
                    "requested budget exceeds parent or child policy ceiling".to_owned(),
                ));
            }
            Ok(requested.min(child_policy_budget).min(parent_budget))
        }
    }
}

/// Refuse when spawning a child would exceed `max_delegation_depth`.
///
/// `current_depth` is the parent's depth from the root (root = 0). The child
/// would be at `current_depth + 1`. Enforcement site is `runtime::delegate`
/// (ADR-009 A.3); this helper is the pure predicate.
///
/// # Errors
///
/// [`DelegationRefuse::Depth`] when `current_depth >= max_delegation_depth`.
pub fn check_depth(current_depth: u32, max_delegation_depth: u32) -> Result<(), DelegationRefuse> {
    if current_depth >= max_delegation_depth {
        Err(DelegationRefuse::Depth)
    } else {
        Ok(())
    }
}

/// Refuse when `join_set_len` already equals or exceeds `max_children`.
///
/// `join_set_len` is `JoinSet::len()` at the moment of the host call
/// (ADR-009 A.3). Adding one more child would exceed the fan-out bound.
///
/// # Errors
///
/// [`DelegationRefuse::Fanout`] when `join_set_len as u32 >= max_children`.
pub fn check_fanout(join_set_len: usize, max_children: u32) -> Result<(), DelegationRefuse> {
    let len = u32::try_from(join_set_len).unwrap_or(u32::MAX);
    if len >= max_children {
        Err(DelegationRefuse::Fanout)
    } else {
        Ok(())
    }
}

/// Rematerialize a wire [`CapabilitySet`] against the request tree's guard intern table.
///
/// Lookup-only: a path or authority absent from the snapshot cannot be interned
/// and is [`DelegationRefuse::Escalation`] (ADR-008 A.3). The returned set owns
/// a clone of the snapshot interner so lattice ops share ids with policy grants.
///
/// # Errors
///
/// [`DelegationRefuse::Escalation`] when a path/authority is missing from the
/// snapshot, the wire set has no resolvable interner for non-empty grants, or
/// [`CapabilitySet::new`] rejects the remapped grants.
pub fn intern_against_guard(
    wire: &CapabilitySet,
    guard: &PolicyGuard,
) -> Result<CapabilitySet, DelegationRefuse> {
    intern_against(wire, guard.interner())
}

/// Rematerialize a wire [`CapabilitySet`] against a snapshot [`Interner`].
///
/// Same rules as [`intern_against_guard`]; exposed for unit tests without a
/// full [`PolicyGuard`].
///
/// # Errors
///
/// See [`intern_against_guard`].
pub fn intern_against(
    wire: &CapabilitySet,
    snapshot: &Interner,
) -> Result<CapabilitySet, DelegationRefuse> {
    let interfaces: Vec<Interface> = INTERFACES.into_iter().filter(|i| wire.has(*i)).collect();

    let wire_intern = wire.interner();
    let needs_paths = !wire.files().is_empty() || !wire.dirs().is_empty();
    let needs_hosts = !wire.hosts().is_empty();

    if (needs_paths || needs_hosts) && wire_intern.is_empty() {
        return Err(DelegationRefuse::Escalation(
            "wire CapabilitySet has no interner to resolve paths/authorities".to_owned(),
        ));
    }

    let files = wire
        .files()
        .iter()
        .map(|f| {
            let path = wire_intern.path(f.path());
            let id = snapshot.get_path(path).ok_or_else(|| {
                DelegationRefuse::Escalation(format!("not interned: {}", path.display()))
            })?;
            Ok(FileGrant::new(id, f.mode()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let dirs = wire
        .dirs()
        .iter()
        .map(|d| {
            let path = wire_intern.path(d.root());
            let id = snapshot.get_path(path).ok_or_else(|| {
                DelegationRefuse::Escalation(format!("not interned: {}", path.display()))
            })?;
            Ok(DirGrant::new(id, d.mode()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let hosts = wire
        .hosts()
        .iter()
        .map(|h| {
            let authority = wire_intern.authority(h.authority());
            let id = snapshot.get_authority(authority).ok_or_else(|| {
                DelegationRefuse::Escalation(format!("not interned: {authority}"))
            })?;
            Ok(HostGrant::new(id, h.methods()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    CapabilitySet::new(&interfaces, files, dirs, hosts)
        .map(|set| set.with_interner(snapshot.clone()))
        .map_err(caps_to_refuse)
}

fn caps_to_refuse(err: CapsError) -> DelegationRefuse {
    match err {
        CapsError::Escalation(s) | CapsError::NotInterned(s) => DelegationRefuse::Escalation(s),
        other => DelegationRefuse::Escalation(other.to_string()),
    }
}
