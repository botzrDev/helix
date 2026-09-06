//! POL-6 and budget / depth / fan-out unit coverage (test-plan.md). M2-03 / HLX-16.

use std::path::Path;

use helix_caps::{
    CapabilitySet, FileMode, HostGrant, Interface, Interner, Method, MethodMask, ResourceBudget,
};
use helix_policy::{
    check_depth, check_fanout, effective_budget, effective_caps, encode_thumbprint, intern_against,
    parse_identity_thumbprint, parse_tool_digest, resolve_host, DelegationRefuse, MapFs,
    MemoryArtifactStore, PathKind, PolicyFile, PolicyGuard,
};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn valid_toml() -> String {
    format!(
        r#"
version = 1

[tools]
read_db = "{DIGEST_A}"
sum_pdf = "{DIGEST_B}"

[budgets.default]
wall_clock_ms = 2000
memory_bytes = 67108864
output_bytes = 1048576
max_delegation_depth = 2
max_children = 8

[budgets.heavy]
preempt_ticks = 5000
wall_clock_ms = 30000
memory_bytes = 536870912
output_bytes = 8388608
max_delegation_depth = 2
max_children = 8

[identities]
billing = "{billing}"
research = "{research}"

[[grants]]
identity = "billing"
tool = "read_db"
digest = "{DIGEST_A}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"
files = [{{ path = "/srv/data/customers.sqlite", mode = "read" }}]

[[grants]]
identity = "research"
tool = "sum_pdf"
digest = "{DIGEST_B}"
interfaces = ["stdio", "clocks", "random", "filesystem", "http_outbound"]
budget = "heavy"
dirs = [{{ path = "/srv/inbox", mode = "read" }}]
hosts = [{{ authority = "api.example.com:443", methods = ["GET", "POST"] }}]
"#,
        billing = thumb(1),
        research = thumb(2),
    )
}

fn map_fs_ok() -> MapFs {
    MapFs::new()
        .insert("/srv", PathKind::Directory)
        .insert("/srv/data", PathKind::Directory)
        .insert("/srv/data/customers.sqlite", PathKind::File)
        .insert("/srv/inbox", PathKind::Directory)
}

fn store_ok() -> MemoryArtifactStore {
    let a = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let b = parse_tool_digest("sum_pdf", DIGEST_B).unwrap();
    MemoryArtifactStore::new()
        .with_digest(a)
        .with_digest(b)
        .with_runtime_max(256)
}

fn load_guard() -> PolicyGuard {
    let file = PolicyFile::parse(&valid_toml()).expect("toml");
    let snap = resolve_host(&file, &store_ok(), &map_fs_ok()).expect("resolve");
    PolicyGuard::from_snapshot(snap, 300)
}

fn budget(
    preempt: u32,
    wall: u32,
    mem: u64,
    out: u32,
    depth: u32,
    children: u32,
    concurrent: u32,
) -> ResourceBudget {
    ResourceBudget::new(preempt, wall, mem, out, depth, children, concurrent)
}

/// POL-6: effective set equals `attenuate(parent, meet(policy(child), requested))`.
#[test]
fn pol6_effective_caps_equals_attenuate_meet() {
    let guard = load_guard();
    let identity = parse_identity_thumbprint("billing", &thumb(1)).unwrap();
    let child_digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let (child_policy, _) = guard.policy(&identity, &child_digest).expect("grant");

    // Parent holds a superset of the child policy (stdio+clocks+filesystem+file).
    let parent_effective = child_policy.clone();

    // Request a strict subset: stdio + clocks only (no filesystem grants).
    let requested = CapabilitySet::new(
        &[Interface::Stdio, Interface::Clocks],
        vec![],
        vec![],
        vec![],
    )
    .unwrap()
    .with_interner(guard.interner().clone());

    let got = effective_caps(&parent_effective, child_policy, &requested).expect("ok");
    let expected = {
        let meet = child_policy.meet(&requested);
        CapabilitySet::attenuate(&parent_effective, &meet).expect("attenuate")
    };
    assert_eq!(got, expected);
    assert!(got.has(Interface::Stdio));
    assert!(got.has(Interface::Clocks));
    assert!(!got.has(Interface::Filesystem));
    assert!(got.files().is_empty());
}

#[test]
fn pol6_effective_caps_escalation_when_requested_exceeds_parent() {
    let guard = load_guard();
    let billing = parse_identity_thumbprint("billing", &thumb(1)).unwrap();
    let research = parse_identity_thumbprint("research", &thumb(2)).unwrap();
    let read_db = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let sum_pdf = parse_tool_digest("sum_pdf", DIGEST_B).unwrap();

    let (parent_effective, _) = guard.policy(&billing, &read_db).expect("billing grant");
    let (child_policy, _) = guard.policy(&research, &sum_pdf).expect("research grant");

    // Request the research grant (http + dirs) while parent is billing (no http).
    let err = effective_caps(parent_effective, child_policy, child_policy).unwrap_err();
    assert!(matches!(err, DelegationRefuse::Escalation(_)));
    assert_eq!(err.reason(), "escalation");
}

#[test]
fn effective_budget_absent_is_min_of_ceilings() {
    let parent = budget(2000, 2000, 64 << 20, 1 << 20, 2, 8, 32);
    let child = budget(500, 1000, 32 << 20, 512 << 10, 1, 4, 16);
    let got = effective_budget(&parent, &child, None).expect("ok");
    assert_eq!(got, parent.min(&child));
    assert!(got.is_within(&parent));
    assert!(got.is_within(&child));
}

#[test]
fn effective_budget_requested_within_both_returns_min() {
    let parent = budget(2000, 2000, 64 << 20, 1 << 20, 2, 8, 32);
    let child = budget(1000, 1500, 48 << 20, 768 << 10, 2, 8, 32);
    let requested = budget(500, 800, 16 << 20, 256 << 10, 1, 2, 8);
    let got = effective_budget(&parent, &child, Some(&requested)).expect("ok");
    assert_eq!(got, requested);
    assert!(got.is_within(&parent));
    assert!(got.is_within(&child));
}

#[test]
fn effective_budget_requested_exceeds_parent_refused() {
    let parent = budget(500, 500, 16 << 20, 256 << 10, 1, 2, 8);
    let child = budget(2000, 2000, 64 << 20, 1 << 20, 2, 8, 32);
    let requested = budget(1000, 1000, 32 << 20, 512 << 10, 1, 2, 8);
    let err = effective_budget(&parent, &child, Some(&requested)).unwrap_err();
    assert!(matches!(err, DelegationRefuse::Escalation(_)));
}

#[test]
fn effective_budget_requested_exceeds_child_policy_refused() {
    let parent = budget(2000, 2000, 64 << 20, 1 << 20, 2, 8, 32);
    let child = budget(500, 500, 16 << 20, 256 << 10, 1, 2, 8);
    let requested = budget(1000, 1000, 32 << 20, 512 << 10, 1, 2, 8);
    let err = effective_budget(&parent, &child, Some(&requested)).unwrap_err();
    assert!(matches!(err, DelegationRefuse::Escalation(_)));
}

#[test]
fn check_depth_allows_beneath_max() {
    assert!(check_depth(0, 2).is_ok());
    assert!(check_depth(1, 2).is_ok());
}

#[test]
fn check_depth_refuses_at_and_above_max() {
    assert_eq!(check_depth(2, 2).unwrap_err(), DelegationRefuse::Depth);
    assert_eq!(check_depth(3, 2).unwrap_err(), DelegationRefuse::Depth);
    assert_eq!(check_depth(0, 0).unwrap_err().reason(), "depth");
}

#[test]
fn check_fanout_allows_beneath_max() {
    assert!(check_fanout(0, 8).is_ok());
    assert!(check_fanout(7, 8).is_ok());
}

#[test]
fn check_fanout_refuses_at_and_above_max() {
    assert_eq!(check_fanout(8, 8).unwrap_err(), DelegationRefuse::Fanout);
    assert_eq!(check_fanout(9, 8).unwrap_err(), DelegationRefuse::Fanout);
    assert_eq!(check_fanout(0, 0).unwrap_err().reason(), "fanout");
}

#[test]
fn intern_against_snapshot_paths_ok() {
    let guard = load_guard();
    let snapshot = guard.interner();

    // Build a throwaway wire set that names a path already in the snapshot.
    let mut wire_intern = Interner::new();
    let path_id = wire_intern.intern_path(Path::new("/srv/data/customers.sqlite"));
    let wire = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![helix_caps::FileGrant::new(path_id, FileMode::Read)],
        vec![],
        vec![],
    )
    .unwrap()
    .with_interner(wire_intern);

    let remapped = intern_against(&wire, snapshot).expect("intern");
    assert_eq!(remapped.files().len(), 1);
    assert_eq!(
        remapped.interner().path(remapped.files()[0].path()),
        Path::new("/srv/data/customers.sqlite")
    );
    // Remapped onto the snapshot table: same PathId as a direct lookup.
    assert_eq!(
        remapped.files()[0].path(),
        snapshot
            .get_path(Path::new("/srv/data/customers.sqlite"))
            .expect("path in snapshot")
    );
}

#[test]
fn intern_against_unknown_path_is_escalation() {
    let guard = load_guard();
    let mut wire_intern = Interner::new();
    let path_id = wire_intern.intern_path(Path::new("/etc/passwd"));
    let wire = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![helix_caps::FileGrant::new(path_id, FileMode::Read)],
        vec![],
        vec![],
    )
    .unwrap()
    .with_interner(wire_intern);

    let err = intern_against(&wire, guard.interner()).unwrap_err();
    assert!(matches!(err, DelegationRefuse::Escalation(ref s) if s.contains("/etc/passwd")));
    assert_eq!(err.reason(), "escalation");
}

#[test]
fn intern_against_unknown_authority_is_escalation() {
    let guard = load_guard();
    let mut wire_intern = Interner::new();
    let auth_id = wire_intern.intern_authority("evil.example.com:443");
    let wire = CapabilitySet::new(
        &[Interface::HttpOutbound],
        vec![],
        vec![],
        vec![HostGrant::new(auth_id, MethodMask::new(&[Method::Get]))],
    )
    .unwrap()
    .with_interner(wire_intern);

    let err = intern_against(&wire, guard.interner()).unwrap_err();
    assert!(matches!(err, DelegationRefuse::Escalation(ref s) if s.contains("evil.example.com")));
}

#[test]
fn intern_against_json_wire_round_trip_known_host() {
    let guard = load_guard();
    let json = r#"{
        "interfaces": ["http_outbound"],
        "files": [],
        "dirs": [],
        "hosts": [{"authority": "api.example.com:443", "methods": ["GET"]}]
    }"#;
    let wire: CapabilitySet = serde_json::from_str(json).expect("wire deserialize");
    let remapped = intern_against(&wire, guard.interner()).expect("intern");
    assert!(remapped.has(Interface::HttpOutbound));
    assert_eq!(remapped.hosts().len(), 1);
    assert_eq!(
        remapped
            .interner()
            .authority(remapped.hosts()[0].authority()),
        "api.example.com:443"
    );
}
