//! CAPS-8 and CAPS-9 unit tests (test-plan.md).

use std::path::Path;

use crate::{
    CapabilitySet, CapsError, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner,
    Method, MethodMask, ResourceBudget,
};

fn sample_json() -> &'static str {
    r#"{
      "interfaces": ["stdio", "clocks", "random", "filesystem", "http_outbound"],
      "files": [{ "path": "/srv/data/report.csv", "mode": "read" }],
      "dirs": [{ "path": "/srv/inbox", "mode": "read_write" }],
      "hosts": [{ "authority": "api.example.com:443", "methods": ["GET", "POST"] }]
    }"#
}

#[test]
fn caps8_new_rejects_relative_path_via_wire() {
    let json = r#"{
      "interfaces": ["filesystem"],
      "files": [{ "path": "relative/file.txt", "mode": "read" }],
      "dirs": [],
      "hosts": []
    }"#;
    let err = serde_json::from_str::<CapabilitySet>(json).unwrap_err();
    assert!(
        err.to_string().contains("canonical") || err.to_string().contains("relative"),
        "unexpected error: {err}"
    );
}

#[test]
fn caps8_new_rejects_dotdot_component_via_wire() {
    let json = r#"{
      "interfaces": ["filesystem"],
      "files": [{ "path": "/srv/../etc/passwd", "mode": "read" }],
      "dirs": [],
      "hosts": []
    }"#;
    let err = serde_json::from_str::<CapabilitySet>(json).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("canonical") || msg.contains(".."),
        "unexpected error: {msg}"
    );
}

#[test]
fn caps8_new_rejects_duplicate_paths() {
    let mut interner = Interner::new();
    let p = interner.intern_path(Path::new("/srv/a"));
    let err = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![
            FileGrant::new(p, FileMode::Read),
            FileGrant::new(p, FileMode::ReadWrite),
        ],
        vec![],
        vec![],
    )
    .unwrap_err();
    assert!(matches!(err, CapsError::Duplicate(_)));
}

#[test]
fn caps8_new_rejects_duplicate_dir_roots() {
    let mut interner = Interner::new();
    let p = interner.intern_path(Path::new("/srv/inbox"));
    let err = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![
            DirGrant::new(p, FileMode::Read),
            DirGrant::new(p, FileMode::ReadWrite),
        ],
        vec![],
    )
    .unwrap_err();
    assert!(matches!(err, CapsError::Duplicate(_)));
}

#[test]
fn caps8_new_rejects_duplicate_authorities() {
    let mut interner = Interner::new();
    let a = interner.intern_authority("api.example.com:443");
    let err = CapabilitySet::new(
        &[Interface::HttpOutbound],
        vec![],
        vec![],
        vec![
            HostGrant::new(a, MethodMask::new(&[Method::Get])),
            HostGrant::new(a, MethodMask::new(&[Method::Post])),
        ],
    )
    .unwrap_err();
    assert!(matches!(err, CapsError::Duplicate(_)));
}

#[test]
fn caps8_new_rejects_orphan_file_grants() {
    let mut interner = Interner::new();
    let p = interner.intern_path(Path::new("/srv/a"));
    let err = CapabilitySet::new(
        &[Interface::Stdio],
        vec![FileGrant::new(p, FileMode::Read)],
        vec![],
        vec![],
    )
    .unwrap_err();
    assert_eq!(err, CapsError::OrphanGrant(Interface::Filesystem));
}

#[test]
fn caps8_new_rejects_orphan_host_grants() {
    let mut interner = Interner::new();
    let a = interner.intern_authority("api.example.com:443");
    let err = CapabilitySet::new(
        &[Interface::Stdio],
        vec![],
        vec![],
        vec![HostGrant::new(a, MethodMask::new(&[Method::Get]))],
    )
    .unwrap_err();
    assert_eq!(err, CapsError::OrphanGrant(Interface::HttpOutbound));
}

#[test]
fn caps9_json_round_trip_every_field() {
    let set: CapabilitySet = serde_json::from_str(sample_json()).unwrap();
    assert!(set.has(Interface::Stdio));
    assert!(set.has(Interface::Clocks));
    assert!(set.has(Interface::Random));
    assert!(set.has(Interface::Filesystem));
    assert!(set.has(Interface::HttpOutbound));
    assert_eq!(set.files().len(), 1);
    assert_eq!(set.dirs().len(), 1);
    assert_eq!(set.hosts().len(), 1);
    assert_eq!(
        set.interner().path(set.files()[0].path()),
        Path::new("/srv/data/report.csv")
    );
    assert_eq!(set.files()[0].mode(), FileMode::Read);
    assert_eq!(
        set.interner().path(set.dirs()[0].root()),
        Path::new("/srv/inbox")
    );
    assert_eq!(set.dirs()[0].mode(), FileMode::ReadWrite);
    assert_eq!(
        set.interner().authority(set.hosts()[0].authority()),
        "api.example.com:443"
    );
    assert!(set.hosts()[0]
        .methods()
        .is_subset_of(MethodMask::new(&[Method::Get, Method::Post])));
    assert!(MethodMask::new(&[Method::Get, Method::Post]).is_subset_of(set.hosts()[0].methods()));

    let encoded = serde_json::to_string(&set).unwrap();
    let again: CapabilitySet = serde_json::from_str(&encoded).unwrap();
    assert_eq!(set, again);

    let v: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert!(v.get("interfaces").is_some());
    assert!(v.get("files").is_some());
    assert!(v.get("dirs").is_some());
    assert!(v.get("hosts").is_some());
    assert!(
        v.get("budget").is_none(),
        "budget is a sibling, not a CapabilitySet field"
    );
}

#[test]
fn caps9_unknown_interface_name_fails_to_deserialize() {
    let json = r#"{
      "interfaces": ["stdio", "environment"],
      "files": [],
      "dirs": [],
      "hosts": []
    }"#;
    let err = serde_json::from_str::<CapabilitySet>(json).unwrap_err();
    assert!(
        err.to_string().to_ascii_lowercase().contains("environment")
            || err.to_string().to_ascii_lowercase().contains("unknown"),
        "unexpected error: {err}"
    );
}

#[test]
fn resource_budget_is_within_and_min() {
    let high = ResourceBudget::new(500, 2000, 64 * 1024 * 1024, 1024 * 1024, 2, 8, 32);
    let low = ResourceBudget::new(100, 500, 1024, 512, 1, 2, 4);
    assert!(low.is_within(&high));
    assert!(!high.is_within(&low));
    assert!(high.is_within(&high));
    let m = high.min(&low);
    assert_eq!(m.preempt_ticks(), 100);
    assert_eq!(m.wall_clock_ms(), 500);
    assert_eq!(m.memory_bytes(), 1024);
    assert_eq!(m.output_bytes(), 512);
    assert_eq!(m.max_delegation_depth(), 1);
    assert_eq!(m.max_children(), 2);
    assert_eq!(m.max_concurrent_instances(), 4);
}

#[test]
fn empty_const_is_bottom() {
    assert_eq!(CapabilitySet::EMPTY.interfaces_bits(), 0);
    assert!(CapabilitySet::EMPTY.files().is_empty());
    assert!(CapabilitySet::EMPTY.dirs().is_empty());
    assert!(CapabilitySet::EMPTY.hosts().is_empty());
}
