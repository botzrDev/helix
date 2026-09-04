//! CAPS-8, CAPS-9, CAPS-12, CAPS-13, and CAPS-15 unit tests (test-plan.md).

use std::path::Path;

use crate::{
    CapabilitySet, CapsError, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner,
    Method, MethodMask, RequestId, ResourceBudget,
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

/// CAPS-12: unknown method names and non-array interface encodings are fatal.
#[test]
fn caps12_unknown_names_and_non_array_interfaces() {
    let unknown_method = r#"{
      "interfaces": ["http_outbound"],
      "files": [],
      "dirs": [],
      "hosts": [{ "authority": "api.example.com:443", "methods": ["GET", "TRACE"] }]
    }"#;
    let err = serde_json::from_str::<CapabilitySet>(unknown_method).unwrap_err();
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("trace") || msg.contains("unknown") || msg.contains("method"),
        "unexpected error: {err}"
    );

    let connect = r#"{
      "interfaces": ["http_outbound"],
      "files": [],
      "dirs": [],
      "hosts": [{ "authority": "api.example.com:443", "methods": ["CONNECT"] }]
    }"#;
    assert!(serde_json::from_str::<CapabilitySet>(connect).is_err());

    let unknown_iface = r#"{
      "interfaces": ["stdio", "environment"],
      "files": [],
      "dirs": [],
      "hosts": []
    }"#;
    let err = serde_json::from_str::<CapabilitySet>(unknown_iface).unwrap_err();
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("environment") || msg.contains("unknown"),
        "unexpected error: {err}"
    );

    let as_int = r#"{
      "interfaces": 31,
      "files": [],
      "dirs": [],
      "hosts": []
    }"#;
    assert!(
        serde_json::from_str::<CapabilitySet>(as_int).is_err(),
        "integer interfaces encoding must be rejected"
    );

    let as_bitmask = r#"{
      "interfaces": 15,
      "files": [],
      "dirs": [],
      "hosts": []
    }"#;
    assert!(
        serde_json::from_str::<CapabilitySet>(as_bitmask).is_err(),
        "raw bitmask interfaces encoding must be rejected"
    );

    let as_object = r#"{
      "interfaces": { "bits": 15 },
      "files": [],
      "dirs": [],
      "hosts": []
    }"#;
    assert!(serde_json::from_str::<CapabilitySet>(as_object).is_err());

    let methods_as_bits = r#"{
      "interfaces": ["http_outbound"],
      "files": [],
      "dirs": [],
      "hosts": [{ "authority": "api.example.com:443", "methods": 3 }]
    }"#;
    assert!(
        serde_json::from_str::<CapabilitySet>(methods_as_bits).is_err(),
        "MethodMask integer bitmask must be rejected"
    );
}

/// CAPS-13: prefix containment edges for `DirGrant`.
#[test]
#[allow(clippy::similar_names)] // /a, /a/b, /a/bc are the cases under test
fn caps13_prefix_containment_edges() {
    let mut intern = Interner::new();
    let root = intern.intern_path(Path::new("/"));
    let a = intern.intern_path(Path::new("/a"));
    let ab = intern.intern_path(Path::new("/a/b"));
    let abc = intern.intern_path(Path::new("/a/bc"));

    assert!(!intern.is_prefix(ab, abc), "/a/b must not contain /a/bc");
    assert!(!intern.is_prefix(abc, ab));

    assert!(intern.is_prefix(root, root));
    assert!(intern.is_prefix(root, a));
    assert!(intern.is_prefix(root, ab));
    assert!(intern.is_prefix(root, abc), "/ contains everything");

    assert!(intern.is_prefix(ab, ab), "equal roots contain each other");
    assert!(intern.is_prefix(abc, abc));

    let fs = [Interface::Filesystem];
    let set = |root_id, mode: FileMode| {
        CapabilitySet::new(&fs, vec![], vec![DirGrant::new(root_id, mode)], vec![])
            .unwrap()
            .with_interner(intern.clone())
    };

    let ab_read = set(ab, FileMode::Read);
    let ab_write = set(ab, FileMode::ReadWrite);
    let abc_read = set(abc, FileMode::Read);
    let abc_write = set(abc, FileMode::ReadWrite);
    let root_write = set(root, FileMode::ReadWrite);
    let a_read = set(a, FileMode::Read);
    let a_write = set(a, FileMode::ReadWrite);

    assert!(!abc_read.is_subset_of(&ab_read));
    assert!(!ab_read.is_subset_of(&abc_read));

    assert!(ab_read.is_subset_of(&root_write));
    assert!(abc_read.is_subset_of(&root_write));
    assert!(abc_write.is_subset_of(&root_write));

    assert!(ab_read.is_subset_of(&ab_read));
    assert!(ab_read.is_subset_of(&ab_write));
    assert!(!ab_write.is_subset_of(&ab_read));

    assert!(ab_read.is_subset_of(&a_read));
    assert!(ab_read.is_subset_of(&a_write));
    assert!(!ab_write.is_subset_of(&a_read), "mode ordering respected");
    assert!(ab_write.is_subset_of(&a_write));
}

/// CAPS-15: `RequestId` JSON is a 26-char Crockford ULID string.
#[test]
fn caps15_request_id_ulid_json() {
    let id = RequestId::from_u128(0x018F_2C2A_5E0B_4C3D_9A1E_7B8C_6D5E_4F30);
    let json = serde_json::to_string(&id).unwrap();
    assert!(json.starts_with('"') && json.ends_with('"'), "JSON: {json}");
    let inner = json.trim_matches('"');
    assert_eq!(inner.len(), 26, "ULID text must be 26 chars, got {inner}");
    let value = serde_json::to_value(id).unwrap();
    assert!(value.is_string());
    assert_eq!(value.as_str().unwrap().len(), 26);

    let back: RequestId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, id);

    let zero = RequestId::from_u128(0);
    let zero_json = serde_json::to_string(&zero).unwrap();
    assert_eq!(zero_json, "\"00000000000000000000000000\"");
    assert_eq!(serde_json::from_str::<RequestId>(&zero_json).unwrap(), zero);

    assert!(serde_json::from_str::<RequestId>("0").is_err());
    assert!(serde_json::from_str::<RequestId>("12345").is_err());
    assert!(serde_json::from_str::<RequestId>("340282366920938463463374607431768211455").is_err());

    assert!(serde_json::from_str::<RequestId>("\"\"").is_err());
    assert!(serde_json::from_str::<RequestId>("\"01ARZ3NDEKTSV4RRFFQ69G5FA\"").is_err());
    assert!(serde_json::from_str::<RequestId>("\"01ARZ3NDEKTSV4RRFFQ69G5FAVA\"").is_err());
    assert!(serde_json::from_str::<RequestId>("\"IIIIIIIIIIIIIIIIIIIIIIIIII\"").is_err());
    assert!(serde_json::from_str::<RequestId>("\"0000000000000000000000000U\"").is_err());
    assert!(serde_json::from_str::<RequestId>("\"0000000000000000000000000O\"").is_err());
    assert!(serde_json::from_str::<RequestId>("\"LLLLLLLLLLLLLLLLLLLLLLLLLL\"").is_err());
}
