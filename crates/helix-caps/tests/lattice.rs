//! CAPS-1 through CAPS-7 and CAPS-10 (test-plan.md). Generators include `dirs`.

use std::path::Path;

use helix_caps::{
    CapabilitySet, CapsError, DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner,
    Method, MethodMask,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

/// Miri-friendly proptest config: no file persistence (getcwd under isolation),
/// and fewer cases under Miri so ST-5 finishes in CI.
fn prop_config() -> ProptestConfig {
    #[cfg(miri)]
    let cases = 32;
    #[cfg(not(miri))]
    let cases = ProptestConfig::default().cases;
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

const ALL_IFACES: [Interface; 5] = [
    Interface::Stdio,
    Interface::Clocks,
    Interface::Random,
    Interface::Filesystem,
    Interface::HttpOutbound,
];

const ALL_METHODS: [Method; 6] = [
    Method::Get,
    Method::Head,
    Method::Post,
    Method::Put,
    Method::Patch,
    Method::Delete,
];

const DIR_PATHS: [&str; 8] = [
    "/",
    "/a",
    "/a/b",
    "/a/bc",
    "/srv",
    "/srv/inbox",
    "/srv/data",
    "/etc",
];

const FILE_PATHS: [&str; 4] = ["/a/b/c", "/a/bc/x", "/srv/data/report.csv", "/etc/passwd"];

const HOSTS: [&str; 3] = ["api.example.com:443", "example.com:80", "localhost:8080"];

fn pool() -> Interner {
    let mut intern = Interner::new();
    for p in DIR_PATHS.iter().chain(FILE_PATHS.iter()) {
        intern.intern_path(Path::new(p));
    }
    for a in HOSTS {
        intern.intern_authority(a);
    }
    intern
}

fn mask_from_bits(bits: u8) -> MethodMask {
    let methods: Vec<Method> = ALL_METHODS
        .into_iter()
        .enumerate()
        .filter_map(|(i, m)| ((bits & (1 << i)) != 0).then_some(m))
        .collect();
    MethodMask::new(&methods)
}

fn interfaces_from_bits(bits: u8) -> Vec<Interface> {
    ALL_IFACES
        .into_iter()
        .enumerate()
        .filter_map(|(i, iface)| ((bits & (1 << i)) != 0).then_some(iface))
        .collect()
}

fn iface_only(bits: u8) -> CapabilitySet {
    CapabilitySet::new(&interfaces_from_bits(bits), vec![], vec![], vec![])
        .expect("interface-only set is valid")
}

fn canonicalize(set: &CapabilitySet) -> CapabilitySet {
    let intern = set.interner().clone();
    let dirs: Vec<DirGrant> = set
        .dirs()
        .iter()
        .copied()
        .filter(|d| {
            !set.dirs().iter().any(|other| {
                other.root() != d.root()
                    && intern.is_prefix(other.root(), d.root())
                    && d.mode() <= other.mode()
            })
        })
        .collect();
    let files: Vec<FileGrant> = set
        .files()
        .iter()
        .copied()
        .filter(|f| {
            !dirs
                .iter()
                .any(|d| intern.is_prefix(d.root(), f.path()) && f.mode() <= d.mode())
        })
        .collect();
    let interfaces: Vec<Interface> = ALL_IFACES.into_iter().filter(|i| set.has(*i)).collect();
    CapabilitySet::new(&interfaces, files, dirs, set.hosts().to_vec())
        .expect("canonical form preserves construction invariants")
        .with_interner(intern)
}

fn build(
    bits: u8,
    files: &[(usize, FileMode)],
    dirs: &[(usize, FileMode)],
    hosts: &[(usize, MethodMask)],
) -> CapabilitySet {
    let intern = pool();
    let interfaces = interfaces_from_bits(bits);
    let has_fs = interfaces.contains(&Interface::Filesystem);
    let has_http = interfaces.contains(&Interface::HttpOutbound);

    let mut file_mode = [None; FILE_PATHS.len()];
    let mut dir_mode = [None; DIR_PATHS.len()];
    let mut host_bits = [0u8; HOSTS.len()];
    if has_fs {
        for (idx, mode) in files {
            let i = *idx % FILE_PATHS.len();
            file_mode[i] = Some(file_mode[i].map_or(*mode, |m: FileMode| m.max(*mode)));
        }
        for (idx, mode) in dirs {
            let i = *idx % DIR_PATHS.len();
            dir_mode[i] = Some(dir_mode[i].map_or(*mode, |m: FileMode| m.max(*mode)));
        }
    }
    if has_http {
        for (idx, mask) in hosts {
            let i = *idx % HOSTS.len();
            host_bits[i] |= mask.bits();
        }
    }

    let file_grants: Vec<FileGrant> = file_mode
        .into_iter()
        .enumerate()
        .filter_map(|(i, mode)| {
            mode.map(|m| FileGrant::new(intern.get_path(Path::new(FILE_PATHS[i])).unwrap(), m))
        })
        .collect();
    let dir_grants: Vec<DirGrant> = dir_mode
        .into_iter()
        .enumerate()
        .filter_map(|(i, mode)| {
            mode.map(|m| DirGrant::new(intern.get_path(Path::new(DIR_PATHS[i])).unwrap(), m))
        })
        .collect();
    let host_grants: Vec<HostGrant> = host_bits
        .into_iter()
        .enumerate()
        .filter_map(|(i, b)| {
            if b == 0 {
                None
            } else {
                Some(HostGrant::new(
                    intern.get_authority(HOSTS[i]).unwrap(),
                    mask_from_bits(b),
                ))
            }
        })
        .collect();

    let set = CapabilitySet::new(&interfaces, file_grants, dir_grants, host_grants)
        .expect("generated grants match interface bits and have unique ids")
        .with_interner(intern);
    canonicalize(&set)
}

fn set_strategy() -> impl Strategy<Value = CapabilitySet> {
    (
        0u8..32,
        prop::collection::vec((0usize..FILE_PATHS.len(), prop::bool::ANY), 0..4),
        prop::collection::vec((0usize..DIR_PATHS.len(), prop::bool::ANY), 0..4),
        prop::collection::vec((0usize..HOSTS.len(), 1u8..=0b0011_1111), 0..3),
    )
        .prop_map(|(bits, files, dirs, hosts)| {
            let files: Vec<(usize, FileMode)> = files
                .into_iter()
                .map(|(i, rw)| {
                    (
                        i,
                        if rw {
                            FileMode::ReadWrite
                        } else {
                            FileMode::Read
                        },
                    )
                })
                .collect();
            let dirs: Vec<(usize, FileMode)> = dirs
                .into_iter()
                .map(|(i, rw)| {
                    (
                        i,
                        if rw {
                            FileMode::ReadWrite
                        } else {
                            FileMode::Read
                        },
                    )
                })
                .collect();
            let hosts: Vec<(usize, MethodMask)> = hosts
                .into_iter()
                .map(|(i, b)| (i, mask_from_bits(b)))
                .filter(|(_, m)| m.bits() != 0)
                .collect();
            build(bits, &files, &dirs, &hosts)
        })
}

// CAPS-1
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps1_is_subset_of_reflexive(a in set_strategy()) {
        prop_assert!(a.is_subset_of(&a));
    }
}

// CAPS-2
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps2_is_subset_of_antisymmetric(a in set_strategy(), b in set_strategy()) {
        if a.is_subset_of(&b) && b.is_subset_of(&a) {
            prop_assert_eq!(a, b);
        }
    }
}

// CAPS-3
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps3_is_subset_of_transitive(
        a in set_strategy(),
        b in set_strategy(),
        c in set_strategy(),
    ) {
        if a.is_subset_of(&b) && b.is_subset_of(&c) {
            prop_assert!(a.is_subset_of(&c));
        }
    }
}

// CAPS-4
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps4_attenuate_ok_iff_subset(p in set_strategy(), r in set_strategy()) {
        let ok = CapabilitySet::attenuate(&p, &r).is_ok();
        prop_assert_eq!(ok, r.is_subset_of(&p));
    }
}

// CAPS-5
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps5_attenuate_result_subset_of_parent(p in set_strategy(), r in set_strategy()) {
        if let Ok(s) = CapabilitySet::attenuate(&p, &r) {
            prop_assert!(s.is_subset_of(&p));
            prop_assert_eq!(s, r);
        }
    }
}

// CAPS-6
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps6_meet_is_glb(a in set_strategy(), b in set_strategy(), c in set_strategy()) {
        let m = a.meet(&b);
        prop_assert!(m.is_subset_of(&a));
        prop_assert!(m.is_subset_of(&b));
        if c.is_subset_of(&a) && c.is_subset_of(&b) {
            prop_assert!(c.is_subset_of(&m));
        }
    }
}

// CAPS-10
proptest! {
    #![proptest_config(prop_config())]
    #[test]
    fn caps10_empty_subset_of_every_x(x in set_strategy()) {
        prop_assert!(CapabilitySet::EMPTY.is_subset_of(&x));
        prop_assert!(x.has(Interface::Stdio) || !x.has(Interface::Stdio));
    }
}

/// CAPS-7: exhaustive 32 interface combinations over 5 bits, zero grants.
#[test]
fn caps7_exhaustive_32_interface_combos() {
    let sets: Vec<CapabilitySet> = (0u8..32).map(iface_only).collect();
    assert_eq!(sets.len(), 32);
    for (i, a) in sets.iter().enumerate() {
        let i = u64::try_from(i).unwrap();
        assert_eq!(a.interfaces_bits(), i);
        assert!(a.files().is_empty());
        assert!(a.dirs().is_empty());
        assert!(a.hosts().is_empty());
        for (bit, iface) in ALL_IFACES.iter().enumerate() {
            assert_eq!(a.has(*iface), i & (1 << bit) != 0);
        }
        for (j, b) in sets.iter().enumerate() {
            let j = u64::try_from(j).unwrap();
            assert_eq!(a.is_subset_of(b), i & !j == 0, "{i} ⊆ {j}");
            let meet = a.meet(b);
            assert_eq!(meet.interfaces_bits(), i & j);
            assert_eq!(CapabilitySet::attenuate(b, a).is_ok(), a.is_subset_of(b));
        }
    }
}

#[test]
fn caps10_empty_subset_hand_built() {
    let intern = pool();
    let dir = intern.get_path(Path::new("/srv/inbox")).unwrap();
    let set = CapabilitySet::new(
        &[Interface::Filesystem, Interface::Stdio],
        vec![],
        vec![DirGrant::new(dir, FileMode::ReadWrite)],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    assert!(CapabilitySet::EMPTY.is_subset_of(&set));
    assert!(CapabilitySet::EMPTY.is_subset_of(&CapabilitySet::EMPTY));
}

#[test]
fn dir_grant_covers_nested_file() {
    let intern = pool();
    let file = intern.get_path(Path::new("/srv/data/report.csv")).unwrap();
    let dir = intern.get_path(Path::new("/srv/data")).unwrap();
    let parent = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(dir, FileMode::ReadWrite)],
        vec![],
    )
    .unwrap()
    .with_interner(intern.clone());
    let child = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![FileGrant::new(file, FileMode::Read)],
        vec![],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    assert!(child.is_subset_of(&parent));
    assert!(!parent.is_subset_of(&child));
    assert_eq!(CapabilitySet::attenuate(&parent, &child).unwrap(), child);
}

#[test]
fn a_slash_b_does_not_contain_a_slash_bc() {
    let intern = pool();
    let ab = intern.get_path(Path::new("/a/b")).unwrap();
    let abc = intern.get_path(Path::new("/a/bc")).unwrap();
    assert!(!intern.is_prefix(ab, abc));
    assert!(!intern.is_prefix(abc, ab));
    let a = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(ab, FileMode::Read)],
        vec![],
    )
    .unwrap()
    .with_interner(intern.clone());
    let b = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(abc, FileMode::Read)],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    assert!(!b.is_subset_of(&a));
    assert!(!a.is_subset_of(&b));
    let m = a.meet(&b);
    assert!(m.dirs().is_empty());
}

#[test]
fn root_dir_covers_everything() {
    let intern = pool();
    let root = intern.get_path(Path::new("/")).unwrap();
    let nested = intern.get_path(Path::new("/a/b")).unwrap();
    let parent = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(root, FileMode::ReadWrite)],
        vec![],
    )
    .unwrap()
    .with_interner(intern.clone());
    let child = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(nested, FileMode::Read)],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    assert!(child.is_subset_of(&parent));
}

#[test]
fn meet_nested_dirs_is_more_specific() {
    let intern = pool();
    let a_root = intern.get_path(Path::new("/a")).unwrap();
    let ab = intern.get_path(Path::new("/a/b")).unwrap();
    let wide = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(a_root, FileMode::ReadWrite)],
        vec![],
    )
    .unwrap()
    .with_interner(intern.clone());
    let narrow = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(ab, FileMode::Read)],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    let m = wide.meet(&narrow);
    assert_eq!(m.dirs().len(), 1);
    assert_eq!(m.dirs()[0].root(), ab);
    assert_eq!(m.dirs()[0].mode(), FileMode::Read);
    assert!(m.is_subset_of(&wide));
    assert!(m.is_subset_of(&narrow));
}

#[test]
fn meet_file_with_covering_dir_lesser_mode() {
    let intern = pool();
    let file = intern.get_path(Path::new("/srv/data/report.csv")).unwrap();
    let dir = intern.get_path(Path::new("/srv")).unwrap();
    let files = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![FileGrant::new(file, FileMode::ReadWrite)],
        vec![],
        vec![],
    )
    .unwrap()
    .with_interner(intern.clone());
    let dirs = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(dir, FileMode::Read)],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    let m = files.meet(&dirs);
    assert_eq!(m.files().len(), 1);
    assert_eq!(m.files()[0].path(), file);
    assert_eq!(m.files()[0].mode(), FileMode::Read);
    assert!(m.dirs().is_empty());
}

#[test]
fn attenuate_rejects_escalation() {
    let intern = pool();
    let dir = intern.get_path(Path::new("/srv/inbox")).unwrap();
    let parent = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(dir, FileMode::Read)],
        vec![],
    )
    .unwrap()
    .with_interner(intern.clone());
    let requested = CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(dir, FileMode::ReadWrite)],
        vec![],
    )
    .unwrap()
    .with_interner(intern);
    let err = CapabilitySet::attenuate(&parent, &requested).unwrap_err();
    assert!(matches!(err, CapsError::Escalation(_)));
}

#[test]
fn host_methods_subset_and_meet() {
    let intern = pool();
    let auth = intern.get_authority("api.example.com:443").unwrap();
    let get_post = CapabilitySet::new(
        &[Interface::HttpOutbound],
        vec![],
        vec![],
        vec![HostGrant::new(
            auth,
            MethodMask::new(&[Method::Get, Method::Post]),
        )],
    )
    .unwrap()
    .with_interner(intern.clone());
    let get = CapabilitySet::new(
        &[Interface::HttpOutbound],
        vec![],
        vec![],
        vec![HostGrant::new(auth, MethodMask::new(&[Method::Get]))],
    )
    .unwrap()
    .with_interner(intern);
    assert!(get.is_subset_of(&get_post));
    assert!(!get_post.is_subset_of(&get));
    let m = get_post.meet(&get);
    assert_eq!(m.hosts().len(), 1);
    assert!(m.hosts()[0]
        .methods()
        .is_subset_of(MethodMask::new(&[Method::Get])));
    assert!(MethodMask::new(&[Method::Get]).is_subset_of(m.hosts()[0].methods()));
}
