//! POL-1, POL-2, POL-7 (test-plan.md). M2-01 / HLX-14.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use helix_caps::{FileMode, Interface};
use helix_policy::{
    encode_thumbprint, parse_identity_thumbprint, parse_tool_digest, resolve_host,
    validate_structural, validate_structural_with_fs, MapFs, MemoryArtifactStore, PanicFs,
    PathKind, PolicyError, PolicyFile, StdFs,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

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

[budgets.heavy]
preempt_ticks = 5000
wall_clock_ms = 30000
memory_bytes = 536870912
output_bytes = 8388608
max_delegation_depth = 2
max_children = 8
max_concurrent_instances = 32

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

fn parse_valid() -> PolicyFile {
    PolicyFile::parse(&valid_toml()).expect("valid fixture")
}

fn rules(errs: &[PolicyError]) -> Vec<u8> {
    errs.iter().filter_map(PolicyError::rule).collect()
}

fn has_rule(errs: &[PolicyError], n: u8) -> bool {
    errs.iter().any(|e| e.rule() == Some(n))
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

// ---------------------------------------------------------------------------
// POL-1: each of the 12 rules produces the documented fatal error
// ---------------------------------------------------------------------------

#[test]
fn pol1_rule1_version_must_be_1() {
    let mut file = parse_valid();
    file.version = 2;
    let err = validate_structural_with_fs(&file, &PanicFs).unwrap_err();
    assert!(has_rule(&err, 1), "{err:?}");
}

#[test]
fn pol1_rule2_digest_must_exist_in_store() {
    let file = parse_valid();
    let err = resolve_host(&file, &MemoryArtifactStore::new(), &map_fs_ok()).unwrap_err();
    assert!(has_rule(&err, 2), "{err:?}");
}

#[test]
fn pol1_rule3_identity_and_tool_must_be_keys() {
    let mut file = parse_valid();
    file.grants[0].identity = "nope".into();
    file.grants[0].tool = "missing".into();
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 3), "{err:?}");
    assert!(
        err.iter()
            .any(|e| matches!(e, PolicyError::UnknownIdentity { .. })),
        "{err:?}"
    );
    assert!(
        err.iter()
            .any(|e| matches!(e, PolicyError::UnknownTool { .. })),
        "{err:?}"
    );
}

#[test]
fn pol1_rule4_identity_tool_pairs_unique() {
    let mut file = parse_valid();
    file.grants.push(file.grants[0].clone());
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 4), "{err:?}");
}

#[test]
fn pol1_rule5_relative_path_fatal() {
    let mut file = parse_valid();
    file.grants[0].files[0].path = "relative/file.txt".into();
    let err = resolve_host(&file, &store_ok(), &map_fs_ok()).unwrap_err();
    assert!(has_rule(&err, 5), "{err:?}");
    assert!(
        err.iter()
            .any(|e| matches!(e, PolicyError::PathNotAbsolute(_))),
        "{err:?}"
    );
}

#[test]
fn pol1_rule6_files_require_filesystem() {
    let mut file = parse_valid();
    file.grants[0].interfaces.retain(|i| i != "filesystem");
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 6), "{err:?}");
}

#[test]
fn pol1_rule6_hosts_require_http_outbound() {
    let mut file = parse_valid();
    file.grants[1].interfaces.retain(|i| i != "http_outbound");
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 6), "{err:?}");
}

#[test]
fn pol1_rule7_authority_port_and_lowercase() {
    let mut file = parse_valid();
    file.grants[1].hosts[0].authority = "API.EXAMPLE.COM:443".into();
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 7), "{err:?}");

    let mut file = parse_valid();
    file.grants[1].hosts[0].authority = "api.example.com".into();
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 7), "{err:?}");
}

#[test]
fn pol1_rule8_budget_must_exist() {
    let mut file = parse_valid();
    file.grants[0].budget = "missing".into();
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 8), "{err:?}");
}

#[test]
fn pol1_rule9_methods_closed_set() {
    let mut file = parse_valid();
    file.grants[1].hosts[0].methods = vec!["GET".into(), "TRACE".into()];
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 9), "{err:?}");
}

#[test]
fn pol1_rule10_digest_must_match_alias() {
    let mut file = parse_valid();
    file.grants[0].digest = Some(DIGEST_B.to_owned());
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 10), "{err:?}");

    let mut file = parse_valid();
    file.grants[0].digest = None;
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 10), "{err:?}");
}

#[test]
fn pol1_rule11_preempt_ticks_le_wall_clock() {
    let mut file = parse_valid();
    file.budgets.get_mut("heavy").unwrap().preempt_ticks = Some(30_001);
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 11), "{err:?}");
}

#[test]
fn pol1_rule12_max_concurrent_at_least_one() {
    let mut file = parse_valid();
    file.budgets
        .get_mut("default")
        .unwrap()
        .max_concurrent_instances = 0;
    let err = validate_structural(&file).unwrap_err();
    assert!(has_rule(&err, 12), "{err:?}");
}

#[test]
fn pol1_valid_structural_passes_under_panic_fs() {
    let file = parse_valid();
    validate_structural_with_fs(&file, &PanicFs).expect("valid structural");
}

// ---------------------------------------------------------------------------
// POL-2: directory grants are not expanded; symlink at a granted path is fatal
// ---------------------------------------------------------------------------

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn pol2_temp() -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("helix-pol2-{}-{}", std::process::id(), n));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn grant_path(root: &Path, rel: &str, is_dir: bool) -> PolicyFile {
    let abs = root.join(rel);
    let mut file = parse_valid();
    // drop the second grant; retarget the first
    file.grants.truncate(1);
    file.grants[0].files.clear();
    file.grants[0].dirs.clear();
    if is_dir {
        file.grants[0].dirs.push(helix_policy::DirGrantTable {
            path: abs.to_string_lossy().into_owned(),
            mode: "read".into(),
        });
    } else {
        file.grants[0].files.push(helix_policy::FileGrantTable {
            path: abs.to_string_lossy().into_owned(),
            mode: "read".into(),
        });
    }
    file
}

#[test]
fn pol2_directory_grants_are_not_expanded() {
    let root = pol2_temp();
    let inbox = root.join("inbox");
    fs::create_dir_all(inbox.join("nested")).unwrap();
    fs::write(inbox.join("nested/file.txt"), b"x").unwrap();
    fs::write(inbox.join("a.txt"), b"y").unwrap();

    let file = grant_path(&root, "inbox", true);
    let snap = resolve_host(&file, &store_ok(), &StdFs).expect("resolve dir grant");
    let grant = snap.grants().next().expect("one grant");
    assert_eq!(grant.caps().dirs().len(), 1, "one DirGrant, not expanded");
    assert!(
        grant.caps().files().is_empty(),
        "directory must not expand to FileGrants; got {:?}",
        grant.caps().files().len()
    );
    let intern = snap.interner();
    let root_id = grant.caps().dirs()[0].root();
    assert_eq!(intern.path(root_id), inbox.canonicalize().unwrap());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pol2_symlink_at_file_path_is_fatal() {
    let root = pol2_temp();
    fs::write(root.join("real.txt"), b"x").unwrap();
    symlink(root.join("real.txt"), root.join("link.txt")).unwrap();

    let file = grant_path(&root, "link.txt", false);
    let err = resolve_host(&file, &store_ok(), &StdFs).unwrap_err();
    assert!(has_rule(&err, 5), "{err:?}");
    assert!(
        err.iter().any(|e| matches!(e, PolicyError::Symlink(_))),
        "{err:?}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pol2_symlink_at_dir_path_is_fatal() {
    let root = pol2_temp();
    fs::create_dir(root.join("realdir")).unwrap();
    symlink(root.join("realdir"), root.join("linkdir")).unwrap();

    let file = grant_path(&root, "linkdir", true);
    let err = resolve_host(&file, &store_ok(), &StdFs).unwrap_err();
    assert!(has_rule(&err, 5), "{err:?}");
    assert!(
        err.iter().any(|e| matches!(e, PolicyError::Symlink(_))),
        "{err:?}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pol2_mapfs_symlink_is_fatal_without_walking() {
    let mut file = parse_valid();
    file.grants.truncate(1);
    file.grants[0].files[0].path = "/srv/data/customers.sqlite".into();
    let fs = MapFs::new()
        .insert("/srv", PathKind::Directory)
        .insert("/srv/data", PathKind::Directory)
        .insert("/srv/data/customers.sqlite", PathKind::Symlink);
    let err = resolve_host(&file, &store_ok(), &fs).unwrap_err();
    assert!(
        err.iter().any(|e| matches!(e, PolicyError::Symlink(_))),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Happy host resolve + defaults + warn
// ---------------------------------------------------------------------------

#[test]
fn resolve_interns_and_defaults_preempt_ticks() {
    let file = parse_valid();
    let snap = resolve_host(&file, &store_ok(), &map_fs_ok()).expect("resolve");
    assert_eq!(snap.grants().count(), 2);

    let billing = parse_identity_thumbprint("billing", &thumb(1)).unwrap();
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let g = snap.grant(&billing, &digest).expect("hit");
    assert_eq!(g.budget().preempt_ticks(), 2000, "default = wall_clock_ms");
    assert_eq!(g.budget().max_delegation_depth(), 2);
    assert_eq!(g.budget().max_children(), 8);
    assert_eq!(g.budget().max_concurrent_instances(), 32);
    assert!(g.caps().has(Interface::Filesystem));
    assert_eq!(g.caps().files()[0].mode(), FileMode::Read);

    let research = parse_identity_thumbprint("research", &thumb(2)).unwrap();
    let d2 = parse_tool_digest("sum_pdf", DIGEST_B).unwrap();
    let g2 = snap.grant(&research, &d2).expect("hit");
    assert_eq!(g2.budget().preempt_ticks(), 5000);
    assert_eq!(g2.caps().dirs().len(), 1);
    assert_eq!(g2.caps().hosts().len(), 1);
}

#[test]
fn host_warns_when_identity_cap_exceeds_runtime_pool() {
    let mut file = parse_valid();
    file.budgets
        .get_mut("heavy")
        .unwrap()
        .max_concurrent_instances = 64;
    let store = store_ok().with_runtime_max(32);
    let snap = resolve_host(&file, &store, &map_fs_ok()).expect("resolve");
    assert!(
        snap.warnings()
            .iter()
            .any(|w| w.contains("research") && w.contains("64") && w.contains("32")),
        "{:?}",
        snap.warnings()
    );
}

// ---------------------------------------------------------------------------
// POL-7: structural never touches Fs; rejects generated violations
// ---------------------------------------------------------------------------

fn prop_config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

#[derive(Clone, Debug)]
enum StructuralViolation {
    Version,
    UnknownIdentity,
    UnknownTool,
    DuplicateGrant,
    FilesWithoutFs,
    HostsWithoutHttp,
    AuthorityUpper,
    AuthorityNoPort,
    UnknownBudget,
    UnknownMethod,
    DigestMismatch,
    MissingDigest,
    PreemptTicks,
    ConcurrentZero,
}

fn arb_violation() -> impl Strategy<Value = StructuralViolation> {
    prop_oneof![
        Just(StructuralViolation::Version),
        Just(StructuralViolation::UnknownIdentity),
        Just(StructuralViolation::UnknownTool),
        Just(StructuralViolation::DuplicateGrant),
        Just(StructuralViolation::FilesWithoutFs),
        Just(StructuralViolation::HostsWithoutHttp),
        Just(StructuralViolation::AuthorityUpper),
        Just(StructuralViolation::AuthorityNoPort),
        Just(StructuralViolation::UnknownBudget),
        Just(StructuralViolation::UnknownMethod),
        Just(StructuralViolation::DigestMismatch),
        Just(StructuralViolation::MissingDigest),
        Just(StructuralViolation::PreemptTicks),
        Just(StructuralViolation::ConcurrentZero),
    ]
}

fn apply_violation(mut file: PolicyFile, v: &StructuralViolation) -> (PolicyFile, u8) {
    match v {
        StructuralViolation::Version => {
            file.version = 99;
            (file, 1)
        }
        StructuralViolation::UnknownIdentity => {
            file.grants[0].identity = "ghost".into();
            (file, 3)
        }
        StructuralViolation::UnknownTool => {
            file.grants[0].tool = "ghost".into();
            (file, 3)
        }
        StructuralViolation::DuplicateGrant => {
            file.grants.push(file.grants[0].clone());
            (file, 4)
        }
        StructuralViolation::FilesWithoutFs => {
            file.grants[0].interfaces.retain(|i| i != "filesystem");
            (file, 6)
        }
        StructuralViolation::HostsWithoutHttp => {
            file.grants[1].interfaces.retain(|i| i != "http_outbound");
            (file, 6)
        }
        StructuralViolation::AuthorityUpper => {
            file.grants[1].hosts[0].authority = "API.EXAMPLE.COM:443".into();
            (file, 7)
        }
        StructuralViolation::AuthorityNoPort => {
            file.grants[1].hosts[0].authority = "api.example.com".into();
            (file, 7)
        }
        StructuralViolation::UnknownBudget => {
            file.grants[0].budget = "nope".into();
            (file, 8)
        }
        StructuralViolation::UnknownMethod => {
            file.grants[1].hosts[0].methods.push("CONNECT".into());
            (file, 9)
        }
        StructuralViolation::DigestMismatch => {
            file.grants[0].digest = Some(DIGEST_B.to_owned());
            (file, 10)
        }
        StructuralViolation::MissingDigest => {
            file.grants[0].digest = None;
            (file, 10)
        }
        StructuralViolation::PreemptTicks => {
            file.budgets.get_mut("heavy").unwrap().preempt_ticks = Some(99_999);
            (file, 11)
        }
        StructuralViolation::ConcurrentZero => {
            file.budgets
                .get_mut("default")
                .unwrap()
                .max_concurrent_instances = 0;
            (file, 12)
        }
    }
}

proptest! {
    #![proptest_config(prop_config())]

    #[test]
    fn pol7_structural_never_touches_fs_and_rejects_violations(v in arb_violation()) {
        let fs = PanicFs;
        let (file, rule) = apply_violation(parse_valid(), &v);
        let err = validate_structural_with_fs(&file, &fs)
            .expect_err("generated violation must be fatal");
        prop_assert!(
            has_rule(&err, rule),
            "expected rule {rule}, got {:?} from {v:?}",
            rules(&err)
        );
    }

    #[test]
    fn pol7_valid_structural_ok_under_panic_fs(_unit in Just(())) {
        let fs = PanicFs;
        validate_structural_with_fs(&parse_valid(), &fs).expect("valid");
    }
}

#[test]
fn pol7_validate_structural_api_does_not_take_fs_and_still_works() {
    // ADR-008 C.2 signature (no Fs). POL-7 also covers `validate_structural_with_fs`.
    validate_structural(&parse_valid()).unwrap();
}
