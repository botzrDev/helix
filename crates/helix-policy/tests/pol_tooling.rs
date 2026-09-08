//! Manual/tooling helpers for HLX-17 (`policy check` / `explain` / wire JSON).

use std::fs;
use std::path::PathBuf;

use helix_policy::{
    caps_budget_wire_json, check_policy, encode_thumbprint, explain_grant_json,
    load_snapshot_for_explain, parse_tool_digest, resolve_host, CheckPasses, MapFs,
    MemoryArtifactStore, PathKind, PolicyFile,
};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn fixture_toml(file_path: &str, dir_path: &str) -> String {
    format!(
        r#"
version = 1

[tools]
read_db = "{DIGEST_A}"

[budgets.default]
wall_clock_ms = 2000
memory_bytes = 67108864
output_bytes = 1048576

[identities]
billing = "{billing}"

[[grants]]
identity = "billing"
tool = "read_db"
digest = "{DIGEST_A}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"
files = [{{ path = "{file_path}", mode = "read" }}]
dirs = [{{ path = "{dir_path}", mode = "read" }}]
"#,
        billing = thumb(1),
    )
}

#[test]
fn check_structural_only_labels_mode_and_lists_grants() {
    let dir = tempfile_dir();
    let policy = dir.join("policy.toml");
    fs::write(
        &policy,
        fixture_toml("/srv/data/customers.sqlite", "/srv/inbox"),
    )
    .unwrap();

    let report = check_policy(&policy, None).expect("structural ok");
    assert_eq!(report.passes, CheckPasses::StructuralOnly);
    let text = report.display_text();
    assert!(text.contains("mode: structural only"), "{text}");
    assert!(text.contains("passes: structural"), "{text}");
    assert!(
        text.contains("file  /srv/data/customers.sqlite  read"),
        "{text}"
    );
    assert!(text.contains("dir  /srv/inbox  read"), "{text}");
}

#[test]
fn check_host_pass_requires_artifacts_and_real_paths() {
    let root = tempfile_dir();
    let data = root.join("data");
    let inbox = root.join("inbox");
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&inbox).unwrap();
    let file = data.join("customers.sqlite");
    fs::write(&file, b"x").unwrap();

    let policy = root.join("policy.toml");
    fs::write(
        &policy,
        fixture_toml(file.to_str().unwrap(), inbox.to_str().unwrap()),
    )
    .unwrap();

    let artifacts = root.join("artifacts");
    fs::create_dir_all(&artifacts).unwrap();
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let mut hex = String::with_capacity(64);
    for b in digest.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    fs::write(artifacts.join(&hex), b"artifact").unwrap();

    let report = check_policy(&policy, Some(&artifacts)).expect("host ok");
    assert_eq!(report.passes, CheckPasses::StructuralAndHost);
    let text = report.display_text();
    assert!(text.contains("passes: structural, host"), "{text}");
    assert!(text.contains("mode: structural + host"), "{text}");
    assert!(text.contains("file  "), "{text}");
    assert!(text.contains("dir  "), "{text}");
}

#[test]
fn explain_emits_budget_sibling_wire_json() {
    let file =
        PolicyFile::parse(&fixture_toml("/srv/data/customers.sqlite", "/srv/inbox")).unwrap();
    let fs = MapFs::new()
        .insert("/srv", PathKind::Directory)
        .insert("/srv/data", PathKind::Directory)
        .insert("/srv/data/customers.sqlite", PathKind::File)
        .insert("/srv/inbox", PathKind::Directory);
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let store = MemoryArtifactStore::new().with_digest(digest);
    let snapshot = resolve_host(&file, &store, &fs).unwrap();
    let json = explain_grant_json(&snapshot, "billing", "read_db").unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("interfaces").is_some());
    assert!(v.get("files").is_some());
    assert!(v.get("dirs").is_some());
    assert!(v.get("budget").is_some(), "budget must be sibling: {json}");
    assert_eq!(v["budget"]["wall_clock_ms"], 2000);
}

#[test]
fn caps_budget_wire_json_flattens_set() {
    let file =
        PolicyFile::parse(&fixture_toml("/srv/data/customers.sqlite", "/srv/inbox")).unwrap();
    let fs = MapFs::new()
        .insert("/srv", PathKind::Directory)
        .insert("/srv/data", PathKind::Directory)
        .insert("/srv/data/customers.sqlite", PathKind::File)
        .insert("/srv/inbox", PathKind::Directory);
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let store = MemoryArtifactStore::new().with_digest(digest);
    let snapshot = resolve_host(&file, &store, &fs).unwrap();
    let id = *snapshot.identities().get("billing").unwrap();
    let (caps, budget) = snapshot.policy(&id, &digest).unwrap();
    let json = caps_budget_wire_json(caps, budget).unwrap();
    assert!(json.contains("\"budget\""));
    assert!(json.contains("\"interfaces\""));
}

#[test]
fn load_snapshot_for_explain_without_artifacts_trusts_tools_table() {
    let root = tempfile_dir();
    let data = root.join("data");
    let inbox = root.join("inbox");
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&inbox).unwrap();
    let file = data.join("customers.sqlite");
    fs::write(&file, b"x").unwrap();
    let policy = root.join("policy.toml");
    fs::write(
        &policy,
        fixture_toml(file.to_str().unwrap(), inbox.to_str().unwrap()),
    )
    .unwrap();
    let snap = load_snapshot_for_explain(&policy, None).expect("explain load");
    assert!(snap.tools().contains_key("read_db"));
}

fn tempfile_dir() -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!(
        "helix-pol-tooling-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}
