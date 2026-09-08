//! SDK-4: author-guide examples build, run via helix-ctl / reference runtime,
//! delegation returns the child result, and RT-2 FS grants hold.

#![allow(
    clippy::too_many_lines,
    clippy::needless_raw_string_hashes,
    clippy::doc_markdown,
    clippy::unnecessary_wraps,
    clippy::items_after_statements,
    clippy::unnecessary_debug_formatting
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use helix_caps::{CapabilitySet, RequestId, ResourceBudget, ToolDigest};
use helix_policy::{
    encode_thumbprint, parse_identity_thumbprint, resolve_host, MapFs, MemoryArtifactStore,
    PolicyFile, PolicyGuard, DEFAULT_MAX_SNAPSHOT_AGE_S,
};
use helix_runtime::{
    build_engine, digest_hex, digest_of_bytes, invoke, invoke_with_delegation, DelegationCtx,
    EpochTicker, IdentitySemaphore, MapToolResolver, NopDelegationAudit, NopHook, RuntimeConfig,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use wasmtime::component::Component;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo_root().join("tests/fixtures")
}

fn find_wasm(pkg_dir: &Path, crate_name: &str) -> PathBuf {
    let candidates = [
        pkg_dir.join(format!("target/wasm32-wasip1/release/{crate_name}.wasm")),
        PathBuf::from("/tmp/helix-hlx38-target")
            .join(format!("wasm32-wasip1/release/{crate_name}.wasm")),
        PathBuf::from("/tmp/helix-hlx39-target")
            .join(format!("wasm32-wasip1/release/{crate_name}.wasm")),
    ];
    for c in candidates {
        if c.is_file() {
            return c;
        }
    }
    // Search under pkg target
    let walk = pkg_dir.join("target");
    if walk.is_dir() {
        for ent in walkdir_simple(&walk) {
            if ent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == format!("{crate_name}.wasm"))
            {
                return ent;
            }
        }
    }
    panic!("wasm for {crate_name} not found; run cargo component build first");
}

fn walkdir_simple(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn component_build(manifest: &Path) {
    let status = Command::new("cargo")
        .args(["component", "build", "--release", "--manifest-path"])
        .arg(manifest)
        .status()
        .expect("spawn cargo component");
    assert!(
        status.success(),
        "cargo component build failed for {manifest:?}"
    );
}

fn load_component(engine: &wasmtime::Engine, wasm: &Path) -> (ToolDigest, Component) {
    let bytes = fs::read(wasm).unwrap_or_else(|e| panic!("read {}: {e}", wasm.display()));
    let digest = digest_of_bytes(&bytes);
    let component = Component::new(engine, &bytes).expect("component");
    (digest, component)
}

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn budget() -> ResourceBudget {
    ResourceBudget::new(500, 5000, 64 * 1024 * 1024, 1024 * 1024, 2, 8, 32)
}

fn caps_stdio_fs() -> CapabilitySet {
    serde_json::from_value(serde_json::json!({
        "interfaces": ["stdio", "clocks", "filesystem"],
        "files": [],
        "dirs": [],
        "hosts": []
    }))
    .expect("caps")
}

#[test]
fn sdk4_word_count_builds_and_runs() {
    let manifest = fixtures().join("word_count/Cargo.toml");
    component_build(&manifest);
    let wasm = find_wasm(&fixtures().join("word_count"), "word_count");

    let tmp = tempfile::tempdir().unwrap();
    let engine = build_engine(&RuntimeConfig::for_test(tmp.path())).unwrap();
    let _ticker = EpochTicker::start(engine.clone());
    let (_d, component) = load_component(&engine, &wasm);
    let caps = caps_stdio_fs();
    let mut hook = NopHook;
    let out = invoke(
        &engine,
        &component,
        &caps,
        &budget(),
        br#"{"text":"a b c"}"#,
        &mut hook,
    )
    .expect("word_count invoke");
    let v: serde_json::Value = serde_json::from_slice(&out.output).unwrap();
    assert_eq!(v["words"], 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk4_delegate_returns_child_result() {
    let wc_manifest = fixtures().join("word_count/Cargo.toml");
    let dc_manifest = fixtures().join("delegate_count/Cargo.toml");
    component_build(&wc_manifest);
    component_build(&dc_manifest);
    let wc_wasm = find_wasm(&fixtures().join("word_count"), "word_count");
    let dc_wasm = find_wasm(&fixtures().join("delegate_count"), "delegate_count");

    let tmp = tempfile::tempdir().unwrap();
    let cfg = RuntimeConfig::new(tmp.path(), 16, 64 * 1024 * 1024);
    let engine = build_engine(&cfg).unwrap();
    let _ticker = EpochTicker::start(engine.clone());

    let (wc_digest, wc_comp) = load_component(&engine, &wc_wasm);
    let (dc_digest, dc_comp) = load_component(&engine, &dc_wasm);

    let id = thumb(9);
    let toml = format!(
        r#"
version = 1

[tools]
word_count = "sha256:{wc}"
delegate_count = "sha256:{dc}"

[budgets.default]
wall_clock_ms = 5000
memory_bytes = 67108864
output_bytes = 1048576
max_delegation_depth = 2
max_children = 8
max_concurrent_instances = 32

[identities]
author = "{id}"

[[grants]]
identity = "author"
tool = "word_count"
digest = "sha256:{wc}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"

[[grants]]
identity = "author"
tool = "delegate_count"
digest = "sha256:{dc}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"
"#,
        wc = digest_hex(&wc_digest),
        dc = digest_hex(&dc_digest),
        id = id,
    );

    let file = PolicyFile::parse(&toml).expect("toml");
    let store = MemoryArtifactStore::new()
        .with_digest(wc_digest)
        .with_digest(dc_digest)
        .with_runtime_max(256);
    let snap = resolve_host(&file, &store, &MapFs::new()).expect("resolve");
    let guard = PolicyGuard::from_snapshot(snap, DEFAULT_MAX_SNAPSHOT_AGE_S);
    let identity = parse_identity_thumbprint("author", &id).unwrap();
    let (parent_caps, parent_budget) = guard.policy(&identity, &dc_digest).expect("grant");
    let parent_caps = parent_caps.clone();
    let parent_budget = *parent_budget;

    let tools = Arc::new(MapToolResolver::new());
    tools.insert(
        wc_digest,
        wc_comp,
        r#"{"type":"object","properties":{"text":{"type":"string"}}}"#,
    );
    tools.insert(dc_digest, dc_comp.clone(), r#"{"type":"object"}"#);

    let ctx = DelegationCtx {
        request_id: RequestId::from_u128(1),
        parent: None,
        identity,
        digest: dc_digest,
        depth: 0,
        guard,
        effective: parent_caps.clone(),
        budget: parent_budget,
        semaphore: Arc::new(IdentitySemaphore::new(32)),
        token: CancellationToken::new(),
        children: JoinSet::new(),
        tools,
        audit: Arc::new(NopDelegationAudit),
        caps_store: None,
        store_creations: Arc::new(AtomicUsize::new(0)),
        engine: engine.clone(),
    };

    let mut hook = NopHook;
    let out = invoke_with_delegation(
        &engine,
        &dc_comp,
        &parent_caps,
        &parent_budget,
        br#"{"text":"one two three four"}"#,
        Some(ctx),
        &mut hook,
    )
    .expect("delegate_count");
    let v: serde_json::Value = serde_json::from_slice(&out.output).unwrap();
    assert_eq!(v["words"], 4, "child word_count result must surface");
}

/// RT-2 against the reference runtime using the guide §4 filesystem example.
#[test]
fn sdk4_rt2_file_grant_via_guide_example() {
    let manifest = fixtures().join("read_b/Cargo.toml");
    component_build(&manifest);
    let wasm = find_wasm(&fixtures().join("read_b"), "read_b");

    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    fs::create_dir_all(&a).unwrap();
    let b = a.join("b.txt");
    let c = a.join("c.txt");
    fs::write(&b, b"granted").unwrap();
    fs::write(&c, b"secret-sibling").unwrap();

    let caps: CapabilitySet = serde_json::from_value(serde_json::json!({
        "interfaces": ["stdio", "clocks", "filesystem"],
        "files": [{ "path": b.to_string_lossy(), "mode": "read" }],
        "dirs": [],
        "hosts": []
    }))
    .expect("caps with throwaway interner");

    let engine = build_engine(&RuntimeConfig::for_test(tmp.path().join("art"))).unwrap();
    let _ticker = EpochTicker::start(engine.clone());
    let (_d, component) = load_component(&engine, &wasm);

    let mut hook = NopHook;
    let ok = invoke(
        &engine,
        &component,
        &caps,
        &budget(),
        &serde_json::to_vec(&serde_json::json!({ "path": b.to_string_lossy() })).unwrap(),
        &mut hook,
    )
    .expect("read granted file");
    let v: serde_json::Value = serde_json::from_slice(&ok.output).unwrap();
    assert_eq!(v["contents"], "granted");

    let mut hook2 = NopHook;
    let denied = invoke(
        &engine,
        &component,
        &caps,
        &budget(),
        &serde_json::to_vec(&serde_json::json!({ "path": c.to_string_lossy() })).unwrap(),
        &mut hook2,
    );
    match denied {
        Err(helix_runtime::InvokeError::ToolError { kind, .. }) => {
            assert_eq!(kind, "capability-denied");
        }
        other => panic!("expected capability-denied for sibling, got {other:?}"),
    }
}
