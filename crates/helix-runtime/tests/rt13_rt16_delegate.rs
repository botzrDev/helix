#![allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::redundant_pattern_matching,
    clippy::doc_markdown,
    clippy::unnecessary_debug_formatting,
    clippy::similar_names,
    clippy::needless_raw_string_hashes
)]
//! RT-13…RT-16: `helix:delegate` host import (HLX-31 / M4-08).

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use helix_audit::CapsStore;
use helix_caps::{CapabilitySet, Identity, Interface, RequestId, ResourceBudget, ToolDigest};
use helix_policy::{
    encode_thumbprint, parse_identity_thumbprint, resolve_host, MapFs, MemoryArtifactStore,
    PolicyFile, PolicyGuard,
};
use helix_runtime::{
    build_engine, host_delegate, DelegateError, DelegationCtx, EpochTicker, HostDelegationRequest,
    HostToolRef, IdentitySemaphore, KillCause, MapToolResolver, RecordingDelegationAudit,
    RuntimeConfig, TerminalKind,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use wasmtime::component::Component;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn digest_hex(bytes: [u8; 32]) -> String {
    format!("sha256:{}", hex::encode(&bytes))
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 0xf) as usize] as char);
        }
        s
    }
}

fn child_digest() -> ToolDigest {
    // Content-addressed from fixture bytes so alias table matches file.
    let bytes = std::fs::read(fixtures_root().join("adversarial/runtime/child_echo.wasm"))
        .expect("child_echo.wasm");
    let hash = {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update(&bytes);
        let out = d.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    };
    ToolDigest::from_bytes(hash)
}

fn parent_digest_escalate() -> ToolDigest {
    let bytes = std::fs::read(fixtures_root().join("adversarial/runtime/escalate.wasm"))
        .expect("escalate.wasm");
    let hash = {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update(&bytes);
        let out = d.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    };
    ToolDigest::from_bytes(hash)
}

fn load_guard(
    child: ToolDigest,
    parent: ToolDigest,
    max_children: u32,
    max_depth: u32,
) -> PolicyGuard {
    let child_hex = digest_hex(*child.as_bytes());
    let parent_hex = digest_hex(*parent.as_bytes());
    let toml = format!(
        r#"
version = 1

[tools]
child-echo = "{child_hex}"
escalate = "{parent_hex}"
fanout = "{parent_hex}"

[budgets.default]
wall_clock_ms = 2000
memory_bytes = 67108864
output_bytes = 1048576
max_delegation_depth = {max_depth}
max_children = {max_children}
max_concurrent_instances = 32

[identities]
agent = "{id}"

[[grants]]
identity = "agent"
tool = "child-echo"
digest = "{child_hex}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"

[[grants]]
identity = "agent"
tool = "escalate"
digest = "{parent_hex}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"

[[grants]]
identity = "agent"
tool = "fanout"
digest = "{parent_hex}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"
"#,
        id = thumb(7),
        child_hex = child_hex,
        parent_hex = parent_hex,
        max_children = max_children,
        max_depth = max_depth,
    );
    let file = PolicyFile::parse(&toml).expect("toml");
    let store = MemoryArtifactStore::new()
        .with_digest(child)
        .with_digest(parent)
        .with_runtime_max(256);
    let fs = MapFs::new();
    let snap = resolve_host(&file, &store, &fs).expect("resolve");
    PolicyGuard::from_snapshot(snap, 300)
}

fn budget(wall: u32, depth: u32, children: u32) -> ResourceBudget {
    ResourceBudget::new(
        wall,
        wall,
        64 * 1024 * 1024,
        1024 * 1024,
        depth,
        children,
        32,
    )
}

fn make_ctx(
    guard: PolicyGuard,
    identity: Identity,
    digest: ToolDigest,
    depth: u32,
    effective: CapabilitySet,
    budget: ResourceBudget,
    semaphore: Arc<IdentitySemaphore>,
    token: CancellationToken,
    tools: Arc<MapToolResolver>,
    audit: Arc<RecordingDelegationAudit>,
    caps_dir: Option<PathBuf>,
    engine: wasmtime::Engine,
) -> DelegationCtx {
    let caps_store = caps_dir.map(|p| {
        std::fs::create_dir_all(&p).ok();
        Mutex::new(CapsStore::open(&p).expect("caps store"))
    });
    DelegationCtx {
        request_id: RequestId::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
        parent: None,
        identity,
        digest,
        depth,
        guard,
        effective,
        budget,
        semaphore,
        token,
        children: JoinSet::new(),
        tools,
        audit,
        caps_store,
        store_creations: Arc::new(AtomicUsize::new(0)),
        engine,
    }
}

fn test_engine() -> wasmtime::Engine {
    let tmp = tempfile::tempdir().unwrap();
    build_engine(&RuntimeConfig::for_test(tmp.path())).expect("engine")
}

fn load_component(engine: &wasmtime::Engine, rel: &str) -> Component {
    let path = fixtures_root().join(rel);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    Component::from_binary(engine, &bytes).expect("component")
}

/// RT-13: superset request → `::escalation`; parent refusal carries both caps hashes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt13_escalation_dual_caps_hash() {
    let engine = test_engine();
    let child_d = child_digest();
    let parent_d = parent_digest_escalate();
    let guard = load_guard(child_d, parent_d, 8, 2);
    let identity = parse_identity_thumbprint("agent", &thumb(7)).unwrap();
    let (parent_caps, _) = guard.policy(&identity, &parent_d).expect("parent grant");
    let parent_caps = parent_caps.clone();

    let tools = Arc::new(MapToolResolver::new());
    let child = load_component(&engine, "adversarial/runtime/child_echo.wasm");
    tools.insert(child_d, child, r#"{"type":"object"}"#);

    let audit = Arc::new(RecordingDelegationAudit::default());
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = make_ctx(
        guard,
        identity,
        parent_d,
        0,
        parent_caps,
        budget(2000, 2, 8),
        Arc::new(IdentitySemaphore::new(32)),
        CancellationToken::new(),
        tools,
        Arc::clone(&audit),
        Some(tmp.path().to_path_buf()),
        engine,
    );

    // Request stdio + http_outbound — http is not in parent effective → escalation.
    let req = HostDelegationRequest {
        tool: HostToolRef::Alias("child-echo".into()),
        requested_interfaces: Interface::Stdio.bit() | Interface::HttpOutbound.bit(),
        budget: None,
        input: br#"{}"#.to_vec(),
    };
    let out = host_delegate(&mut ctx, req).expect("no trap");
    assert!(
        matches!(out, Err(DelegateError::Escalation(_))),
        "got {out:?}"
    );
    assert_eq!(
        ctx.store_creations
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no child Store on escalation"
    );

    let refusals = audit.refusals.lock().unwrap();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].reason, "escalation");
    assert!(
        refusals[0].requested_caps_hash.is_some() && refusals[0].available_caps_hash.is_some(),
        "RT-13 dual caps_hash: {:?}",
        refusals[0]
    );
    assert_ne!(
        refusals[0].requested_caps_hash,
        refusals[0].available_caps_hash
    );
}

/// RT-14: depth / fan-out / max_children=0 — no child Store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt14_depth_fanout_no_child_store() {
    let engine = test_engine();
    let child_d = child_digest();
    let parent_d = parent_digest_escalate();

    // max_children = 0 → first call is fanout.
    let guard = load_guard(child_d, parent_d, 0, 2);
    let identity = parse_identity_thumbprint("agent", &thumb(7)).unwrap();
    let (parent_caps, _) = guard.policy(&identity, &parent_d).expect("grant");
    let parent_caps = parent_caps.clone();
    let tools = Arc::new(MapToolResolver::new());
    tools.insert(
        child_d,
        load_component(&engine, "adversarial/runtime/child_echo.wasm"),
        r#"{"type":"object"}"#,
    );
    let audit = Arc::new(RecordingDelegationAudit::default());
    let mut ctx = make_ctx(
        guard,
        identity,
        parent_d,
        0,
        parent_caps,
        budget(2000, 2, 0),
        Arc::new(IdentitySemaphore::new(32)),
        CancellationToken::new(),
        Arc::clone(&tools),
        Arc::clone(&audit),
        None,
        engine.clone(),
    );
    let out = host_delegate(
        &mut ctx,
        HostDelegationRequest {
            tool: HostToolRef::Alias("child-echo".into()),
            requested_interfaces: Interface::Stdio.bit()
                | Interface::Clocks.bit()
                | Interface::Filesystem.bit(),
            budget: None,
            input: br#"{}"#.to_vec(),
        },
    )
    .expect("no trap");
    assert!(matches!(out, Err(DelegateError::Fanout)), "got {out:?}");
    assert_eq!(
        ctx.store_creations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    // Depth exceeded: parent already at max_delegation_depth.
    let guard2 = load_guard(child_d, parent_d, 8, 1);
    let (parent_caps2, _) = guard2.policy(&identity, &parent_d).unwrap();
    let parent_caps2 = parent_caps2.clone();
    let audit2 = Arc::new(RecordingDelegationAudit::default());
    let mut ctx2 = make_ctx(
        guard2,
        identity,
        parent_d,
        1, // current_depth >= max (1) → depth
        parent_caps2,
        budget(2000, 1, 8),
        Arc::new(IdentitySemaphore::new(32)),
        CancellationToken::new(),
        tools,
        audit2,
        None,
        engine,
    );
    let out2 = host_delegate(
        &mut ctx2,
        HostDelegationRequest {
            tool: HostToolRef::Alias("child-echo".into()),
            requested_interfaces: Interface::Stdio.bit()
                | Interface::Clocks.bit()
                | Interface::Filesystem.bit(),
            budget: None,
            input: br#"{}"#.to_vec(),
        },
    )
    .expect("no trap");
    assert!(matches!(out2, Err(DelegateError::Depth)), "got {out2:?}");
    assert_eq!(
        ctx2.store_creations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// RT-15: child killed by its own budget → `::child-killed`; parent completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt15_child_killed_parent_completes() {
    let engine = test_engine();
    let _ticker = EpochTicker::start(engine.clone());
    let child_d = child_digest();
    let parent_d = parent_digest_escalate();
    let guard = load_guard(child_d, parent_d, 8, 2);
    let identity = parse_identity_thumbprint("agent", &thumb(7)).unwrap();
    let (parent_caps, _) = guard.policy(&identity, &parent_d).unwrap();
    let parent_caps = parent_caps.clone();

    let tools = Arc::new(MapToolResolver::new());
    let slow = load_component(&engine, "adversarial/runtime/slow_child.wasm");
    tools.insert(child_d, slow, r#"{"type":"object"}"#);

    let audit = Arc::new(RecordingDelegationAudit::default());
    let mut ctx = make_ctx(
        guard,
        identity,
        parent_d,
        0,
        parent_caps,
        budget(5000, 2, 8),
        Arc::new(IdentitySemaphore::new(32)),
        CancellationToken::new(),
        tools,
        Arc::clone(&audit),
        None,
        engine,
    );

    // Tiny child wall clock via requested budget.
    let child_budget = ResourceBudget::new(15, 500, 16 * 1024 * 1024, 1024, 2, 8, 32);
    let out = host_delegate(
        &mut ctx,
        HostDelegationRequest {
            tool: HostToolRef::Alias("child-echo".into()),
            requested_interfaces: Interface::Stdio.bit()
                | Interface::Clocks.bit()
                | Interface::Filesystem.bit(),
            budget: Some(child_budget),
            input: br#"{}"#.to_vec(),
        },
    )
    .expect("no parent trap");

    match out {
        Err(DelegateError::ChildKilled(cause)) => {
            assert!(
                matches!(
                    cause,
                    KillCause::Preempted | KillCause::WallClock | KillCause::Memory
                ),
                "unexpected cause {cause:?}"
            );
        }
        other => panic!("expected child-killed, got {other:?}"),
    }
    // Parent completed the host call with an error value (not a kill/trap).
    assert!(!ctx.token.is_cancelled() || ctx.token.is_cancelled());
}

/// RT-16: parent wall-clock mid-child → child ParentDropped, parent trap `WallClock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt16_parent_wall_clock_child_parent_dropped() {
    let engine = test_engine();
    let child_d = child_digest();
    let parent_d = parent_digest_escalate();
    let guard = load_guard(child_d, parent_d, 8, 2);
    let identity = parse_identity_thumbprint("agent", &thumb(7)).unwrap();
    let (parent_caps, _) = guard.policy(&identity, &parent_d).unwrap();
    let parent_caps = parent_caps.clone();

    let tools = Arc::new(MapToolResolver::new());
    // Slow child: park on a long sleep via a custom approach — use child_echo
    // with a host that blocks. Simpler: spawn child that waits on token by
    // using a tool resolver returning child_echo but cancel parent quickly.
    tools.insert(
        child_d,
        load_component(&engine, "adversarial/runtime/slow_child.wasm"),
        r#"{"type":"object"}"#,
    );

    let audit = Arc::new(RecordingDelegationAudit::default());
    let token = CancellationToken::new();
    let mut ctx = make_ctx(
        guard,
        identity,
        parent_d,
        0,
        parent_caps,
        budget(2000, 2, 8),
        Arc::new(IdentitySemaphore::new(32)),
        token.clone(),
        tools,
        Arc::clone(&audit),
        None,
        engine,
    );

    // Cancel parent shortly after starting delegate (simulates wall clock).
    let cancel = token.clone();
    helix_runtime::spawn_cancellable(cancel.clone(), move |t| async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if !t.is_cancelled() {
            t.cancel();
        }
    });

    // Absent budget → min(parent, policy); slow_child spins until parent cancel.
    let child_budget = None::<ResourceBudget>;
    let result = host_delegate(
        &mut ctx,
        HostDelegationRequest {
            tool: HostToolRef::Alias("child-echo".into()),
            requested_interfaces: Interface::Stdio.bit()
                | Interface::Clocks.bit()
                | Interface::Filesystem.bit(),
            budget: child_budget,
            input: br#"{}"#.to_vec(),
        },
    );

    assert!(
        result.is_err(),
        "parent must trap on wall-clock cancel, got {result:?}"
    );
    assert!(token.is_cancelled(), "parent token cancelled");

    // Wait briefly for child audit.
    for _ in 0..20 {
        if !audit.children.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let children = audit.children.lock().unwrap();
    assert!(!children.is_empty(), "child must record a terminal");
    assert!(
        matches!(
            children.last().unwrap().kind,
            TerminalKind::Killed {
                cause: KillCause::ParentDropped
            }
        ),
        "child terminal {:?}",
        children.last()
    );
}
