//! Shared helpers for gateway integration tests (HLX-36).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use helix_audit::{
    AuditWriter, AuditWriterRuntime, CapsStore, FailClosedConfig, FileHeader, IoFault,
    NoopSyncHook, RecordingFatal, Transition,
};
use helix_gateway::{
    DpopMode, GatewayConfig, GatewayRuntime, GatewayState, JwksCache, ToolRuntime, VerificationKeys,
};
use helix_policy::{
    parse_tool_digest, MapFs, MemoryArtifactStore, PolicyHolder, DEFAULT_MAX_SNAPSHOT_AGE_S,
};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;

pub const ISSUER: &str = "https://issuer.test/realms/helix";
pub const AUDIENCE: &str = "helix";

pub const ISSUER_PRIVATE_PEM: &str = include_str!("../fixtures/issuer_ed25519_private.pem");
pub const ISSUER_PUBLIC_PEM: &str = include_str!("../fixtures/issuer_ed25519_public.pem");
pub const AGENT_JKT: &str = include_str!("../fixtures/agent_jkt.txt");

pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("fits")
}

pub fn agent_jkt() -> String {
    AGENT_JKT.trim().to_owned()
}

#[derive(Serialize)]
struct WireClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    cnf: CnfWire,
}

#[derive(Serialize)]
struct CnfWire {
    jkt: String,
}

pub fn access_token_for(jkt: &str) -> String {
    let t = now();
    let claims = WireClaims {
        iss: ISSUER.to_owned(),
        sub: jkt.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: t + 600,
        iat: t,
        cnf: CnfWire {
            jkt: jkt.to_owned(),
        },
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("issuer-1".to_owned());
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(ISSUER_PRIVATE_PEM.as_bytes()).expect("priv"),
    )
    .expect("sign")
}

pub fn access_token() -> String {
    access_token_for(&agent_jkt())
}

pub fn issuer_keys() -> VerificationKeys {
    let mut keys = VerificationKeys::new();
    keys.insert(
        "issuer-1",
        DecodingKey::from_ed_pem(ISSUER_PUBLIC_PEM.as_bytes()).expect("pub"),
    );
    keys
}

pub fn hello_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hello-world/hello_world.wasm")
}

pub fn http_import_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/http-import/http_import.wasm")
}

pub fn load_holder_with(
    digest_hex: &str,
    tool_alias: &str,
    jkt: &str,
    max_concurrent: u32,
    interfaces: &str,
) -> PolicyHolder {
    let digest = parse_tool_digest(tool_alias, digest_hex).unwrap();
    let store = MemoryArtifactStore::new()
        .with_digest(digest)
        .with_runtime_max(256);
    let toml = format!(
        r#"
version = 1

[tools]
{tool_alias} = "{digest_hex}"

[budgets.default]
wall_clock_ms = 5000
memory_bytes = 67108864
output_bytes = 1048576
max_concurrent_instances = {max_concurrent}

[identities]
agent = "{jkt}"

[[grants]]
identity = "agent"
tool = "{tool_alias}"
digest = "{digest_hex}"
interfaces = [{interfaces}]
budget = "default"
"#
    );
    PolicyHolder::load(&toml, &store, &MapFs::new(), DEFAULT_MAX_SNAPSHOT_AGE_S).expect("policy")
}

pub fn base_config() -> GatewayConfig {
    GatewayConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        dpop: DpopMode::Off,
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: "file://unused".to_owned(),
        health_detail: helix_gateway::HealthDetail::Full,
        ..Default::default()
    }
}

pub async fn open_audit(dir: &std::path::Path) -> (AuditWriterRuntime, AuditWriter, CapsStore) {
    let log = dir.join("audit.log");
    let fatal = RecordingFatal::new();
    let fc = FailClosedConfig::for_test(Arc::new(helix_audit::NoopIoFault), fatal);
    let rt = AuditWriterRuntime::open_genesis_with_hook_fail_closed(
        &log,
        "gw-test",
        [0u8; 16],
        Arc::new(NoopSyncHook),
        16,
        fc,
    )
    .await
    .expect("audit open");
    let w = rt.writer();
    let caps = CapsStore::open(dir).expect("caps");
    (rt, w, caps)
}

pub async fn open_audit_fault(
    dir: &std::path::Path,
    fault: Arc<dyn IoFault>,
) -> (AuditWriterRuntime, AuditWriter, CapsStore) {
    let log = dir.join("audit.log");
    let fatal = RecordingFatal::new();
    let fc = FailClosedConfig::for_test(fault, fatal).with_max_consecutive_errors(10);
    let rt = AuditWriterRuntime::open_genesis_with_hook_fail_closed(
        &log,
        "gw-test",
        [0u8; 16],
        Arc::new(NoopSyncHook),
        16,
        fc,
    )
    .await
    .expect("audit open");
    let w = rt.writer();
    let caps = CapsStore::open(dir).expect("caps");
    (rt, w, caps)
}

pub fn read_transitions(log_path: &std::path::Path) -> Vec<(Transition, String)> {
    // Allow writer to flush.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let bytes = std::fs::read(log_path).unwrap_or_default();
    if bytes.is_empty() {
        return Vec::new();
    }
    let (_header, mut offset) = FileHeader::decode_cbor(&bytes).expect("header");
    let mut out = Vec::new();
    while offset < bytes.len() {
        let (frame, n) = helix_audit::frame::decode_frame(&bytes[offset..]).expect("frame");
        offset += n;
        out.push((frame.record.transition, frame.record.reason.clone()));
    }
    out
}

pub fn assert_has_transition(log: &std::path::Path, want: Transition) {
    let ts = read_transitions(log);
    assert!(
        ts.iter().any(|(t, _)| *t == want),
        "expected {want:?} in {ts:?}"
    );
}

pub async fn post_rpc(base: &str, token: &str, body: &str) -> Value {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(body.to_owned())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

pub fn make_state(policy: PolicyHolder) -> GatewayState {
    GatewayState::new(
        base_config(),
        policy,
        JwksCache::from_keys(issuer_keys()),
        None,
    )
}

pub async fn start(state: GatewayState) -> GatewayRuntime {
    GatewayRuntime::start_with_state(base_config(), state)
        .await
        .expect("start")
}

pub fn register_hello(tools: &ToolRuntime) -> helix_caps::ToolDigest {
    tools.register_path(&hello_wasm()).expect("register hello")
}
