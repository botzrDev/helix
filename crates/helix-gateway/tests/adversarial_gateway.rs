//! HLX-37 / M5-06: adversarial suite through the gateway.
//!
//! Gateway namespace: batch envelope, `alg:none` token, replayed `DPoP` proof,
//! concurrency flood from one identity.
//!
//! Runtime fixtures exercised end-to-end where the root invoke path supports
//! them: spin / membomb / flood invoke guests → kill JSON-RPC codes within
//! `budget.wall_clock_ms`.
//!
//! HOLEs (documented in `tests/adversarial/`):
//! - `traverse.wasm` guest: host canary in helix-runtime (RT-2/3/4).
//! - `unlinked.wasm` sockets: runtime provision (RT-1); no signature export for registry.
//! - `slowhost.wasm` guest-through-gateway: M4-07 host tarpit path (needs async HTTP guest).
//! - `escalate` / `fanout`: runtime namespace (delegate not linked on root `invoke`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use common::*;
use helix_gateway::{
    expected_htu, DpopMode, DpopRuntime, GatewayConfig, GatewayRuntime, GatewayState, JwksCache,
    NonceKeys, ToolRuntime,
};
use helix_runtime::digest_of_bytes;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
    OctetKeyPairType,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};
use tempfile::tempdir;
use tokio::sync::Notify;

const AGENT_DPOP_PRIV: &str = include_str!("fixtures/agent_dpop_ed25519_private.pem");
const AGENT_DPOP_X: &str = include_str!("fixtures/agent_dpop_x.txt");
const AGENT_DPOP_JKT: &str = include_str!("fixtures/agent_dpop_jkt.txt");

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

fn now_i64() -> i64 {
    i64::try_from(now_secs()).expect("fits")
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Craft compact JWT with arbitrary `alg` (unsigned / fake sig) — never logs token.
fn craft_alg_token(alg: &str, claims: &Value) -> String {
    let header = json!({ "alg": alg, "typ": "JWT" });
    format!(
        "{}.{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes()),
        b64url(b"x")
    )
}

async fn start_tools_gateway(
    wasm: &[u8],
    alias: &str,
    preempt: u32,
    wall: u32,
    memory: u64,
    output: u32,
    max_concurrent: u32,
) -> (GatewayRuntime, tempfile::TempDir, String) {
    let dir = tempdir().unwrap();
    let digest = digest_of_bytes(wasm);
    let d = format!("sha256:{}", helix_runtime::digest_hex(&digest));
    let mut state = make_state(load_holder_budget(
        &d,
        alias,
        &agent_jkt(),
        max_concurrent,
        r#""stdio", "clocks", "random", "filesystem""#,
        preempt,
        wall,
        memory,
        output,
    ));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = ToolRuntime::new(&tools_dir).unwrap();
    tools.register_bytes(wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    (rt, dir, alias.to_owned())
}

async fn invoke_tool(base: &str, alias: &str) -> (Value, Duration) {
    let token = access_token();
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{{"tool":"{alias}","input":{{}}}}}}"#
    );
    let started = Instant::now();
    let v = post_rpc(base, &token, &body).await;
    (v, started.elapsed())
}

fn assert_killed_within(v: &Value, code: i64, wall_ms: u32, elapsed: Duration) {
    assert_eq!(v["error"]["code"], json!(code), "body={v}");
    assert!(
        elapsed <= Duration::from_millis(u64::from(wall_ms).saturating_add(2_000)),
        "elapsed {elapsed:?} exceeds wall_clock_ms={wall_ms} (+slack)",
    );
    if let Some(usage) = v["error"]["data"].get("usage") {
        let wall = usage["wall_ms"].as_u64().unwrap_or(0);
        assert!(
            wall <= u64::from(wall_ms).saturating_add(500),
            "usage.wall_ms={wall} > budget {wall_ms}"
        );
    }
}

// ----- Runtime fixtures through gateway -----

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adv_spin_invoke_killed_preempted_through_gateway() {
    let wasm = std::fs::read(adversarial_fixture("runtime/spin_invoke.wasm")).unwrap();
    let wall = 500u32;
    let preempt = 25u32;
    let (rt, _dir, alias) =
        start_tools_gateway(&wasm, "spin", preempt, wall, 16 * 1024 * 1024, 65_536, 4).await;
    let (v, elapsed) = invoke_tool(&rt.base_url(), &alias).await;
    assert_killed_within(&v, -32010, wall, elapsed);
    rt.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adv_membomb_invoke_killed_memory_through_gateway() {
    let wasm = std::fs::read(adversarial_fixture("runtime/membomb_invoke.wasm")).unwrap();
    let wall = 5_000u32;
    let (rt, _dir, alias) = start_tools_gateway(
        &wasm,
        "membomb",
        wall, // preempt_ticks <= wall_clock_ms (POL-1)
        wall,
        2 * 1024 * 1024, // 2 MiB — room to instantiate; guest grows past
        65_536,
        4,
    )
    .await;
    let (v, elapsed) = invoke_tool(&rt.base_url(), &alias).await;
    assert_killed_within(&v, -32012, wall, elapsed);
    rt.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adv_flood_invoke_killed_output_through_gateway() {
    let wasm = std::fs::read(adversarial_fixture("runtime/flood.wasm")).unwrap();
    let wall = 5_000u32;
    let (rt, _dir, alias) = start_tools_gateway(
        &wasm,
        "flood",
        5_000,
        wall,
        16 * 1024 * 1024,
        4_096, // tight output budget; guest returns 256 KiB
        4,
    )
    .await;
    let (v, elapsed) = invoke_tool(&rt.base_url(), &alias).await;
    assert_killed_within(&v, -32013, wall, elapsed);
    rt.shutdown().await;
}

// ----- Gateway namespace -----

#[tokio::test]
async fn adv_gateway_batch_envelope_32600() {
    let dir = tempdir().unwrap();
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let mut state = make_state(load_holder_with(&d, "hello", &agent_jkt(), 8, r#""stdio""#));
    let tools = ToolRuntime::new(dir.path().join("artifacts")).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/", rt.base_url()))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", access_token()))
        .body(r#"[{"jsonrpc":"2.0","id":1,"method":"helix.health","params":{}}]"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32600));
    assert_eq!(v["error"]["data"]["reason"], json!("batch_not_supported"));
    rt.shutdown().await;
}

#[tokio::test]
async fn adv_gateway_alg_none_token_32001() {
    let dir = tempdir().unwrap();
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let mut state = make_state(load_holder_with(&d, "hello", &agent_jkt(), 8, r#""stdio""#));
    let tools = ToolRuntime::new(dir.path().join("artifacts")).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;

    let claims = json!({
        "iss": ISSUER,
        "sub": agent_jkt(),
        "aud": AUDIENCE,
        "exp": now_i64() + 600,
        "iat": now_i64(),
        "cnf": { "jkt": agent_jkt() },
    });
    let bad = craft_alg_token("none", &claims);
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/", rt.base_url()))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bad}"))
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"x"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32001));
    // Closed reason set; alg rejection maps to signature.
    let reason = v["error"]["data"]["reason"].as_str().unwrap_or("");
    assert!(
        reason == "signature" || reason == "binding",
        "unexpected reason {reason}"
    );
    rt.shutdown().await;
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

#[derive(Serialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

fn dpop_agent_jkt() -> String {
    AGENT_DPOP_JKT.trim().to_owned()
}

fn dpop_access_token() -> String {
    let jkt = dpop_agent_jkt();
    let t = now_i64();
    let claims = WireClaims {
        iss: ISSUER.to_owned(),
        sub: jkt.clone(),
        aud: AUDIENCE.to_owned(),
        exp: t + 600,
        iat: t,
        cnf: CnfWire { jkt },
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("issuer-1".to_owned());
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(ISSUER_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn sign_dpop(claims: &DpopClaims) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(Jwk {
        common: CommonParameters::default(),
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: AGENT_DPOP_X.trim().to_owned(),
        }),
    });
    encode(
        &header,
        claims,
        &EncodingKey::from_ed_pem(AGENT_DPOP_PRIV.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adv_gateway_replayed_dpop_proof_32001() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("nonce.key");
    std::fs::write(&key_path, [7u8; 32]).unwrap();
    let external = "https://helix.example.com";
    let ttl = 60u64;

    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let policy = load_holder_with(&d, "hello", &dpop_agent_jkt(), 8, r#""stdio""#);

    let config = GatewayConfig {
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        dpop: DpopMode::Required,
        external_url: external.to_owned(),
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: "file://unused".to_owned(),
        nonce_key: Some(key_path.clone()),
        dpop_nonce_ttl_s: ttl,
        ..Default::default()
    };
    let keys = NonceKeys::new(vec![7u8; 32], None).unwrap();
    let dpop = DpopRuntime::new(
        DpopMode::Required,
        external.to_owned(),
        keys,
        ttl,
        ttl,
        1_048_576,
    );
    let mut state = GatewayState::new(
        config.clone(),
        policy,
        JwksCache::from_keys(issuer_keys()),
        Some(dpop),
    );
    let tools = ToolRuntime::new(dir.path().join("artifacts")).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = GatewayRuntime::start_with_state(config, state)
        .await
        .expect("start");

    let client = reqwest::Client::new();
    let jkt = dpop_agent_jkt();
    let token = dpop_access_token();
    let htu = expected_htu(external, "/");

    let nonce_resp = client
        .post(format!("{}/", rt.base_url()))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"helix.nonce","params":{{"jkt":"{jkt}"}}}}"#
        ))
        .send()
        .await
        .unwrap();
    let nonce_body: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_body["result"]["nonce"].as_str().unwrap().to_owned();

    let proof = sign_dpop(&DpopClaims {
        htm: "POST".to_owned(),
        htu: htu.clone(),
        iat: now_i64(),
        jti: "adv-replay-jti-1".to_owned(),
        nonce: Some(nonce),
    });

    let body = r#"{"jsonrpc":"2.0","id":2,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"x"}}}"#;
    let first = client
        .post(format!("{}/", rt.base_url()))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_v: Value = first.json().await.unwrap();
    // First may complete or fail tool path; must not be unauthenticated.
    if let Some(code) = first_v["error"]["code"].as_i64() {
        assert_ne!(code, -32001, "first proof must authenticate: {first_v}");
    }

    let replay = client
        .post(format!("{}/", rt.base_url()))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 200);
    let v: Value = replay.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32001), "replay body={v}");
    assert_eq!(v["error"]["data"]["reason"], json!("replay"));
    rt.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn adv_gateway_concurrency_flood_one_identity() {
    let dir = tempdir().unwrap();
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let cap = 4u32;
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        cap,
        r#""stdio""#,
    ));
    let mut tools = ToolRuntime::new(dir.path().join("artifacts")).unwrap();
    tools.register_bytes(&wasm).unwrap();
    let hold = Arc::new(Notify::new());
    tools.set_hold(Some(Arc::clone(&hold)));
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    let base = rt.base_url();
    let token = access_token();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"x"}}}"#;

    let mut joins = tokio::task::JoinSet::new();
    for i in 0..cap {
        let base = base.clone();
        let token = token.clone();
        let body = body.to_owned();
        joins.spawn(async move {
            let _ = (i, post_rpc(&base, &token, &body).await);
        });
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let overflow = post_rpc(&base, &token, body).await;
    assert_eq!(overflow["error"]["code"], json!(-32002));
    assert_eq!(overflow["error"]["data"]["reason"], json!("concurrency"));
    hold.notify_waiters();
    while joins.join_next().await.is_some() {}
    rt.shutdown().await;
}

#[test]
fn adv_fixture_matrix_present() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/adversarial");
    for rel in [
        "spin.wasm",
        "membomb.wasm",
        "flood.wasm",
        "runtime/spin_invoke.wasm",
        "runtime/membomb_invoke.wasm",
        "runtime/flood.wasm",
        "runtime/escalate.wasm",
        "runtime/fanout.wasm",
        "runtime/child_echo.wasm",
        "runtime/slow_child.wasm",
    ] {
        let p = root.join(rel);
        assert!(p.is_file(), "missing fixture {rel} at {}", p.display());
    }
    let unlinked = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/sockets-import/unlinked.wasm");
    assert!(unlinked.is_file());
}
