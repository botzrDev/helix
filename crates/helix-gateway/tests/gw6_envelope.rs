//! GW-6 / envelope + health coverage for M5-01 / HLX-32.
//!
//! GW-6: batch JSON-RPC array produces `-32600`.
//! Also covers parse error `-32700`, unknown method `-32601`, health detail,
//! and the `Request` seam via `helix.invoke` → pipeline (`-32004` provision when unwired).

use std::net::SocketAddr;

use helix_gateway::{
    parse_envelope, EnvelopeOutcome, GatewayConfig, GatewayRuntime, HealthDetail, TrustedProxy,
};
use helix_policy::{
    encode_thumbprint, parse_tool_digest, MapFs, MemoryArtifactStore, PolicyHolder,
    DEFAULT_MAX_SNAPSHOT_AGE_S,
};
use serde_json::{json, Value};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn test_policy_toml() -> String {
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
interfaces = ["stdio", "clocks"]
budget = "default"
"#,
        billing = thumb(1),
    )
}

fn load_holder() -> PolicyHolder {
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let store = MemoryArtifactStore::new()
        .with_digest(digest)
        .with_runtime_max(256);
    PolicyHolder::load(
        &test_policy_toml(),
        &store,
        &MapFs::new(),
        DEFAULT_MAX_SNAPSHOT_AGE_S,
    )
    .expect("policy load")
}

/// GW-6: batch array → -32600.
#[test]
fn gw6_batch_array_is_invalid_request() {
    let body = br#"[{"jsonrpc":"2.0","id":1,"method":"helix.health","params":{}}]"#;
    match parse_envelope(body) {
        EnvelopeOutcome::Err(v) => {
            assert_eq!(v["error"]["code"], json!(-32600));
            assert_eq!(v["error"]["data"]["reason"], json!("batch_not_supported"));
        }
        EnvelopeOutcome::Ok(_) => panic!("batch must be rejected"),
    }
}

#[test]
fn parse_error_is_32700() {
    match parse_envelope(b"{") {
        EnvelopeOutcome::Err(v) => assert_eq!(v["error"]["code"], json!(-32700)),
        EnvelopeOutcome::Ok(_) => panic!("expected parse error"),
    }
}

#[test]
fn empty_array_batch_is_32600() {
    match parse_envelope(b"[]") {
        EnvelopeOutcome::Err(v) => assert_eq!(v["error"]["code"], json!(-32600)),
        EnvelopeOutcome::Ok(_) => panic!("empty batch must be rejected"),
    }
}

#[tokio::test]
async fn health_unknown_method_batch_and_invoke_seam() {
    let config = GatewayConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        health_detail: HealthDetail::Full,
        trusted_proxies: vec![TrustedProxy::parse("127.0.0.1/32").unwrap()],
        ..Default::default()
    };

    let rt = GatewayRuntime::start(config, load_holder())
        .await
        .expect("start");
    let base = rt.base_url();
    rt.state().set_artifacts_loaded(3);

    let client = reqwest::Client::new();

    // helix.health via JSON-RPC (unauthenticated)
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":"h1","method":"helix.health","params":{}}"#)
        .send()
        .await
        .expect("health rpc");
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["result"]["status"], json!("ok"));
    assert_eq!(v["result"]["artifacts_loaded"], json!(3));
    assert!(v["result"]["policy_version"].is_string());
    assert_eq!(v["result"]["audit"], json!("ok"));

    // GET /health (runbook ops path)
    let resp = client
        .get(format!("{base}/health"))
        .send()
        .await
        .expect("get health");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["status"], json!("ok"));
    assert_eq!(v["artifacts_loaded"], json!(3));

    // unknown method → -32601
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":2,"method":"helix.nope","params":{}}"#)
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32601));

    // GW-6 over HTTP: batch → -32600
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .body(r#"[{"jsonrpc":"2.0","id":1,"method":"helix.health"}]"#)
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32600));

    // invoke without Authorization → -32001 (HLX-33 replaced stub identity)
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .body(
            r#"{"jsonrpc":"2.0","id":"i1","method":"helix.invoke","params":{"tool":"read_db","input":{"q":1}}}"#,
        )
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32001));
    assert_eq!(v["error"]["data"]["reason"], json!("signature"));

    // wrong content-type
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "text/plain")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"helix.health"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 415);

    rt.shutdown().await;
}

#[tokio::test]
async fn health_minimal_omits_detail_fields() {
    let config = GatewayConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        health_detail: HealthDetail::Minimal,
        ..Default::default()
    };

    let rt = GatewayRuntime::start(config, load_holder())
        .await
        .expect("start");
    let base = rt.base_url();
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"helix.health"}"#)
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["result"], json!({ "status": "ok" }));
    assert!(v["result"].get("artifacts_loaded").is_none());

    rt.shutdown().await;
}
