//! GW-5: payload violating `input-schema` → `-32602` with correct `data.path` (HLX-35).
//!
//! Never prints token values.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use helix_gateway::{
    DpopMode, GatewayConfig, GatewayRuntime, GatewayState, JwksCache, SchemaRegistry,
    VerificationKeys,
};
use helix_policy::{
    parse_tool_digest, MapFs, MemoryArtifactStore, PolicyHolder, DEFAULT_MAX_SNAPSHOT_AGE_S,
};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};

const ISSUER: &str = "https://issuer.test/realms/helix";
const AUDIENCE: &str = "helix";
const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const ISSUER_PRIVATE_PEM: &str = include_str!("fixtures/issuer_ed25519_private.pem");
const ISSUER_PUBLIC_PEM: &str = include_str!("fixtures/issuer_ed25519_public.pem");
const AGENT_JKT: &str = include_str!("fixtures/agent_jkt.txt");

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("fits")
}

fn agent_jkt() -> String {
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

fn access_token() -> String {
    let jkt = agent_jkt();
    let t = now();
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
        &EncodingKey::from_ed_pem(ISSUER_PRIVATE_PEM.as_bytes()).expect("priv"),
    )
    .expect("sign")
}

fn issuer_keys() -> VerificationKeys {
    let mut keys = VerificationKeys::new();
    keys.insert(
        "issuer-1",
        DecodingKey::from_ed_pem(ISSUER_PUBLIC_PEM.as_bytes()).expect("pub"),
    );
    keys
}

fn load_holder() -> PolicyHolder {
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let store = MemoryArtifactStore::new()
        .with_digest(digest)
        .with_runtime_max(256);
    let jkt = agent_jkt();
    let toml = format!(
        r#"
version = 1

[tools]
read_db = "{DIGEST_A}"

[budgets.default]
wall_clock_ms = 2000
memory_bytes = 67108864
output_bytes = 1048576

[identities]
agent = "{jkt}"

[[grants]]
identity = "agent"
tool = "read_db"
digest = "{DIGEST_A}"
interfaces = ["stdio", "clocks"]
budget = "default"
"#
    );
    PolicyHolder::load(&toml, &store, &MapFs::new(), DEFAULT_MAX_SNAPSHOT_AGE_S).expect("policy")
}

#[tokio::test]
async fn gw5_schema_violation_is_32602_with_path() {
    let config = GatewayConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        dpop: DpopMode::Off,
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: "file://unused".to_owned(),
        ..Default::default()
    };
    let state = GatewayState::new(
        config.clone(),
        load_holder(),
        JwksCache::from_keys(issuer_keys()),
        None,
    );

    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let mut schemas = SchemaRegistry::new();
    schemas
        .insert_raw(
            &digest,
            r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}"#,
        )
        .unwrap();
    state.set_schemas(schemas);

    let rt = GatewayRuntime::start_with_state(config, state)
        .await
        .expect("start");
    let base = rt.base_url();
    let client = reqwest::Client::new();
    let token = access_token();

    // Wrong type at /query → -32602 with data.path == "/query"
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(
            r#"{"jsonrpc":"2.0","id":"gw5","method":"helix.invoke","params":{"tool":"read_db","input":{"query":42}}}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32602));
    assert_eq!(v["error"]["data"]["path"], json!("/query"));
    assert!(v["error"]["data"]["reason"]
        .as_str()
        .unwrap()
        .contains("type"));
    assert!(v["error"]["data"]["request_id"].is_string());

    // Valid payload passes schema gate → provision not wired (-32004)
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(
            r#"{"jsonrpc":"2.0","id":"gw5b","method":"helix.invoke","params":{"tool":"read_db","input":{"query":"SELECT 1"}}}"#,
        )
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32004));
    assert_eq!(v["error"]["data"]["reason"], json!("not_wired"));

    rt.shutdown().await;
}

#[test]
fn gw5_unit_missing_required_path() {
    use helix_gateway::{validate_payload, PayloadSchema};
    let schema = PayloadSchema::parse(
        r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}"#,
    )
    .unwrap();
    let err = validate_payload(&schema, br"{}").unwrap_err();
    assert_eq!(err.path, "/query");
}
