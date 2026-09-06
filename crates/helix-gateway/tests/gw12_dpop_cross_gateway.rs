//! GW-12: two gateways sharing `nonce_key`; challenge / `helix.nonce` cross-accept.
//!
//! Never prints tokens or key material.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use helix_gateway::{
    bind_identity, expected_htu, issue_nonce, nonce_acceptable, verify_token, DpopMode,
    DpopRuntime, GatewayConfig, GatewayRuntime, GatewayState, JwksCache, NonceKeys,
    VerificationKeys, VerifyParams,
};
use helix_policy::{
    encode_thumbprint, parse_tool_digest, MapFs, MemoryArtifactStore, PolicyHolder,
    DEFAULT_MAX_SNAPSHOT_AGE_S,
};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
    OctetKeyPairType,
};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};

const ISSUER: &str = "https://issuer.test/realms/helix";
const AUDIENCE: &str = "helix";
const ISSUER_PRIVATE_PEM: &str = include_str!("fixtures/issuer_ed25519_private.pem");
const ISSUER_PUBLIC_PEM: &str = include_str!("fixtures/issuer_ed25519_public.pem");
const AGENT_PRIV: &str = include_str!("fixtures/agent_dpop_ed25519_private.pem");
const AGENT_X: &str = include_str!("fixtures/agent_dpop_x.txt");
const AGENT_JKT: &str = include_str!("fixtures/agent_dpop_jkt.txt");
const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn agent_x() -> String {
    AGENT_X.trim().to_owned()
}
fn agent_jkt() -> String {
    AGENT_JKT.trim().to_owned()
}
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn now_i64() -> i64 {
    i64::try_from(now_secs()).unwrap()
}

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn load_holder() -> PolicyHolder {
    let digest = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let store = MemoryArtifactStore::new()
        .with_digest(digest)
        .with_runtime_max(256);
    let id = agent_jkt();
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
agent = "{id}"
[[grants]]
identity = "agent"
tool = "read_db"
digest = "{DIGEST_A}"
interfaces = ["stdio", "clocks"]
budget = "default"
"#
    );
    let _ = thumb(1);
    PolicyHolder::load(&toml, &store, &MapFs::new(), DEFAULT_MAX_SNAPSHOT_AGE_S).expect("policy")
}

fn write_nonce_key(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&path, perms).unwrap();
    path
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

#[derive(Serialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

fn sign_dpop(claims: &DpopClaims) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(Jwk {
        common: CommonParameters::default(),
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: agent_x(),
        }),
    });
    encode(
        &header,
        claims,
        &EncodingKey::from_ed_pem(AGENT_PRIV.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn dpop_proof(htu: &str, jti: &str, nonce: Option<String>) -> String {
    sign_dpop(&DpopClaims {
        htm: "POST".to_owned(),
        htu: htu.to_owned(),
        iat: now_i64(),
        jti: jti.to_owned(),
        nonce,
    })
}

fn issuer_keys() -> VerificationKeys {
    let mut keys = VerificationKeys::new();
    keys.insert(
        "issuer-1",
        DecodingKey::from_ed_pem(ISSUER_PUBLIC_PEM.as_bytes()).unwrap(),
    );
    keys
}

async fn start_gateway(
    external_url: &str,
    nonce_key: &[u8],
    ttl: u64,
) -> (GatewayRuntime, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.keep();
    let key_path = write_nonce_key(&dir_path, "nonce.key", nonce_key);
    let config = GatewayConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        dpop: DpopMode::Required,
        external_url: external_url.to_owned(),
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: "file://unused".to_owned(),
        nonce_key: Some(key_path.clone()),
        dpop_nonce_ttl_s: ttl,
        dpop_jti_window_s: ttl,
        ..Default::default()
    };
    let keys = NonceKeys::new(nonce_key.to_vec(), None).unwrap();
    let dpop = DpopRuntime::new(
        DpopMode::Required,
        external_url.to_owned(),
        keys,
        ttl,
        ttl,
        1_048_576,
    );
    let state = GatewayState::new(
        config.clone(),
        load_holder(),
        JwksCache::from_keys(issuer_keys()),
        Some(dpop),
    );
    let rt = GatewayRuntime::start_with_state(config, state)
        .await
        .expect("start");
    (rt, dir_path)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn gw12_shared_nonce_key_cross_gateway() {
    let shared_key = [42u8; 32];
    let ttl = 60u64;
    let external = "https://helix.example.com";

    let (gw_a, _dir_a) = start_gateway(external, &shared_key, ttl).await;
    let (gw_b, _dir_b) = start_gateway(external, &shared_key, ttl).await;
    let base_a = gw_a.base_url();
    let base_b = gw_b.base_url();
    let client = reqwest::Client::new();
    let jkt = agent_jkt();
    let htu = expected_htu(external, "/");
    let token = access_token();

    // helix.nonce from A → accepted by B's acceptor
    let resp = client
        .post(format!("{base_a}/"))
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"helix.nonce","params":{{"jkt":"{jkt}"}}}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let hdr = resp
        .headers()
        .get("DPoP-Nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let body: Value = resp.json().await.unwrap();
    let nonce_a = body["result"]["nonce"].as_str().unwrap().to_owned();
    assert_eq!(nonce_a, hdr);

    let keys = NonceKeys::new(shared_key.to_vec(), None).unwrap();
    assert!(nonce_acceptable(&keys, &jkt, &nonce_a, now_secs(), ttl));

    // Proof with A's nonce accepted on B (full HTTP invoke)
    let proof = dpop_proof(&htu, "gw12-jti-1", Some(nonce_a.clone()));
    let resp = client
        .post(format!("{base_b}/"))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof)
        .body(r#"{"jsonrpc":"2.0","id":"i1","method":"helix.invoke","params":{"tool":"read_db","input":{"q":1}}}"#)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let v: Value = resp.json().await.unwrap();
    // Pipeline not wired → -32004 after auth, or -32001 if policy identity mismatch
    assert!(
        status.is_success() || status.as_u16() == 200,
        "status {status}"
    );
    let code = v["error"]["code"].as_i64().unwrap();
    assert!(
        code == -32004 || code == -32003 || code == -32002,
        "unexpected {v}"
    );

    // Three-bucket-old nonce refused by both
    let bucket = now_secs() / ttl;
    let old = {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&shared_key).unwrap();
        mac.update(&(bucket.saturating_sub(3)).to_be_bytes());
        mac.update(jkt.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    };
    assert!(!nonce_acceptable(&keys, &jkt, &old, now_secs(), ttl));
    for base in [&base_a, &base_b] {
        let proof = dpop_proof(&htu, &format!("old-{}", base.len()), Some(old.clone()));
        let resp = client
            .post(format!("{base}/"))
            .header("content-type", "application/json")
            .header("authorization", format!("DPoP {token}"))
            .header("dpop", &proof)
            .body(r#"{"jsonrpc":"2.0","id":"o1","method":"helix.invoke","params":{"tool":"read_db","input":{}}}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert!(resp.headers().get("DPoP-Nonce").is_some());
        let v: Value = resp.json().await.unwrap();
        assert_eq!(v["error"]["data"]["reason"], json!("nonce"));
    }

    // Challenge flow: missing nonce → 401 + DPoP-Nonce → retry accepted
    let proof_missing = dpop_proof(&htu, "gw12-challenge", None);
    let resp = client
        .post(format!("{base_a}/"))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof_missing)
        .body(r#"{"jsonrpc":"2.0","id":"c1","method":"helix.invoke","params":{"tool":"read_db","input":{}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let challenge = resp
        .headers()
        .get("DPoP-Nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["data"]["reason"], json!("nonce"));

    let proof_retry = dpop_proof(&htu, "gw12-challenge-retry", Some(challenge));
    let resp = client
        .post(format!("{base_a}/"))
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", &proof_retry)
        .body(r#"{"jsonrpc":"2.0","id":"c2","method":"helix.invoke","params":{"tool":"read_db","input":{}}}"#)
        .send()
        .await
        .unwrap();
    let v: Value = resp.json().await.unwrap();
    assert_ne!(v["error"]["data"]["reason"], json!("nonce"));
    assert_ne!(v["error"]["data"]["reason"], json!("signature"));
    assert_ne!(v["error"]["data"]["reason"], json!("binding"));

    gw_a.shutdown().await;
    gw_b.shutdown().await;
}

#[test]
fn gw12_unit_nonce_from_a_math_on_b() {
    let keys = NonceKeys::new(vec![7u8; 32], None).unwrap();
    let jkt = agent_jkt();
    let ttl = 60;
    let now = now_secs();
    let n = issue_nonce(&keys, &jkt, now, ttl);
    // "gateway B" uses same keys
    assert!(nonce_acceptable(&keys, &jkt, &n, now, ttl));
    let bucket = now / ttl;
    let three_ago = {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(&keys.current).unwrap();
        mac.update(&(bucket.saturating_sub(3)).to_be_bytes());
        mac.update(jkt.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    };
    assert!(!nonce_acceptable(&keys, &jkt, &three_ago, now, ttl));
}

#[test]
fn access_token_binds_to_dpop_agent() {
    let token = access_token();
    let verified = verify_token(
        &token,
        &issuer_keys(),
        &VerifyParams {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
        },
    )
    .unwrap();
    let key = helix_gateway::Ed25519PublicJwk::from_x(agent_x());
    bind_identity(&verified.claims, Some(&key)).unwrap();
}
