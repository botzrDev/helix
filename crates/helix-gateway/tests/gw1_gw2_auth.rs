//! GW-1 / GW-2: EdDSA-only JWT verification and thumbprint identity (HLX-33).
//!
//! Never prints token values.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use helix_gateway::{
    bind_identity, derive_identity, verify_token, AccessClaims, AuthReason, CnfClaim,
    Ed25519PublicJwk, VerificationKeys, VerifyParams,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;

const ISSUER: &str = "https://issuer.test/realms/helix";
const AUDIENCE: &str = "helix";

const ISSUER_PRIVATE_PEM: &str = include_str!("fixtures/issuer_ed25519_private.pem");
const ISSUER_PUBLIC_PEM: &str = include_str!("fixtures/issuer_ed25519_public.pem");
const ISSUER_X: &str = include_str!("fixtures/issuer_x.txt");
const AGENT_X: &str = include_str!("fixtures/agent_x.txt");
const AGENT_JKT: &str = include_str!("fixtures/agent_jkt.txt");

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("fits i64")
}

fn params() -> VerifyParams {
    VerifyParams {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
    }
}

fn issuer_keys() -> VerificationKeys {
    let mut keys = VerificationKeys::new();
    keys.insert(
        "issuer-1",
        jsonwebtoken::DecodingKey::from_ed_pem(ISSUER_PUBLIC_PEM.as_bytes()).expect("pub"),
    );
    keys
}

fn agent_jkt() -> String {
    AGENT_JKT.trim().to_owned()
}

fn agent_key() -> Ed25519PublicJwk {
    Ed25519PublicJwk::from_x(AGENT_X.trim())
}

#[derive(Serialize)]
struct WireClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
    cnf: CnfWire,
}

#[derive(Serialize)]
struct CnfWire {
    jkt: String,
}

fn good_claims() -> WireClaims {
    let jkt = agent_jkt();
    let t = now();
    WireClaims {
        iss: ISSUER.to_owned(),
        sub: jkt.clone(),
        aud: AUDIENCE.to_owned(),
        exp: t + 600,
        iat: t,
        nbf: None,
        cnf: CnfWire { jkt },
    }
}

fn sign_eddsa(claims: &WireClaims) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("issuer-1".to_owned());
    encode(
        &header,
        claims,
        &EncodingKey::from_ed_pem(ISSUER_PRIVATE_PEM.as_bytes()).expect("priv"),
    )
    .expect("sign")
}

fn b64url_json(v: &serde_json::Value) -> String {
    let raw = serde_json::to_vec(v).expect("json");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

/// Craft a compact JWT with an arbitrary header alg and payload (unsigned / fake sig).
fn craft_token(alg: &str, claims: &serde_json::Value) -> String {
    let header = json!({ "alg": alg, "typ": "JWT" });
    format!(
        "{}.{}.{}",
        b64url_json(&header),
        b64url_json(claims),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig")
    )
}

/// Poisoned claims: would fail `AccessClaims` deserialize if ever parsed.
fn poisoned_claims() -> serde_json::Value {
    json!({
        "iss": ISSUER,
        "sub": agent_jkt(),
        "aud": AUDIENCE,
        "exp": "not-a-number",
        "iat": "also-bad",
        "cnf": { "jkt": agent_jkt() },
        "evil": { "nested": true }
    })
}

// ----- GW-1 -----

#[test]
fn gw1_hs256_rejected_before_claims() {
    let token = craft_token("HS256", &poisoned_claims());
    let err = verify_token(&token, &issuer_keys(), &params()).expect_err("HS256");
    assert_eq!(err.reason, AuthReason::Signature);
}

#[test]
fn gw1_none_rejected_before_claims() {
    let token = craft_token("none", &poisoned_claims());
    let err = verify_token(&token, &issuer_keys(), &params()).expect_err("none");
    assert_eq!(err.reason, AuthReason::Signature);
}

#[test]
fn gw1_rs256_rejected_before_claims() {
    let token = craft_token("RS256", &poisoned_claims());
    let err = verify_token(&token, &issuer_keys(), &params()).expect_err("RS256");
    assert_eq!(err.reason, AuthReason::Signature);
}

#[test]
fn gw1_valid_eddsa_accepted() {
    let token = sign_eddsa(&good_claims());
    let verified = verify_token(&token, &issuer_keys(), &params()).expect("valid");
    assert_eq!(verified.claims.sub, agent_jkt());
    let id = bind_identity(&verified.claims, None).expect("bind");
    assert_eq!(id, derive_identity(&agent_key()));
}

// ----- GW-2 -----

#[test]
fn gw2_expired_reason_expired() {
    let mut claims = good_claims();
    claims.exp = now() - 10;
    claims.iat = now() - 100;
    let token = sign_eddsa(&claims);
    let err = verify_token(&token, &issuer_keys(), &params()).expect_err("expired");
    assert_eq!(err.reason, AuthReason::Expired);
}

#[test]
fn gw2_nbf_not_yet_valid_reason_expired() {
    let mut claims = good_claims();
    claims.nbf = Some(now() + 600);
    let token = sign_eddsa(&claims);
    let err = verify_token(&token, &issuer_keys(), &params()).expect_err("nbf");
    assert_eq!(err.reason, AuthReason::Expired);
}

#[test]
fn gw2_wrong_aud_reason_signature() {
    let mut claims = good_claims();
    claims.aud = "not-helix".to_owned();
    let token = sign_eddsa(&claims);
    let err = verify_token(&token, &issuer_keys(), &params()).expect_err("aud");
    assert_eq!(err.reason, AuthReason::Signature);
}

#[test]
fn gw2_sub_cnf_mismatch_reason_binding() {
    let token = sign_eddsa(&good_claims());
    let verified = verify_token(&token, &issuer_keys(), &params()).expect("verify");
    let mut claims = verified.claims;
    claims.sub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
    let err = bind_identity(&claims, None).expect_err("binding");
    assert_eq!(err.reason, AuthReason::Binding);
}

#[test]
fn gw2_proof_thumbprint_mismatch_reason_binding() {
    let token = sign_eddsa(&good_claims());
    let verified = verify_token(&token, &issuer_keys(), &params()).expect("verify");
    // Issuer public key thumbprint ≠ agent jkt.
    let wrong_proof = Ed25519PublicJwk::from_x(ISSUER_X.trim());
    assert_ne!(derive_identity(&wrong_proof), derive_identity(&agent_key()));
    let err = bind_identity(&verified.claims, Some(&wrong_proof)).expect_err("proof");
    assert_eq!(err.reason, AuthReason::Binding);
}

#[test]
fn gw2_proof_thumbprint_match_ok() {
    let token = sign_eddsa(&good_claims());
    let verified = verify_token(&token, &issuer_keys(), &params()).expect("verify");
    let id = bind_identity(&verified.claims, Some(&agent_key())).expect("bind");
    assert_eq!(id, derive_identity(&agent_key()));
}

#[test]
fn derive_identity_matches_fixture_jkt() {
    let id = derive_identity(&agent_key());
    let jkt = helix_gateway::identity_to_jkt(id);
    assert_eq!(jkt, agent_jkt());
}

#[test]
fn access_claims_roundtrip_shape() {
    let claims = AccessClaims {
        iss: ISSUER.to_owned(),
        sub: agent_jkt(),
        aud: vec![AUDIENCE.to_owned()],
        exp: now() + 1,
        iat: now(),
        nbf: None,
        cnf: CnfClaim { jkt: agent_jkt() },
    };
    let v = serde_json::to_value(&claims).unwrap();
    let back: AccessClaims = serde_json::from_value(v).unwrap();
    assert_eq!(back.sub, claims.sub);
}
