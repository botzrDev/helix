//! GW-3 / GW-4 / GW-14: `DPoP` `jti` cache, `htu`/nonce, capacity (HLX-34).
//!
//! Never prints token or nonce key values.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use helix_gateway::{
    expected_htu, issue_nonce, nonce_acceptable, verify_dpop_proof, AuthReason, JtiCache, NonceKeys,
};
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
    OctetKeyPairType,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::Sha256;

const AGENT_PRIV: &str = include_str!("fixtures/agent_dpop_ed25519_private.pem");
const AGENT_X: &str = include_str!("fixtures/agent_dpop_x.txt");
const AGENT_JKT: &str = include_str!("fixtures/agent_dpop_jkt.txt");

fn agent_x() -> String {
    AGENT_X.trim().to_owned()
}

fn agent_jkt() -> String {
    AGENT_JKT.trim().to_owned()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

fn now_i64() -> i64 {
    i64::try_from(now_secs()).expect("fits")
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

fn dpop_header() -> Header {
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
    header
}

fn sign_dpop(claims: &DpopClaims) -> String {
    encode(
        &dpop_header(),
        claims,
        &EncodingKey::from_ed_pem(AGENT_PRIV.as_bytes()).expect("priv"),
    )
    .expect("sign")
}

fn good_proof(htu: &str, jti: &str, nonce: Option<String>) -> String {
    let claims = DpopClaims {
        htm: "POST".to_owned(),
        htu: htu.to_owned(),
        iat: now_i64(),
        jti: jti.to_owned(),
        nonce,
    };
    sign_dpop(&claims)
}

// ----- GW-3 -----

#[test]
fn gw3_reused_jti_inside_window_rejected() {
    let cache = JtiCache::new(64 * 4, 60);
    let now = SystemTime::now();
    cache.insert("jti-1", now).expect("first");
    let err = cache.insert("jti-1", now).expect_err("replay");
    assert_eq!(err.reason, AuthReason::Replay);
}

#[test]
fn gw3_jti_outside_window_accepted() {
    let cache = JtiCache::new(64 * 4, 1);
    let t0 = UNIX_EPOCH + Duration::from_secs(1_000);
    cache.insert("jti-out", t0).expect("first");
    let t1 = t0 + Duration::from_secs(2);
    cache.evict_all_expired(t1);
    cache.insert("jti-out", t1).expect("after window");
}

// ----- GW-4 -----

#[test]
fn gw4_htu_mismatch_rejected() {
    let htu = expected_htu("https://helix.example.com", "/");
    let proof = good_proof("https://evil.example.com/", "jti-htu", Some("n".into()));
    let err = verify_dpop_proof(&proof, &htu, now_i64()).expect_err("htu");
    assert_eq!(err.reason, AuthReason::Signature);
}

#[test]
fn gw4_stale_nonce_rejected_by_acceptor() {
    let keys = NonceKeys::new(vec![9u8; 32], None).unwrap();
    let jkt = agent_jkt();
    let ttl = 60u64;
    let now = now_secs();
    let bucket = now / ttl;
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys.current).unwrap();
    mac.update(&(bucket.saturating_sub(3)).to_be_bytes());
    mac.update(jkt.as_bytes());
    let stale =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    assert!(!nonce_acceptable(&keys, &jkt, &stale, now, ttl));
    let fresh = issue_nonce(&keys, &jkt, now, ttl);
    assert!(nonce_acceptable(&keys, &jkt, &fresh, now, ttl));
}

#[test]
fn gw4_valid_proof_with_htu_and_nonce_ok() {
    let keys = NonceKeys::new(vec![3u8; 32], None).unwrap();
    let external = "https://helix.example.com";
    let htu = expected_htu(external, "/");
    let jkt = agent_jkt();
    let nonce = issue_nonce(&keys, &jkt, now_secs(), 60);
    let proof = good_proof(&htu, "jti-ok-1", Some(nonce));
    let v = verify_dpop_proof(&proof, &htu, now_i64()).expect("proof");
    assert_eq!(v.jkt, jkt);
}

// ----- GW-14 -----

#[test]
fn gw14_cache_full_refuses_and_recovers() {
    // max_entries=64 → 1 entry per shard.
    let cache = JtiCache::new(64, 60);
    let now = UNIX_EPOCH + Duration::from_secs(5_000);
    let mut i = 0u64;
    let mut placed = None;
    while placed.is_none() {
        let jti = format!("fill-{i}");
        i += 1;
        if JtiCache::shard_index(&jti) == 0 {
            cache.insert(&jti, now).expect("fill shard 0");
            placed = Some(jti);
        }
    }
    // Next jti that maps to shard 0 must fail (capacity 1, nothing evictable).
    let mut overflow = None;
    while overflow.is_none() {
        let jti = format!("overflow-{i}");
        i += 1;
        if JtiCache::shard_index(&jti) == 0 {
            overflow = Some(jti);
        }
    }
    let before = cache.full_total();
    let err = cache
        .insert(overflow.as_ref().unwrap(), now)
        .expect_err("full");
    assert_eq!(err.reason, AuthReason::Replay);
    assert_eq!(cache.full_total(), before + 1);

    let later = now + Duration::from_secs(61);
    cache.evict_all_expired(later);
    cache
        .insert(overflow.as_ref().unwrap(), later)
        .expect("after window");
}
