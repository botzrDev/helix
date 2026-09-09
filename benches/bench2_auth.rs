//! BENCH-2: Ed25519 JWT + `DPoP` verification.
//!
//! Protocol gate: median < 150 µs. Absolute gate is informational on CI
//! without AX42-1; set `HELIX_BENCH_ENFORCE_GATES=1` for strict enforcement.

use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use criterion::{criterion_group, criterion_main, Criterion};
use helix_gateway::{
    expected_htu, verify_dpop_proof, verify_token, VerificationKeys, VerifyParams,
};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, OctetKeyPairParameters,
    OctetKeyPairType,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

const ISSUER: &str = "https://issuer.test/realms/helix";
const AUDIENCE: &str = "helix";
const GATE_US: u64 = 150;
const CI_SLACK: u64 = 40;
const GATE_ITERS: usize = 2_000;
const WARMUP_ITERS: usize = 200;

const ISSUER_PRIVATE_PEM: &str = include_str!("fixtures/issuer_ed25519_private.pem");
const ISSUER_PUBLIC_PEM: &str = include_str!("fixtures/issuer_ed25519_public.pem");
const AGENT_PRIV: &str = include_str!("fixtures/agent_dpop_ed25519_private.pem");
const AGENT_X: &str = include_str!("fixtures/agent_dpop_x.txt");
const AGENT_JKT: &str = include_str!("fixtures/agent_dpop_jkt.txt");

fn now_i64() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs(),
    )
    .expect("fits")
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
}

fn issuer_keys() -> VerificationKeys {
    let mut keys = VerificationKeys::new();
    keys.insert(
        "issuer-1",
        jsonwebtoken::DecodingKey::from_ed_pem(ISSUER_PUBLIC_PEM.as_bytes()).expect("pub"),
    );
    keys
}

fn params() -> VerifyParams {
    VerifyParams {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
    }
}

fn sign_access() -> String {
    let jkt = AGENT_JKT.trim().to_owned();
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
        &EncodingKey::from_ed_pem(ISSUER_PRIVATE_PEM.as_bytes()).expect("priv"),
    )
    .expect("sign")
}

fn sign_dpop(htu: &str) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(Jwk {
        common: CommonParameters::default(),
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: AGENT_X.trim().to_owned(),
        }),
    });
    let claims = DpopClaims {
        htm: "POST".to_owned(),
        htu: htu.to_owned(),
        iat: now_i64(),
        jti: "bench-jti-1".to_owned(),
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(AGENT_PRIV.as_bytes()).expect("priv"),
    )
    .expect("sign dpop")
}

struct AuthFixture {
    token: String,
    proof: String,
    htu: String,
    keys: VerificationKeys,
    params: VerifyParams,
}

fn fixture() -> AuthFixture {
    let htu = expected_htu("https://helix.example.com", "/");
    AuthFixture {
        token: sign_access(),
        proof: sign_dpop(&htu),
        htu,
        keys: issuer_keys(),
        params: params(),
    }
}

fn verify_both(f: &AuthFixture) {
    let _ = verify_token(&f.token, &f.keys, &f.params).expect("jwt");
    let _ = verify_dpop_proof(&f.proof, &f.htu, now_i64()).expect("dpop");
}

fn criterion_bench(c: &mut Criterion) {
    let f = fixture();
    verify_both(&f);
    c.bench_function("BENCH-2 Ed25519 JWT+DPoP verify", |b| {
        b.iter(|| {
            let _ = black_box(verify_token(
                black_box(&f.token),
                black_box(&f.keys),
                black_box(&f.params),
            ));
            let _ = black_box(verify_dpop_proof(
                black_box(&f.proof),
                black_box(&f.htu),
                black_box(now_i64()),
            ));
        });
    });
}

fn gate_check() {
    let f = fixture();
    for _ in 0..WARMUP_ITERS {
        verify_both(&f);
    }
    let mut samples = Vec::with_capacity(GATE_ITERS);
    for _ in 0..GATE_ITERS {
        let t0 = Instant::now();
        verify_both(&f);
        samples.push(t0.elapsed());
    }
    samples.sort_unstable();
    let median = samples[GATE_ITERS / 2];
    let median_us = u64::try_from(median.as_micros()).unwrap_or(u64::MAX);
    let enforce = std::env::var_os("HELIX_BENCH_ENFORCE_GATES").is_some();
    let limit = if enforce {
        GATE_US
    } else {
        GATE_US.saturating_mul(CI_SLACK)
    };
    eprintln!("BENCH-2 median={median_us} µs gate={GATE_US} µs limit={limit} µs enforce={enforce}");
    assert!(
        median_us <= limit,
        "BENCH-2 median {median_us} µs exceeds limit {limit} µs (protocol gate {GATE_US} µs)"
    );
}

fn benches(c: &mut Criterion) {
    criterion_bench(c);
    if std::env::var_os("HELIX_BENCH_SKIP_GATES").is_none() {
        gate_check();
    }
}

criterion_group!(benches_group, benches);
criterion_main!(benches_group);
