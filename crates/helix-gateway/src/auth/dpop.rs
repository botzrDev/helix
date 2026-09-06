//! `DPoP` (RFC 9449): HMAC nonces, proof verification, bounded sharded `jti` cache.
//!
//! Cites: ADR-008 B.2; ADR-009 C.1; `interfaces/gateway-protocol.md` §§1,3;
//! runbook §§2,7; security-checklist A3a, A3b, C1; test-plan GW-3,4,9,12,14.

#![allow(clippy::cast_precision_loss)] // metrics gauges are f64

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use crate::auth::error::AuthError;
use crate::auth::thumbprint::{derive_identity, identity_to_jkt, Ed25519PublicJwk};

/// Prometheus gauge: current `jti` cache occupancy.
pub const METRIC_JTI_ENTRIES: &str = "helix_dpop_jti_entries";
/// Prometheus counter: proofs refused because a shard was full.
pub const METRIC_JTI_FULL: &str = "helix_dpop_jti_full_total";

type HmacSha256 = Hmac<Sha256>;

const SHARD_COUNT: usize = 64;
/// `iat` skew accepted for `DPoP` proofs (±60 s).
pub const DPOP_IAT_SKEW_S: i64 = 60;

/// Material for stateless HMAC nonces (`nonce_key` / optional `nonce_key_next`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceKeys {
    /// Active key (32 bytes from a `0600` file).
    pub current: Vec<u8>,
    /// Rotation overlap key (runbook §7).
    pub next: Option<Vec<u8>>,
}

impl NonceKeys {
    /// Construct from raw key bytes.
    ///
    /// # Errors
    ///
    /// Empty `current` is rejected.
    pub fn new(current: Vec<u8>, next: Option<Vec<u8>>) -> Result<Self, AuthError> {
        if current.is_empty() {
            return Err(AuthError::signature());
        }
        if let Some(ref n) = next {
            if n.is_empty() {
                return Err(AuthError::signature());
            }
        }
        Ok(Self { current, next })
    }
}

/// Load a nonce key file: must be non-empty; mode must be `0600` on Unix.
///
/// # Errors
///
/// I/O or permission failures map to a string for the caller to surface.
pub fn load_nonce_key_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("nonce_key metadata: {e}"))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "nonce_key {}: mode {:04o} (require 0600)",
            path.display(),
            mode
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("nonce_key read: {e}"))?;
    if bytes.is_empty() {
        return Err(format!("nonce_key {}: empty", path.display()));
    }
    Ok(bytes)
}

/// Compute expected `htu` from `gateway.external_url` + request path (never headers).
#[must_use]
pub fn expected_htu(external_url: &str, path: &str) -> String {
    let base = external_url.trim_end_matches('/');
    let path = if path.is_empty() {
        "/"
    } else if path.starts_with('/') {
        path
    } else {
        // Defensive: treat as absolute path segment.
        return format!("{base}/{path}");
    };
    format!("{base}{path}")
}

/// Epoch bucket = `floor(now_secs / ttl_s)`.
#[must_use]
pub fn epoch_bucket(now_secs: u64, ttl_s: u64) -> u64 {
    let ttl = ttl_s.max(1);
    now_secs / ttl
}

fn hmac_nonce(key: &[u8], bucket: u64, jkt: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
    mac.update(&bucket.to_be_bytes());
    mac.update(jkt.as_bytes());
    let tag = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag)
}

/// Issue the current-bucket nonce for `jkt`.
#[must_use]
pub fn issue_nonce(keys: &NonceKeys, jkt: &str, now_secs: u64, ttl_s: u64) -> String {
    let bucket = epoch_bucket(now_secs, ttl_s);
    hmac_nonce(&keys.current, bucket, jkt)
}

fn nonce_candidates(keys: &NonceKeys, jkt: &str, now_secs: u64, ttl_s: u64) -> Vec<String> {
    let bucket = epoch_bucket(now_secs, ttl_s);
    let prev = bucket.saturating_sub(1);
    let mut out = Vec::with_capacity(4);
    for b in [bucket, prev] {
        out.push(hmac_nonce(&keys.current, b, jkt));
        if let Some(ref next) = keys.next {
            out.push(hmac_nonce(next, b, jkt));
        }
    }
    out
}

/// True if `nonce` matches current or previous bucket under `current` or `next` key.
#[must_use]
pub fn nonce_acceptable(
    keys: &NonceKeys,
    jkt: &str,
    nonce: &str,
    now_secs: u64,
    ttl_s: u64,
) -> bool {
    nonce_candidates(keys, jkt, now_secs, ttl_s)
        .iter()
        .any(|n| n == nonce)
}

/// Verified `DPoP` proof (crypto + structural claims; nonce/`jti` checked by caller).
#[derive(Clone, Debug)]
pub struct VerifiedDpopProof {
    /// Proof key (for `bind_identity`).
    pub proof_key: Ed25519PublicJwk,
    /// RFC 7638 thumbprint of the proof key (base64url).
    pub jkt: String,
    /// Proof `jti`.
    pub jti: String,
    /// Proof `nonce` claim (may be empty → challenge).
    pub nonce: Option<String>,
    /// Proof issued-at (`iat`).
    pub iat: i64,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    htm: String,
    htu: String,
    iat: i64,
    jti: String,
    #[serde(default)]
    nonce: Option<String>,
}

/// Parse + verify a `DPoP` proof JWT (`alg`/`htm`/`htu`/`iat`/`jti`). Does **not** check nonce or `jti` cache.
///
/// Safe for fuzzing: returns [`AuthError`] instead of panicking on malformed input.
///
/// # Errors
///
/// Closed-set [`AuthError`] (`signature` for crypto/structure; `binding` unused here).
pub fn verify_dpop_proof(
    proof: &str,
    expected_htu: &str,
    now_secs: i64,
) -> Result<VerifiedDpopProof, AuthError> {
    reject_non_eddsa_dpop_header(proof)?;

    let header = jsonwebtoken::decode_header(proof).map_err(|_| AuthError::signature())?;
    if header.alg != Algorithm::EdDSA {
        return Err(AuthError::signature());
    }

    let jwk_val = dpop_jwk_from_header(proof)?;
    let (proof_key, decoding_key) = jwk_to_ed25519(&jwk_val)?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation.set_required_spec_claims(&["iat"]);

    let data = decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map_err(|_| AuthError::signature())?;

    if !data.claims.htm.eq_ignore_ascii_case("POST") {
        return Err(AuthError::signature());
    }
    if data.claims.htu != expected_htu {
        return Err(AuthError::signature());
    }
    let skew = (now_secs - data.claims.iat).abs();
    if skew > DPOP_IAT_SKEW_S {
        return Err(AuthError::signature());
    }
    if data.claims.jti.is_empty() {
        return Err(AuthError::signature());
    }

    let jkt = identity_to_jkt(derive_identity(&proof_key));
    let nonce = data.claims.nonce.filter(|n| !n.is_empty());

    Ok(VerifiedDpopProof {
        proof_key,
        jkt,
        jti: data.claims.jti,
        nonce,
        iat: data.claims.iat,
    })
}

/// Fuzz entry: verify-shaped parse that never panics.
pub fn fuzz_dpop_proof(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = verify_dpop_proof(s, "https://helix.example.com/", 1_700_000_000);
    let _ = reject_non_eddsa_dpop_header(s);
}

fn reject_non_eddsa_dpop_header(token: &str) -> Result<(), AuthError> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or_else(AuthError::signature)?;
    let _payload = parts.next().ok_or_else(AuthError::signature)?;
    let _sig = parts.next().ok_or_else(AuthError::signature)?;
    if parts.next().is_some() {
        return Err(AuthError::signature());
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let padded = base64::engine::general_purpose::URL_SAFE;
    let bytes = engine
        .decode(header_b64)
        .or_else(|_| padded.decode(header_b64))
        .map_err(|_| AuthError::signature())?;
    let header: Value = serde_json::from_slice(&bytes).map_err(|_| AuthError::signature())?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(AuthError::signature)?;
    if alg != "EdDSA" {
        return Err(AuthError::signature());
    }
    // typ is recommended; if present must be dpop+jwt
    if let Some(typ) = header.get("typ").and_then(Value::as_str) {
        if !typ.eq_ignore_ascii_case("dpop+jwt") {
            return Err(AuthError::signature());
        }
    }
    Ok(())
}

fn dpop_jwk_from_header(token: &str) -> Result<Value, AuthError> {
    let header_b64 = token.split('.').next().ok_or_else(AuthError::signature)?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let padded = base64::engine::general_purpose::URL_SAFE;
    let bytes = engine
        .decode(header_b64)
        .or_else(|_| padded.decode(header_b64))
        .map_err(|_| AuthError::signature())?;
    let header: Value = serde_json::from_slice(&bytes).map_err(|_| AuthError::signature())?;
    header.get("jwk").cloned().ok_or_else(AuthError::signature)
}

fn jwk_to_ed25519(jwk: &Value) -> Result<(Ed25519PublicJwk, DecodingKey), AuthError> {
    let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or("");
    let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or("");
    if kty != "OKP" || crv != "Ed25519" {
        return Err(AuthError::signature());
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(AuthError::signature)?;
    let proof_key = Ed25519PublicJwk::from_x(x);
    let decoding_key = DecodingKey::from_ed_components(x).map_err(|_| AuthError::signature())?;
    Ok((proof_key, decoding_key))
}

// ----- jti cache -----

#[derive(Debug)]
struct Shard {
    /// Insertion-ordered `(jti, inserted_at)`.
    order: VecDeque<(String, SystemTime)>,
    index: HashMap<String, SystemTime>,
}

impl Shard {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            index: HashMap::new(),
        }
    }
}

/// Bounded, 64-way sharded, insertion-ordered `jti` replay cache.
pub struct JtiCache {
    shards: Vec<Mutex<Shard>>,
    capacity_per_shard: usize,
    window: Duration,
    entries: AtomicU64,
    full_total: AtomicU64,
}

impl JtiCache {
    /// Build a cache with total capacity `max_entries` (split across 64 shards).
    #[must_use]
    pub fn new(max_entries: usize, window_s: u64) -> Self {
        let per = (max_entries / SHARD_COUNT).max(1);
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(Shard::new()));
        }
        Self {
            shards,
            capacity_per_shard: per,
            window: Duration::from_secs(window_s.max(1)),
            entries: AtomicU64::new(0),
            full_total: AtomicU64::new(0),
        }
    }

    /// Shard index for `jti` (tests / diagnostics).
    #[must_use]
    pub fn shard_index(jti: &str) -> usize {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in jti.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        usize::try_from(h).unwrap_or(0) % SHARD_COUNT
    }

    /// Current occupancy (for tests / gauge).
    #[must_use]
    pub fn entries(&self) -> u64 {
        self.entries.load(Ordering::Relaxed)
    }

    /// Times a shard refused insert because it was full.
    #[must_use]
    pub fn full_total(&self) -> u64 {
        self.full_total.load(Ordering::Relaxed)
    }

    fn publish_gauge(&self) {
        metrics::gauge!(METRIC_JTI_ENTRIES).set(self.entries.load(Ordering::Relaxed) as f64);
    }

    fn evict_expired(shard: &mut Shard, window: Duration, now: SystemTime, entries: &AtomicU64) {
        while let Some((_, at)) = shard.order.front() {
            let age = now.duration_since(*at).unwrap_or_default();
            if age <= window {
                break;
            }
            if let Some((jti, _)) = shard.order.pop_front() {
                shard.index.remove(&jti);
                entries.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Insert `jti` at `now`. Duplicate inside the window → `replay`. Full → `replay` + counter.
    ///
    /// # Errors
    ///
    /// [`AuthError`] with reason `replay`.
    pub fn insert(&self, jti: &str, now: SystemTime) -> Result<(), AuthError> {
        let idx = Self::shard_index(jti);
        let mut shard = self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::evict_expired(&mut shard, self.window, now, &self.entries);

        if shard.index.contains_key(jti) {
            return Err(AuthError::replay());
        }

        if shard.order.len() >= self.capacity_per_shard {
            // Try one more eviction pass (nothing older than window left).
            Self::evict_expired(&mut shard, self.window, now, &self.entries);
            if shard.order.len() >= self.capacity_per_shard {
                self.full_total.fetch_add(1, Ordering::Relaxed);
                metrics::counter!(METRIC_JTI_FULL).increment(1);
                self.publish_gauge();
                return Err(AuthError::replay());
            }
        }

        shard.order.push_back((jti.to_owned(), now));
        shard.index.insert(jti.to_owned(), now);
        self.entries.fetch_add(1, Ordering::Relaxed);
        self.publish_gauge();
        Ok(())
    }

    /// Test helper: advance eviction as of `now` across all shards.
    pub fn evict_all_expired(&self, now: SystemTime) {
        for shard in &self.shards {
            let mut g = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Self::evict_expired(&mut g, self.window, now, &self.entries);
        }
        self.publish_gauge();
    }
}

/// Shared `DPoP` runtime knobs held on [`crate::server::GatewayState`].
#[derive(Clone)]
pub struct DpopRuntime {
    /// Enforcement mode.
    pub mode: crate::config::DpopMode,
    /// Public URL base for `htu`.
    pub external_url: String,
    /// HMAC keys.
    pub keys: Arc<NonceKeys>,
    /// Nonce TTL seconds.
    pub nonce_ttl_s: u64,
    /// Replay cache.
    pub jti: Arc<JtiCache>,
}

impl DpopRuntime {
    /// Build from config pieces.
    #[must_use]
    pub fn new(
        mode: crate::config::DpopMode,
        external_url: String,
        keys: NonceKeys,
        nonce_ttl_s: u64,
        jti_window_s: u64,
        jti_max_entries: usize,
    ) -> Self {
        Self {
            mode,
            external_url,
            keys: Arc::new(keys),
            nonce_ttl_s: nonce_ttl_s.max(1),
            jti: Arc::new(JtiCache::new(jti_max_entries, jti_window_s)),
        }
    }

    /// Issue current nonce for `jkt`.
    #[must_use]
    pub fn issue_nonce_now(&self, jkt: &str) -> String {
        let now = now_secs();
        issue_nonce(&self.keys, jkt, now, self.nonce_ttl_s)
    }

    /// Expected `htu` for `path`.
    #[must_use]
    pub fn htu_for_path(&self, path: &str) -> String {
        expected_htu(&self.external_url, path)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Outcome of `DPoP` proof + nonce + `jti` checks.
#[derive(Debug)]
pub enum DpopCheck {
    /// Proof accepted; caller must `bind_identity` with `proof_key`.
    Ok(VerifiedDpopProof),
    /// Missing/stale nonce → HTTP 401 challenge.
    NonceChallenge {
        /// Fresh nonce for the proof's `jkt`.
        nonce: String,
        /// Proof key (binding still applies on retry).
        proof: VerifiedDpopProof,
    },
}

/// Verify `DPoP` header when mode requires/optional-with-scheme.
///
/// # Errors
///
/// [`AuthError`] for signature / replay failures.
pub fn check_dpop(
    proof_header: Option<&str>,
    runtime: &DpopRuntime,
    request_path: &str,
    now: Option<(i64, u64, SystemTime)>,
) -> Result<DpopCheck, AuthError> {
    let proof = proof_header.ok_or_else(AuthError::signature)?;
    let (now_i, now_u, now_st) = now.unwrap_or_else(|| {
        let u = now_secs();
        let i = i64::try_from(u).unwrap_or(0);
        (i, u, SystemTime::now())
    });
    let htu = runtime.htu_for_path(request_path);
    let verified = verify_dpop_proof(proof, &htu, now_i)?;

    match &verified.nonce {
        None => {
            let nonce = issue_nonce(&runtime.keys, &verified.jkt, now_u, runtime.nonce_ttl_s);
            Ok(DpopCheck::NonceChallenge {
                nonce,
                proof: verified,
            })
        }
        Some(n)
            if !nonce_acceptable(&runtime.keys, &verified.jkt, n, now_u, runtime.nonce_ttl_s) =>
        {
            let nonce = issue_nonce(&runtime.keys, &verified.jkt, now_u, runtime.nonce_ttl_s);
            Ok(DpopCheck::NonceChallenge {
                nonce,
                proof: verified,
            })
        }
        Some(_) => {
            runtime.jti.insert(&verified.jti, now_st)?;
            Ok(DpopCheck::Ok(verified))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn htu_strips_trailing_slash_on_base() {
        assert_eq!(
            expected_htu("https://helix.example.com/", "/"),
            "https://helix.example.com/"
        );
        assert_eq!(
            expected_htu("https://helix.example.com", "/rpc"),
            "https://helix.example.com/rpc"
        );
    }

    #[test]
    fn nonce_current_and_prev_accepted() {
        let keys = NonceKeys::new(vec![7u8; 32], None).unwrap();
        let jkt = "abc";
        let ttl = 60u64;
        let now = 1_700_000_000u64;
        let n = issue_nonce(&keys, jkt, now, ttl);
        assert!(nonce_acceptable(&keys, jkt, &n, now, ttl));
        // previous bucket nonce still ok
        let prev_bucket = epoch_bucket(now, ttl) - 1;
        let prev = hmac_nonce(&keys.current, prev_bucket, jkt);
        assert!(nonce_acceptable(&keys, jkt, &prev, now, ttl));
        // three buckets ago refused
        let old = hmac_nonce(&keys.current, prev_bucket - 1, jkt);
        assert!(!nonce_acceptable(&keys, jkt, &old, now, ttl));
    }
}
