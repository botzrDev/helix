//! JWKS fetch + refresh (`gateway.jwks_url` / `gateway.jwks_refresh_s`).
//!
//! Cites: runbook §7. Keys live behind `ArcSwap`; a `JoinSet` task refreshes.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm};
use jsonwebtoken::DecodingKey;
use tokio::task::JoinSet;

use crate::auth::error::AuthError;
use crate::auth::verify::VerificationKeys;

/// Immutable JWKS snapshot used by [`crate::auth::verify_token`].
#[derive(Clone, Default)]
pub struct JwksSnapshot {
    /// `EdDSA` verification keys from the last successful fetch.
    pub keys: VerificationKeys,
}

/// Live JWKS held in `ArcSwap`, refreshed on an interval.
pub struct JwksCache {
    swap: Arc<ArcSwap<JwksSnapshot>>,
    url: String,
    refresh: Duration,
}

impl JwksCache {
    /// Construct with an initial empty snapshot (call [`Self::refresh_once`] or
    /// [`Self::from_keys`] before serving traffic).
    #[must_use]
    pub fn new(jwks_url: impl Into<String>, jwks_refresh_s: u64) -> Self {
        Self {
            swap: Arc::new(ArcSwap::from_pointee(JwksSnapshot::default())),
            url: jwks_url.into(),
            refresh: Duration::from_secs(jwks_refresh_s.max(1)),
        }
    }

    /// Build a cache preloaded with static keys (unit tests / offline).
    #[must_use]
    pub fn from_keys(keys: VerificationKeys) -> Self {
        let cache = Self::new("static://test", 3600);
        cache.swap.store(Arc::new(JwksSnapshot { keys }));
        cache
    }

    /// Current snapshot (cheap `Arc` clone of the guard contents).
    #[must_use]
    pub fn load(&self) -> Arc<JwksSnapshot> {
        self.swap.load_full()
    }

    /// Fetch JWKS once and publish.
    ///
    /// # Errors
    ///
    /// Network / parse failures. Existing snapshot is left intact on error.
    pub async fn refresh_once(&self, client: &reqwest::Client) -> Result<(), AuthError> {
        let set = fetch_jwks(client, &self.url).await?;
        let keys = jwks_to_verification_keys(&set)?;
        self.swap.store(Arc::new(JwksSnapshot { keys }));
        Ok(())
    }

    /// Spawn a refresh loop on `join` (ST-2 / no bare `tokio::spawn`).
    pub fn spawn_refresh(&self, join: &mut JoinSet<()>, client: reqwest::Client) {
        let swap = Arc::clone(&self.swap);
        let url = self.url.clone();
        let period = self.refresh;
        join.spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match fetch_jwks(&client, &url).await {
                    Ok(set) => match jwks_to_verification_keys(&set) {
                        Ok(keys) => {
                            swap.store(Arc::new(JwksSnapshot { keys }));
                        }
                        Err(e) => {
                            log::warn!(
                                target: "helix_gateway::auth",
                                "JWKS parse failed; keeping previous keys: {e}"
                            );
                        }
                    },
                    Err(e) => {
                        log::warn!(
                            target: "helix_gateway::auth",
                            "JWKS fetch failed; keeping previous keys: {e}"
                        );
                    }
                }
            }
        });
    }
}

async fn fetch_jwks(client: &reqwest::Client, url: &str) -> Result<JwkSet, AuthError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|_| AuthError::signature())?;
    if !resp.status().is_success() {
        return Err(AuthError::signature());
    }
    resp.json::<JwkSet>()
        .await
        .map_err(|_| AuthError::signature())
}

fn jwks_to_verification_keys(set: &JwkSet) -> Result<VerificationKeys, AuthError> {
    let mut keys = VerificationKeys::new();
    for jwk in &set.keys {
        let alg_ok = match jwk.common.key_algorithm {
            None | Some(KeyAlgorithm::EdDSA) => true,
            Some(_) => false,
        };
        if !alg_ok {
            continue;
        }
        match &jwk.algorithm {
            AlgorithmParameters::OctetKeyPair(params) if params.curve == EllipticCurve::Ed25519 => {
                let decoding = DecodingKey::from_jwk(jwk).map_err(|_| AuthError::signature())?;
                let kid = jwk.common.key_id.clone().unwrap_or_default();
                keys.insert(kid, decoding);
            }
            _ => {}
        }
    }
    if keys.is_empty() {
        return Err(AuthError::signature());
    }
    Ok(keys)
}
