//! Gateway configuration (`[gateway]` in `helix.toml`).
//!
//! Cites: runbook §2, ADR-008 B.2 / F.4, `interfaces/gateway-protocol.md` §1.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// How much detail `helix.health` (and `GET /health`) returns (ADR-008 F.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthDetail {
    /// `{ "status": "ok" }` only.
    #[default]
    Minimal,
    /// Includes `artifacts_loaded`, `policy_version`, and `audit`.
    Full,
}

impl FromStr for HealthDetail {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minimal" => Ok(Self::Minimal),
            "full" => Ok(Self::Full),
            other => Err(ConfigError::BadHealthDetail(other.to_owned())),
        }
    }
}

/// `gateway.dpop`: `required` | `optional` | `off`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpopMode {
    /// `Authorization: DPoP <token>` + `DPoP` proof required.
    #[default]
    Required,
    /// Accept `DPoP` or Bearer.
    Optional,
    /// `Authorization: Bearer <token>` only.
    Off,
}

impl FromStr for DpopMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "required" => Ok(Self::Required),
            "optional" => Ok(Self::Optional),
            "off" => Ok(Self::Off),
            other => Err(ConfigError::BadDpopMode(other.to_owned())),
        }
    }
}

/// An IPv4 or IPv6 CIDR used only for source-address / logging (never `DPoP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedProxy {
    addr: IpAddr,
    prefix: u8,
}

impl TrustedProxy {
    /// Parse `addr/prefix` (e.g. `10.0.0.0/8`, `2001:db8::/32`).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BadCidr`] when the string is not a valid CIDR.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let (addr_s, pref_s) = s
            .split_once('/')
            .ok_or_else(|| ConfigError::BadCidr(s.to_owned()))?;
        let addr: IpAddr = addr_s
            .parse()
            .map_err(|_| ConfigError::BadCidr(s.to_owned()))?;
        let prefix: u8 = pref_s
            .parse()
            .map_err(|_| ConfigError::BadCidr(s.to_owned()))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(ConfigError::BadCidr(s.to_owned()));
        }
        Ok(Self { addr, prefix })
    }

    /// True if `ip` falls inside this CIDR.
    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                let shift = 32u32.saturating_sub(u32::from(self.prefix));
                let mask = if shift >= 32 { 0 } else { u32::MAX << shift };
                (u32::from(net) & mask) == (u32::from(host) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                let shift = 128u32.saturating_sub(u32::from(self.prefix));
                let mask = if shift >= 128 {
                    0u128
                } else {
                    u128::MAX << shift
                };
                (u128::from(net) & mask) == (u128::from(host) & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for TrustedProxy {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Default total `jti` cache entries (runbook §2).
pub const DEFAULT_DPOP_JTI_MAX_ENTRIES: usize = 1_048_576;
/// Default nonce / jti window seconds.
pub const DEFAULT_DPOP_TTL_S: u64 = 60;

/// `[gateway]` section used by the axum server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayConfig {
    /// Bind address (`gateway.listen`).
    pub listen: SocketAddr,
    /// CIDRs trusted for `X-Forwarded-*` logging only (ADR-008 B.2).
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Public URL base for `DPoP` `htu` (required).
    pub external_url: String,
    /// `helix.health` detail level.
    pub health_detail: HealthDetail,
    /// `DPoP` enforcement mode.
    pub dpop: DpopMode,
    /// Token issuer URL (Keycloak placeholder until the box exists).
    pub issuer: String,
    /// JWKS URL refreshed every [`Self::jwks_refresh_s`].
    pub jwks_url: String,
    /// JWKS refresh interval in seconds (runbook §7).
    pub jwks_refresh_s: u64,
    /// Expected JWT `aud`.
    pub audience: String,
    /// Path to 32-byte `nonce_key` file (mode 0600).
    pub nonce_key: Option<PathBuf>,
    /// Optional rotation key path (`nonce_key_next`).
    pub nonce_key_next: Option<PathBuf>,
    /// HMAC nonce bucket TTL seconds.
    pub dpop_nonce_ttl_s: u64,
    /// `jti` replay window seconds.
    pub dpop_jti_window_s: u64,
    /// Total `jti` cache capacity (split across 64 shards).
    pub dpop_jti_max_entries: usize,
    /// When true, `-32002` includes requested/available caps (ADR-008 F.4).
    pub verbose_denials: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            trusted_proxies: Vec::new(),
            external_url: "http://127.0.0.1:8080".to_owned(),
            health_detail: HealthDetail::Minimal,
            dpop: DpopMode::Off,
            issuer: "https://<host>/realms/helix".to_owned(),
            jwks_url: "https://<host>/realms/helix/protocol/openid-connect/certs".to_owned(),
            jwks_refresh_s: 300,
            audience: "helix".to_owned(),
            nonce_key: None,
            nonce_key_next: None,
            dpop_nonce_ttl_s: DEFAULT_DPOP_TTL_S,
            dpop_jti_window_s: DEFAULT_DPOP_TTL_S,
            dpop_jti_max_entries: DEFAULT_DPOP_JTI_MAX_ENTRIES,
            verbose_denials: false,
        }
    }
}

impl GatewayConfig {
    /// True if `peer` is inside any configured trusted-proxy CIDR.
    #[must_use]
    pub fn peer_is_trusted(&self, peer: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|c| c.contains(peer))
    }

    /// Log `gateway.verbose_denials.enabled` at warn when the flag is set.
    pub fn warn_verbose_denials(&self) {
        if self.verbose_denials {
            log::warn!(target: "helix_gateway", "gateway.verbose_denials.enabled");
        }
    }
}

/// Configuration parse failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// `gateway.health_detail` was not `minimal` or `full`.
    #[error("gateway.health_detail must be minimal|full, got {0}")]
    BadHealthDetail(String),
    /// `gateway.dpop` was not `required|optional|off`.
    #[error("gateway.dpop must be required|optional|off, got {0}")]
    BadDpopMode(String),
    /// A `trusted_proxies` entry was not a CIDR.
    #[error("gateway.trusted_proxies entry is not a CIDR: {0}")]
    BadCidr(String),
    /// `gateway.listen` was not a socket address.
    #[error("gateway.listen is not a socket address: {0}")]
    BadListen(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_v4_contains() {
        let c = TrustedProxy::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(IpAddr::from([10, 1, 2, 3])));
        assert!(!c.contains(IpAddr::from([11, 0, 0, 1])));
    }

    #[test]
    fn health_detail_parse() {
        assert_eq!("full".parse::<HealthDetail>().unwrap(), HealthDetail::Full);
        assert!("nope".parse::<HealthDetail>().is_err());
    }

    #[test]
    fn dpop_mode_parse() {
        assert_eq!("off".parse::<DpopMode>().unwrap(), DpopMode::Off);
        assert_eq!("required".parse::<DpopMode>().unwrap(), DpopMode::Required);
        assert!("maybe".parse::<DpopMode>().is_err());
    }
}
