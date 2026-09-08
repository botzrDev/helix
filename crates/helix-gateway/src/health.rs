//! `helix.health` result body (unauthenticated).
//!
//! Cites: `interfaces/gateway-protocol.md` §3; ADR-008 F.4; runbook §2.

use helix_audit::AuditHealth;
use serde_json::{json, Value};

use crate::config::HealthDetail;

/// Inputs for building a health result (optional fields for `full`).
#[derive(Clone, Debug, Default)]
pub struct HealthStatus {
    /// Overall status string (`ok` for a live gateway process).
    pub status: &'static str,
    /// Number of compiled artifacts currently loaded (full detail).
    pub artifacts_loaded: u64,
    /// Live `policy_version` (full detail).
    pub policy_version: u64,
    /// Audit writer health (full detail). Absent → reported as `"ok"`.
    pub audit: Option<AuditHealth>,
}

impl HealthStatus {
    /// Render according to `gateway.health_detail`.
    #[must_use]
    pub fn to_json(&self, detail: HealthDetail) -> Value {
        match detail {
            HealthDetail::Minimal => json!({ "status": self.status }),
            HealthDetail::Full => json!({
                "status": self.status,
                "artifacts_loaded": self.artifacts_loaded,
                "policy_version": self.policy_version.to_string(),
                "audit": self.audit.unwrap_or(AuditHealth::Ok).as_str(),
            }),
        }
    }
}
