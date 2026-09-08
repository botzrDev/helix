//! Axum 0.8 JSON-RPC server (HTTP/1.1 + HTTP/2).
//!
//! Cites: `interfaces/gateway-protocol.md` §§1,3,4,6; ADR-008 B.2; ST-2 via `JoinSet`
//! (not bare `tokio::spawn`; same pattern as `helix-audit::WitnessReceiveRuntime`).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use helix_audit::AuditHealth;
use helix_caps::RequestId;
use helix_policy::PolicyHolder;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::auth::{authenticate, JwksCache, VerificationKeys, VerifyParams, METRIC_AUTH_FAILED};
use crate::config::{DpopMode, GatewayConfig, HealthDetail};
use crate::envelope::{parse_envelope, EnvelopeOutcome, ParsedRequest};
use crate::health::HealthStatus;
use crate::request::{Request, RequestBuildError};
use crate::rpc::{self, RpcCode};

/// Shared gateway state.
#[derive(Clone)]
pub struct GatewayState {
    config: Arc<GatewayConfig>,
    policy: Arc<PolicyHolder>,
    artifacts_loaded: Arc<AtomicU64>,
    audit_health: Arc<std::sync::Mutex<AuditHealth>>,
    /// JWKS cache (static keys in tests; URL refresh in production).
    jwks: Arc<JwksCache>,
    /// JWT verification parameters (`iss` / `aud`).
    verify: Arc<VerifyParams>,
}

impl GatewayState {
    /// Construct state from config + live policy holder + JWKS cache.
    #[must_use]
    pub fn new(config: GatewayConfig, policy: PolicyHolder, jwks: JwksCache) -> Self {
        let verify = VerifyParams {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
        };
        Self {
            config: Arc::new(config),
            policy: Arc::new(policy),
            artifacts_loaded: Arc::new(AtomicU64::new(0)),
            audit_health: Arc::new(std::sync::Mutex::new(AuditHealth::Ok)),
            jwks: Arc::new(jwks),
            verify: Arc::new(verify),
        }
    }

    /// Convenience for tests: empty JWKS (auth will fail until keys are loaded).
    #[must_use]
    pub fn new_unenforced(config: GatewayConfig, policy: PolicyHolder) -> Self {
        Self::new(
            config,
            policy,
            JwksCache::from_keys(VerificationKeys::new()),
        )
    }

    /// Override `artifacts_loaded` (tests / later runtime wiring).
    pub fn set_artifacts_loaded(&self, n: u64) {
        self.artifacts_loaded.store(n, Ordering::Relaxed);
    }

    /// Override audit health (tests / later audit wiring).
    pub fn set_audit_health(&self, h: AuditHealth) {
        if let Ok(mut g) = self.audit_health.lock() {
            *g = h;
        }
    }

    /// Configured `gateway.health_detail`.
    #[must_use]
    pub fn health_detail(&self) -> HealthDetail {
        self.config.health_detail
    }

    /// `DPoP` mode.
    #[must_use]
    pub fn dpop_mode(&self) -> DpopMode {
        self.config.dpop
    }

    fn health_status(&self) -> HealthStatus {
        let audit = self.audit_health.lock().map(|g| *g).ok();
        HealthStatus {
            status: "ok",
            artifacts_loaded: self.artifacts_loaded.load(Ordering::Relaxed),
            policy_version: self.policy.policy_version(),
            audit,
        }
    }

    fn health_json(&self) -> Value {
        self.health_status().to_json(self.config.health_detail)
    }
}

/// Owns the accept loop via [`JoinSet`] (ST-2 / no bare `tokio::spawn`).
pub struct GatewayRuntime {
    join: JoinSet<()>,
    /// Bound local address (useful when listen port was 0).
    pub local_addr: SocketAddr,
    state: GatewayState,
}

impl GatewayRuntime {
    /// Bind `config.listen` and serve JSON-RPC.
    ///
    /// Starts a JWKS refresh task when `jwks_url` is an `http(s)` URL.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from bind.
    pub async fn start(
        config: GatewayConfig,
        policy: PolicyHolder,
    ) -> Result<Self, std::io::Error> {
        let jwks = JwksCache::new(config.jwks_url.clone(), config.jwks_refresh_s);
        let client = reqwest::Client::new();
        // Best-effort initial fetch; failures leave empty keys (auth fails closed).
        let _ = jwks.refresh_once(&client).await;

        let state = GatewayState::new(config.clone(), policy, jwks);
        let app = router(state.clone());
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let mut join = JoinSet::new();

        if config.jwks_url.starts_with("http://") || config.jwks_url.starts_with("https://") {
            state.jwks.spawn_refresh(&mut join, client);
        }

        join.spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Ok(Self {
            join,
            local_addr,
            state,
        })
    }

    /// Start with a pre-built state (integration tests with static JWKS).
    ///
    /// # Errors
    ///
    /// Returns I/O errors from bind.
    pub async fn start_with_state(
        config: GatewayConfig,
        state: GatewayState,
    ) -> Result<Self, std::io::Error> {
        let app = router(state.clone());
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let mut join = JoinSet::new();
        join.spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Ok(Self {
            join,
            local_addr,
            state,
        })
    }

    /// Shared state handle (tests).
    #[must_use]
    pub fn state(&self) -> &GatewayState {
        &self.state
    }

    /// Base URL for integration tests.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Abort the accept loop.
    pub async fn shutdown(mut self) {
        self.join.abort_all();
        while self.join.join_next().await.is_some() {}
    }
}

/// Build the axum router.
pub fn router(state: GatewayState) -> Router {
    Router::new()
        .route("/", post(rpc_handler))
        .route("/health", get(health_http))
        .with_state(state)
}

async fn health_http(State(state): State<GatewayState>) -> Json<Value> {
    Json(state.health_json())
}

async fn rpc_handler(
    State(state): State<GatewayState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    log_source(&state, addr.ip(), &headers);

    if !content_type_is_json(&headers) {
        let err = rpc::invalid_request(None, "content_type");
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(err)).into_response();
    }

    match parse_envelope(&body) {
        EnvelopeOutcome::Err(err) => (StatusCode::OK, Json(err)).into_response(),
        EnvelopeOutcome::Ok(parsed) => dispatch(&state, &headers, &parsed).into_response(),
    }
}

fn content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            let base = ct.split(';').next().unwrap_or(ct).trim();
            base.eq_ignore_ascii_case("application/json")
        })
}

/// Log peer / forwarded source. `X-Forwarded-*` never feeds `DPoP` (ADR-008 B.2).
fn log_source(state: &GatewayState, peer: IpAddr, headers: &HeaderMap) {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if state.config.peer_is_trusted(peer) {
        log::debug!(
            target: "helix_gateway::source",
            "peer={peer} trusted=true x_forwarded_for={forwarded:?} x_forwarded_proto={proto:?} x_forwarded_host={host:?}"
        );
    } else {
        log::debug!(
            target: "helix_gateway::source",
            "peer={peer} trusted=false (ignoring X-Forwarded-* for source)"
        );
    }
}

fn dispatch(state: &GatewayState, headers: &HeaderMap, parsed: &ParsedRequest) -> Json<Value> {
    match parsed.method.as_str() {
        "helix.health" => {
            let body = state.health_json();
            Json(rpc::success(parsed.id.as_ref(), &body))
        }
        "helix.invoke" => dispatch_invoke(state, headers, parsed),
        // `helix.describe` / `helix.nonce` land in later M5 tickets.
        _ => Json(rpc::error(
            parsed.id.as_ref(),
            RpcCode::MethodNotFound,
            None,
        )),
    }
}

fn authorization_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

fn dispatch_invoke(
    state: &GatewayState,
    headers: &HeaderMap,
    parsed: &ParsedRequest,
) -> Json<Value> {
    let keys = &state.jwks.load().keys;
    // Proof-key binding is HLX-34; Bearer / DPoP-scheme token only here.
    let identity = match authenticate(
        authorization_value(headers),
        state.config.dpop,
        keys,
        state.verify.as_ref(),
        None,
    ) {
        Ok(id) => id,
        Err(e) => {
            // Metric already incremented inside AuthError::new.
            let _ = METRIC_AUTH_FAILED;
            return Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::Unauthenticated,
                Some(json!({ "reason": e.reason.as_str() })),
            ));
        }
    };

    let snapshot = state.policy.guard();
    let request_id = next_request_id();
    match Request::from_invoke(parsed, identity, snapshot, request_id) {
        Ok(req) => {
            // Pipeline (policy → runtime) is HLX-35…HLX-36. Auth + seam are live.
            let data = json!({
                "reason": "not_wired",
                "request_id": request_id_string(req.id),
                "identity_bound": true,
            });
            let _ = (
                req.identity,
                req.tool,
                req.payload.len(),
                req.snapshot.version(),
            );
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::ProvisionFailed,
                Some(data),
            ))
        }
        Err(RequestBuildError::InvalidParams(reason)) => Json(rpc::error(
            parsed.id.as_ref(),
            RpcCode::InvalidParams,
            Some(json!({ "reason": reason })),
        )),
        Err(RequestBuildError::BadInput) => Json(rpc::error(
            parsed.id.as_ref(),
            RpcCode::InvalidParams,
            Some(json!({ "reason": "input_must_be_object", "path": "/input" })),
        )),
        Err(RequestBuildError::UnknownTool(e)) => {
            let data = match &e {
                helix_policy::AliasDigestError::UnknownAlias { alias }
                | helix_policy::AliasDigestError::Disagreement { alias, .. } => {
                    json!({ "tool": alias })
                }
            };
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::UnknownTool,
                Some(data),
            ))
        }
    }
}

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> RequestId {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let n = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    RequestId::from_u128((u128::from(millis) << 80) | u128::from(n))
}

fn request_id_string(id: RequestId) -> String {
    serde_json::to_value(id)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{}", id.as_u128()))
}
