//! Axum 0.8 JSON-RPC server (HTTP/1.1 + HTTP/2).
//!
//! Cites: `interfaces/gateway-protocol.md` §§1,3,4,6; ADR-008 B.2; ADR-009 C.1;
//! ST-2 via `JoinSet` (not bare `tokio::spawn`).

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use helix_audit::AuditHealth;
use helix_caps::RequestId;
use helix_policy::PolicyHolder;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use crate::auth::dpop::{check_dpop, DpopCheck, DpopRuntime, NonceKeys};
use crate::auth::{
    bind_identity, extract_access_token, verify_token, AuthError, JwksCache, VerificationKeys,
    VerifyParams, METRIC_AUTH_FAILED,
};
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
    /// `DPoP` runtime (nonces + `jti`); `None` when mode is `off` and no keys loaded.
    dpop: Option<Arc<DpopRuntime>>,
}

impl GatewayState {
    /// Construct state from config + live policy holder + JWKS cache + optional `DPoP`.
    #[must_use]
    pub fn new(
        config: GatewayConfig,
        policy: PolicyHolder,
        jwks: JwksCache,
        dpop: Option<DpopRuntime>,
    ) -> Self {
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
            dpop: dpop.map(Arc::new),
        }
    }

    /// Convenience for tests: empty JWKS, no `DPoP` runtime.
    #[must_use]
    pub fn new_unenforced(config: GatewayConfig, policy: PolicyHolder) -> Self {
        Self::new(
            config,
            policy,
            JwksCache::from_keys(VerificationKeys::new()),
            None,
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

    /// `DPoP` runtime (tests).
    #[must_use]
    pub fn dpop_runtime(&self) -> Option<&DpopRuntime> {
        self.dpop.as_deref()
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
    /// Loads `nonce_key` when `dpop != off` or a path is configured.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from bind, or nonce-key load failures as `Other`.
    pub async fn start(
        config: GatewayConfig,
        policy: PolicyHolder,
    ) -> Result<Self, std::io::Error> {
        let jwks = JwksCache::new(config.jwks_url.clone(), config.jwks_refresh_s);
        let client = reqwest::Client::new();
        let _ = jwks.refresh_once(&client).await;

        let dpop = load_dpop_runtime(&config)?;
        let state = GatewayState::new(config.clone(), policy, jwks, dpop);
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

    /// Start with a pre-built state (integration tests with static JWKS / `DPoP`).
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

fn load_dpop_runtime(config: &GatewayConfig) -> Result<Option<DpopRuntime>, std::io::Error> {
    if config.dpop == DpopMode::Off && config.nonce_key.is_none() {
        return Ok(None);
    }
    let path = config.nonce_key.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "gateway.nonce_key required when dpop != off",
        )
    })?;
    let current = crate::auth::load_nonce_key_file(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let next = match &config.nonce_key_next {
        Some(p) => Some(
            crate::auth::load_nonce_key_file(p)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        ),
        None => None,
    };
    let keys = NonceKeys::new(current, next)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad nonce keys"))?;
    Ok(Some(DpopRuntime::new(
        config.dpop,
        config.external_url.clone(),
        keys,
        config.dpop_nonce_ttl_s,
        config.dpop_jti_window_s,
        config.dpop_jti_max_entries,
    )))
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
        EnvelopeOutcome::Ok(parsed) => dispatch(&state, &headers, &parsed),
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

fn dispatch(state: &GatewayState, headers: &HeaderMap, parsed: &ParsedRequest) -> Response {
    match parsed.method.as_str() {
        "helix.health" => {
            let body = state.health_json();
            (
                StatusCode::OK,
                Json(rpc::success(parsed.id.as_ref(), &body)),
            )
                .into_response()
        }
        "helix.nonce" => dispatch_nonce(state, parsed),
        "helix.invoke" => dispatch_invoke(state, headers, parsed),
        // `helix.describe` lands in a later M5 ticket.
        _ => (
            StatusCode::OK,
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::MethodNotFound,
                None,
            )),
        )
            .into_response(),
    }
}

fn authorization_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

fn dpop_header_value(headers: &HeaderMap) -> Option<&str> {
    headers.get("dpop").and_then(|v| v.to_str().ok())
}

fn with_dpop_nonce(mut response: Response, nonce: Option<&str>) -> Response {
    if let Some(n) = nonce {
        if let Ok(v) = HeaderValue::from_str(n) {
            response.headers_mut().insert("DPoP-Nonce", v);
        }
    }
    response
}

fn unauth_json(id: Option<&crate::rpc::RpcId>, reason: &str) -> Value {
    rpc::error(
        id,
        RpcCode::Unauthenticated,
        Some(json!({ "reason": reason })),
    )
}

fn dispatch_nonce(state: &GatewayState, parsed: &ParsedRequest) -> Response {
    let Some(dpop) = state.dpop.as_ref() else {
        return (
            StatusCode::OK,
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::InvalidParams,
                Some(json!({ "reason": "dpop_off", "path": "/jkt" })),
            )),
        )
            .into_response();
    };

    let jkt = parsed
        .params
        .get("jkt")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let Some(jkt) = jkt else {
        return (
            StatusCode::OK,
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::InvalidParams,
                Some(json!({ "reason": "missing_jkt", "path": "/jkt" })),
            )),
        )
            .into_response();
    };

    let nonce = dpop.issue_nonce_now(jkt);
    let body = rpc::success(parsed.id.as_ref(), &json!({ "nonce": nonce }));
    with_dpop_nonce((StatusCode::OK, Json(body)).into_response(), Some(&nonce))
}

#[allow(clippy::too_many_lines)]
fn dispatch_invoke(state: &GatewayState, headers: &HeaderMap, parsed: &ParsedRequest) -> Response {
    let keys = &state.jwks.load().keys;
    let mode = state.config.dpop;
    let _ = METRIC_AUTH_FAILED;

    // Extract scheme first so we know whether a proof is required.
    let extracted = match extract_access_token(authorization_value(headers), mode) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::OK,
                Json(unauth_json(parsed.id.as_ref(), e.reason.as_str())),
            )
                .into_response();
        }
    };

    let need_proof = match mode {
        DpopMode::Required => true,
        DpopMode::Optional => extracted.dpop_scheme,
        DpopMode::Off => false,
    };

    let (proof_key, dpop_nonce_hdr) = if need_proof {
        let Some(dpop) = state.dpop.as_ref() else {
            let err = AuthError::signature();
            return (
                StatusCode::OK,
                Json(unauth_json(parsed.id.as_ref(), err.reason.as_str())),
            )
                .into_response();
        };
        match check_dpop(dpop_header_value(headers), dpop, "/", None) {
            Ok(DpopCheck::Ok(proof)) => {
                let nonce = dpop.issue_nonce_now(&proof.jkt);
                (Some(proof.proof_key), Some(nonce))
            }
            Ok(DpopCheck::NonceChallenge { nonce, .. }) => {
                let body = unauth_json(parsed.id.as_ref(), "nonce");
                // Metric: reason nonce
                let _ = AuthError::nonce();
                return with_dpop_nonce(
                    (StatusCode::UNAUTHORIZED, Json(body)).into_response(),
                    Some(&nonce),
                );
            }
            Err(e) => {
                return (
                    StatusCode::OK,
                    Json(unauth_json(parsed.id.as_ref(), e.reason.as_str())),
                )
                    .into_response();
            }
        }
    } else {
        (None, None)
    };

    let identity = match verify_token(&extracted.token, keys, state.verify.as_ref())
        .and_then(|v| bind_identity(&v.claims, proof_key.as_ref()))
    {
        Ok(id) => id,
        Err(e) => {
            return with_dpop_nonce(
                (
                    StatusCode::OK,
                    Json(unauth_json(parsed.id.as_ref(), e.reason.as_str())),
                )
                    .into_response(),
                dpop_nonce_hdr.as_deref(),
            );
        }
    };

    let snapshot = state.policy.guard();
    let request_id = next_request_id();
    let response = match Request::from_invoke(parsed, identity, snapshot, request_id) {
        Ok(req) => {
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
            (
                StatusCode::OK,
                Json(rpc::error(
                    parsed.id.as_ref(),
                    RpcCode::ProvisionFailed,
                    Some(data),
                )),
            )
                .into_response()
        }
        Err(RequestBuildError::InvalidParams(reason)) => (
            StatusCode::OK,
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::InvalidParams,
                Some(json!({ "reason": reason })),
            )),
        )
            .into_response(),
        Err(RequestBuildError::BadInput) => (
            StatusCode::OK,
            Json(rpc::error(
                parsed.id.as_ref(),
                RpcCode::InvalidParams,
                Some(json!({ "reason": "input_must_be_object", "path": "/input" })),
            )),
        )
            .into_response(),
        Err(RequestBuildError::UnknownTool(e)) => {
            let data = match &e {
                helix_policy::AliasDigestError::UnknownAlias { alias }
                | helix_policy::AliasDigestError::Disagreement { alias, .. } => {
                    json!({ "tool": alias })
                }
            };
            (
                StatusCode::OK,
                Json(rpc::error(
                    parsed.id.as_ref(),
                    RpcCode::UnknownTool,
                    Some(data),
                )),
            )
                .into_response()
        }
    };

    with_dpop_nonce(response, dpop_nonce_hdr.as_deref())
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
