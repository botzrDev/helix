//! File-backed `witness-receive` server (ADR-009 D.2 / AUD-10).
//!
//! PUT/GET/list only. Refuses PUT on existing key with 412. Never deletes.
//! Bearer auth. Write-temp-then-rename (SIGKILL mid-PUT → no partial object).

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinSet;

/// Shared state for the receive server.
#[derive(Clone, Debug)]
pub struct ReceiveState {
    pub dir: PathBuf,
    pub token: String,
}

/// Own the accept loop via [`JoinSet`].
pub struct WitnessReceiveRuntime {
    join: JoinSet<()>,
    pub local_addr: SocketAddr,
}

impl WitnessReceiveRuntime {
    /// Bind `listen` (e.g. `127.0.0.1:0`), serve under `dir`.
    pub async fn start(
        dir: impl Into<PathBuf>,
        listen: SocketAddr,
        token: impl Into<String>,
    ) -> Result<Self, std::io::Error> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let state = Arc::new(ReceiveState {
            dir,
            token: token.into(),
        });
        let app = router(state);
        let listener = TcpListener::bind(listen).await?;
        let local_addr = listener.local_addr()?;
        let mut join = JoinSet::new();
        join.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { join, local_addr })
    }

    pub async fn shutdown(mut self) {
        self.join.abort_all();
        while self.join.join_next().await.is_some() {}
    }

    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

fn router(state: Arc<ReceiveState>) -> Router {
    Router::new()
        .route("/", get(list_root))
        .route("/{*key}", put(put_object).get(get_object))
        .with_state(state)
}

fn check_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
    let Some(val) = headers.get(header::AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Ok(s) = val.to_str() else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let expected = format!("Bearer {token}");
    if s != expected {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

fn safe_join(root: &Path, key: &str) -> Result<PathBuf, StatusCode> {
    if key.contains("..") || key.starts_with('/') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = root.join(key);
    if !path.starts_with(root) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(path)
}

async fn list_root(
    State(state): State<Arc<ReceiveState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    check_auth(&headers, &state.token)?;
    let keys = list_keys_under(&state.dir, "")?;
    Ok(Json(json!(keys)).into_response())
}

async fn get_object(
    State(state): State<Arc<ReceiveState>>,
    AxumPath(key): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    check_auth(&headers, &state.token)?;
    let path = safe_join(&state.dir, &key)?;
    if key.ends_with('/') || path.is_dir() {
        let prefix = key.trim_start_matches('/');
        let keys = list_keys_under(&state.dir, prefix)?;
        return Ok(Json(json!(keys)).into_response());
    }
    if !path.is_file() {
        return Err(StatusCode::NOT_FOUND);
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::OK, bytes).into_response())
}

async fn put_object(
    State(state): State<Arc<ReceiveState>>,
    AxumPath(key): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    check_auth(&headers, &state.token)?;
    let path = safe_join(&state.dir, &key)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    if path.exists() {
        return Err(StatusCode::PRECONDITION_FAILED);
    }

    // AUD-10: write to temp in same directory, then rename.
    let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), nano_stamp()));
    if tokio::fs::write(&tmp, &body).await.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    if tokio::fs::rename(&tmp, &path).await.is_ok() {
        Ok(StatusCode::CREATED)
    } else {
        let _ = tokio::fs::remove_file(&tmp).await;
        if path.exists() {
            Err(StatusCode::PRECONDITION_FAILED)
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn nano_stamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

fn walk_keys(dir: &Path, root: &Path, out: &mut Vec<String>) -> Result<(), StatusCode> {
    let rd = std::fs::read_dir(dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for ent in rd {
        let ent = ent.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let path = ent.path();
        if path.is_dir() {
            walk_keys(&path, root, out)?;
        } else if path.is_file() {
            if path
                .extension()
                .is_some_and(|e| e.to_str().is_some_and(|s| s.starts_with("tmp-")))
            {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    Ok(())
}

fn list_keys_under(root: &Path, prefix: &str) -> Result<Vec<String>, StatusCode> {
    let mut keys = Vec::new();
    let walk_root = if prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(prefix.trim_end_matches('/'))
    };
    if !walk_root.exists() {
        return Ok(keys);
    }
    walk_keys(&walk_root, root, &mut keys)?;
    keys.sort();
    Ok(keys)
}

/// Load bearer token from file (trim whitespace).
pub fn load_token_file(path: &Path) -> Result<String, std::io::Error> {
    let s = std::fs::read_to_string(path)?;
    Ok(s.trim().to_owned())
}
