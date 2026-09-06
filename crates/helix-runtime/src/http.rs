//! wasi:http outbound with [`HostGrant`] authority + method enforcement (HLX-30 / M4-07).
//!
//! # Model (PRD §5.3 Network grants, B4)
//!
//! - `wasi:http/outgoing-handler` (and `wasi:http/types`) are linked only when
//!   [`Interface::HttpOutbound`] is set ([`crate::link`]).
//! - [`WasiHttpView::send_request`] rejects any request whose lowercase
//!   `host:port` authority and method are not in the resolved host grants with
//!   [`ErrorCode::HttpRequestDenied`] **before** any socket is opened.
//! - Allowed requests run under a cancel race against the request token so a
//!   tarpit yields a wall-clock trap ([`WALL_CLOCK_TRAP_MSG`]) →
//!   [`crate::error::KillCause::WallClock`].
//!
//! # Send path
//!
//! Helix does **not** enable wasmtime-wasi-http's `default-send-request` feature
//! (that feature pins rustls 0.22 / RUSTSEC advisories). Outbound I/O uses a
//! Helix-owned Hyper HTTP/1.1 client with rustls 0.23 for TLS.

use std::time::Duration;

use helix_caps::{Method, MethodMask};
use http::Uri;
use http_body_util::BodyExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wasmtime_wasi_http::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::hyper_request_error;
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::types::{
    HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig,
};
use wasmtime_wasi_http::{HttpError, HttpResult};

/// Trap message substring mapped to [`crate::error::KillCause::WallClock`].
pub const WALL_CLOCK_TRAP_MSG: &str = "helix: killed wall-clock";

/// Resolved `HostGrant` list: lowercase `host:port` → allowed methods.
#[derive(Debug, Clone, Default)]
pub struct HostGrantTable {
    entries: Vec<(String, MethodMask)>,
}

impl HostGrantTable {
    /// Empty table (no authorities permitted).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// From already-normalized `(authority, methods)` pairs.
    #[must_use]
    pub fn from_entries(entries: Vec<(String, MethodMask)>) -> Self {
        Self { entries }
    }

    /// Borrow entries.
    #[must_use]
    pub fn entries(&self) -> &[(String, MethodMask)] {
        &self.entries
    }

    /// True when some grant covers `authority` + `method`.
    #[must_use]
    pub fn allows(&self, authority: &str, method: Method) -> bool {
        self.entries
            .iter()
            .any(|(a, mask)| a == authority && mask.contains(method))
    }
}

/// Normalize request authority to lowercase `host:port` with an explicit port.
///
/// When the URI omits a port, `80` (http) or `443` (https) is filled from
/// `use_tls` so it can match policy grants that always carry an explicit port.
#[must_use]
pub fn normalize_authority(uri: &Uri, use_tls: bool) -> Option<String> {
    let authority = uri.authority()?;
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port = authority
        .port_u16()
        .unwrap_or(if use_tls { 443 } else { 80 });
    Some(format!("{host}:{port}"))
}

/// Map `http::Method` onto the HELIX [`Method`] enum (CONNECT/OPTIONS/TRACE/other → `None`).
#[must_use]
pub fn helix_method(method: &http::Method) -> Option<Method> {
    Method::parse(method.as_str())
}

/// Check `HostGrant` before any connect. `Ok(())` when permitted.
///
/// # Errors
///
/// [`ErrorCode::HttpRequestDenied`] when authority/method are absent or unknown.
pub fn check_host_grant(
    grants: &HostGrantTable,
    uri: &Uri,
    method: &http::Method,
    use_tls: bool,
) -> Result<(), ErrorCode> {
    let Some(authority) = normalize_authority(uri, use_tls) else {
        return Err(ErrorCode::HttpRequestUriInvalid);
    };
    let Some(m) = helix_method(method) else {
        // Unknown / disallowed method bits (CONNECT, TRACE, …) → denied style.
        return Err(ErrorCode::HttpRequestDenied);
    };
    if grants.allows(&authority, m) {
        Ok(())
    } else {
        Err(ErrorCode::HttpRequestDenied)
    }
}

/// Helix-owned outbound send (plain TCP or rustls 0.23 TLS).
///
/// Grant enforcement is done by [`send_request_with_grants`] before this runs.
async fn helix_send_request_handler(
    mut request: http::Request<HyperOutgoingBody>,
    OutgoingRequestConfig {
        use_tls,
        connect_timeout,
        first_byte_timeout,
        between_bytes_timeout,
    }: OutgoingRequestConfig,
) -> Result<IncomingResponse, ErrorCode> {
    let authority = if let Some(authority) = request.uri().authority() {
        if authority.port().is_some() {
            authority.to_string()
        } else {
            let port = if use_tls { 443 } else { 80 };
            format!("{authority}:{port}")
        }
    } else {
        return Err(ErrorCode::HttpRequestUriInvalid);
    };

    let tcp_stream = timeout(connect_timeout, TcpStream::connect(&authority))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|e| map_connect_error(&e))?;

    let (mut sender, worker) = if use_tls {
        handshake_tls(tcp_stream, &authority, connect_timeout).await?
    } else {
        handshake_plain(tcp_stream, connect_timeout).await?
    };

    // Origin-form request-target (scheme/authority stripped for direct peers).
    *request.uri_mut() = http::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str),
        )
        .build()
        .expect("comes from valid request");

    let resp = timeout(first_byte_timeout, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(hyper_request_error)?
        .map(|body| body.map_err(hyper_request_error).boxed());

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout,
    })
}

fn map_connect_error(e: &std::io::Error) -> ErrorCode {
    match e.kind() {
        std::io::ErrorKind::AddrNotAvailable => {
            ErrorCode::DnsError(wasmtime_wasi_http::bindings::http::types::DnsErrorPayload {
                rcode: Some("address not available".into()),
                info_code: Some(0),
            })
        }
        _ if e
            .to_string()
            .starts_with("failed to lookup address information") =>
        {
            ErrorCode::DnsError(wasmtime_wasi_http::bindings::http::types::DnsErrorPayload {
                rcode: Some("address not available".into()),
                info_code: Some(0),
            })
        }
        _ => ErrorCode::ConnectionRefused,
    }
}

type HttpSender = hyper::client::conn::http1::SendRequest<HyperOutgoingBody>;
type WorkerHandle = wasmtime_wasi::runtime::AbortOnDropJoinHandle<()>;

async fn handshake_plain(
    tcp_stream: TcpStream,
    connect_timeout: Duration,
) -> Result<(HttpSender, WorkerHandle), ErrorCode> {
    let stream = TokioIo::new(tcp_stream);
    let (sender, conn) = timeout(
        connect_timeout,
        hyper::client::conn::http1::handshake(stream),
    )
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)?
    .map_err(hyper_request_error)?;

    // Connection driver: wasmtime AbortOnDropJoinHandle (same as wasi-http default).
    // ST-2 hole: not `spawn_cancellable`; documented in module + PR.
    let worker = wasmtime_wasi::runtime::spawn(async move {
        if let Err(e) = conn.await {
            tracing_warn_conn(&e);
        }
    });
    Ok((sender, worker))
}

async fn handshake_tls(
    tcp_stream: TcpStream,
    authority: &str,
    connect_timeout: Duration,
) -> Result<(HttpSender, WorkerHandle), ErrorCode> {
    use rustls::pki_types::ServerName;

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    let domain = ServerName::try_from(host.to_string()).map_err(|_| {
        ErrorCode::DnsError(wasmtime_wasi_http::bindings::http::types::DnsErrorPayload {
            rcode: Some("invalid dns name".into()),
            info_code: Some(0),
        })
    })?;
    let stream = connector
        .connect(domain, tcp_stream)
        .await
        .map_err(|_| ErrorCode::TlsProtocolError)?;
    let stream = TokioIo::new(stream);

    let (sender, conn) = timeout(
        connect_timeout,
        hyper::client::conn::http1::handshake(stream),
    )
    .await
    .map_err(|_| ErrorCode::ConnectionTimeout)?
    .map_err(hyper_request_error)?;

    let worker = wasmtime_wasi::runtime::spawn(async move {
        if let Err(e) = conn.await {
            tracing_warn_conn(&e);
        }
    });
    Ok((sender, worker))
}

fn tracing_warn_conn(e: &hyper::Error) {
    // Avoid hard dep on `tracing`; swallow like wasmtime's default handler.
    let _ = e;
}

/// Cancel-aware outbound send used by [`crate::host::WasiHost`]'s `WasiHttpView`.
///
/// Grant enforcement runs **synchronously** before any I/O. The hyper send is
/// then raced against `token` via `tokio::select!` (same shape as
/// [`crate::cancel::host_select`]). Cancel completes as a trap carrying
/// [`WALL_CLOCK_TRAP_MSG`].
///
/// # Errors
///
/// - [`ErrorCode::HttpRequestDenied`] when grants fail (no socket).
/// - Trap [`HttpError`] on wall-clock cancel.
pub fn send_request_with_grants(
    grants: &HostGrantTable,
    token: &CancellationToken,
    request: http::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
) -> HttpResult<HostFutureIncomingResponse> {
    check_host_grant(grants, request.uri(), request.method(), config.use_tls)?;

    // Already cancelled: fail closed without opening a socket.
    if token.is_cancelled() {
        return Err(HttpError::trap(anyhow::anyhow!(WALL_CLOCK_TRAP_MSG)));
    }

    let token = token.clone();
    // `HostFutureIncomingResponse::pending` requires wasmtime_wasi::runtime::spawn
    // (AbortOnDropJoinHandle). ST-2 hole: this is not `spawn_cancellable`, but the
    // future still selects on the request token so tarpits become wall-clock traps.
    let handle = wasmtime_wasi::runtime::spawn(async move {
        tokio::select! {
            biased;
            () = token.cancelled() => {
                Err(anyhow::anyhow!(WALL_CLOCK_TRAP_MSG))
            }
            out = helix_send_request_handler(request, config) => {
                Ok(out)
            }
        }
    });
    Ok(HostFutureIncomingResponse::pending(handle))
}

/// Async host HTTP GET used by RT-8 (real socket + cancel), outside the guest.
///
/// Uses `reqwest` so the connection worker stays inside that crate (ST-2: no
/// bare `tokio::spawn` here). Select against `token` for tarpit cancel.
///
/// # Errors
///
/// [`HostHttpError::Cancelled`] when the token fires; transport errors otherwise.
pub async fn host_http_get_status(
    token: &CancellationToken,
    uri: &str,
) -> Result<u16, HostHttpError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| HostHttpError::Transport(e.to_string()))?;

    let send = client.get(uri).send();

    tokio::select! {
        biased;
        () = token.cancelled() => Err(HostHttpError::Cancelled),
        out = send => {
            let resp = out.map_err(|e| HostHttpError::Transport(e.to_string()))?;
            Ok(resp.status().as_u16())
        }
    }
}

/// Errors from [`host_http_get_status`].
#[derive(Debug)]
pub enum HostHttpError {
    /// Request token cancelled (wall-clock / parent).
    Cancelled,
    /// Non-I/O transport / URI / client problem.
    Transport(String),
}

impl std::fmt::Display for HostHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "cancelled"),
            Self::Transport(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for HostHttpError {}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use helix_caps::Method;

    #[test]
    fn normalize_fills_default_ports() {
        let http_uri: Uri = "http://Example.COM/x".parse().unwrap();
        assert_eq!(
            normalize_authority(&http_uri, false).as_deref(),
            Some("example.com:80")
        );
        let https: Uri = "https://Example.COM/x".parse().unwrap();
        assert_eq!(
            normalize_authority(&https, true).as_deref(),
            Some("example.com:443")
        );
        let explicit: Uri = "http://127.0.0.1:9876/".parse().unwrap();
        assert_eq!(
            normalize_authority(&explicit, false).as_deref(),
            Some("127.0.0.1:9876")
        );
    }

    #[test]
    fn grant_table_allows_and_denies() {
        let table = HostGrantTable::from_entries(vec![(
            "127.0.0.1:9".into(),
            MethodMask::new(&[Method::Get]),
        )]);
        assert!(table.allows("127.0.0.1:9", Method::Get));
        assert!(!table.allows("127.0.0.1:9", Method::Post));
        assert!(!table.allows("evil.example:443", Method::Get));
    }

    #[test]
    fn check_denies_before_connect_shape() {
        let table = HostGrantTable::from_entries(vec![(
            "allowed.example:443".into(),
            MethodMask::new(&[Method::Get]),
        )]);
        let uri: Uri = "https://denied.example/path".parse().unwrap();
        let err = check_host_grant(&table, &uri, &http::Method::GET, true).unwrap_err();
        assert!(matches!(err, ErrorCode::HttpRequestDenied));
        let uri_ok: Uri = "https://allowed.example/path".parse().unwrap();
        assert!(check_host_grant(&table, &uri_ok, &http::Method::GET, true).is_ok());
        let err_m = check_host_grant(&table, &uri_ok, &http::Method::POST, true).unwrap_err();
        assert!(matches!(err_m, ErrorCode::HttpRequestDenied));
    }
}
