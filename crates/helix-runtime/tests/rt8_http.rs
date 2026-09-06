//! RT-8 (real HTTP), slowhost tarpit → `Killed(WallClock)`, ungranted never opens a socket.
//!
//! HLX-30 / M4-07.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use helix_caps::{CapabilitySet, HostGrant, Interface, Interner, Method, MethodMask};
use helix_runtime::{
    build_engine, check_host_grant, host_http_get_status, host_select, link, normalize_authority,
    run_with_wall_clock, send_request_with_grants, HostGrantTable, HostHttpError, InvokeError,
    KillCause, RecordingHook, RuntimeConfig, TerminalHook, TerminalKind, TerminalRecord, Usage,
    WasiHost, WALL_CLOCK_TRAP_MSG,
};
use http::Uri;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wasmtime_wasi::p2::Pollable;
use wasmtime_wasi_http::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, OutgoingRequestConfig};

fn test_engine() -> wasmtime::Engine {
    let tmp = tempfile::tempdir().unwrap();
    build_engine(&RuntimeConfig::for_test(tmp.path())).expect("engine")
}

fn caps_http(authority: &str, methods: &[Method]) -> CapabilitySet {
    let mut intern = Interner::new();
    let id = intern.intern_authority(authority);
    CapabilitySet::new(
        &[Interface::HttpOutbound],
        vec![],
        vec![],
        vec![HostGrant::new(id, MethodMask::new(methods))],
    )
    .unwrap()
    .with_interner(intern)
}

fn empty_body() -> wasmtime_wasi_http::body::HyperOutgoingBody {
    use http_body_util::BodyExt;
    http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|_| unreachable!("infallible"))
        .boxed()
}

/// Accept connections but never complete an HTTP response (tarpit / slowhost).
async fn spawn_tarpit() -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let stop_c = stop.clone();
    #[allow(clippy::disallowed_methods)] // test-only listener loop
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = stop_c.cancelled() => break,
                acc = listener.accept() => {
                    let Ok((mut sock, _)) = acc else { break; };
                    let mut buf = [0u8; 64];
                    let _ = sock.read(&mut buf).await;
                    stop_c.cancelled().await;
                    let _ = sock.shutdown().await;
                }
            }
        }
    });
    (addr, stop, handle)
}

/// Echo server that counts accepted connections and replies 200.
async fn spawn_mock_counter(
    accepts: Arc<AtomicUsize>,
) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let stop_c = stop.clone();
    #[allow(clippy::disallowed_methods)] // test-only listener loop
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = stop_c.cancelled() => break,
                acc = listener.accept() => {
                    let Ok((mut sock, _)) = acc else { break; };
                    accepts.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = sock.write_all(resp).await;
                    let _ = sock.shutdown().await;
                }
            }
        }
    });
    (addr, stop, handle)
}

/// RT-8: real HTTP host call blocked on a tarpit is cancelled at `wall_clock` → `WallClock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt8_real_http_tarpit_killed_wall_clock() {
    let (addr, stop, server) = spawn_tarpit().await;
    let uri = format!("http://{addr}/slow");
    let wall_ms = 60u32;
    let started = Instant::now();

    let mut hook = RecordingHook::default();
    let cause = run_with_wall_clock(wall_ms, |token| async move {
        let parked = host_select(
            &token,
            KillCause::WallClock,
            host_http_get_status(&token, &uri),
        )
        .await;
        match parked {
            Err(c) => Err::<(), KillCause>(c),
            Ok(Err(HostHttpError::Cancelled)) => Err(KillCause::WallClock),
            Ok(Ok(status)) => panic!("tarpit returned status {status}"),
            Ok(Err(e)) => panic!("unexpected transport: {e}"),
        }
    })
    .await
    .expect_err("must kill at wall clock");

    assert_eq!(cause, KillCause::WallClock);
    assert_eq!(cause.gateway_code(), -32011);

    let usage = Usage {
        wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        preempt_ticks: 0,
        peak_memory_bytes: 0,
        output_bytes: 0,
    };
    hook.on_terminal(TerminalRecord {
        kind: TerminalKind::Killed { cause },
        usage,
    });
    let err = InvokeError::Killed { cause, usage };
    assert_eq!(err.gateway_code(), -32011);
    assert!(
        usage.wall_ms >= u64::from(wall_ms.saturating_sub(10)),
        "wall_ms={} below budget",
        usage.wall_ms
    );
    assert!(
        usage.wall_ms < u64::from(wall_ms) + 2000,
        "wall_ms={} far above budget",
        usage.wall_ms
    );

    stop.cancel();
    let _ = server.await;
}

/// slowhost: wasi:http `send_request` to tarpit + wall clock → trap message / `WallClock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slowhost_wasi_http_send_killed_wall_clock() {
    let (addr, stop, server) = spawn_tarpit().await;
    let authority = format!("{}:{}", addr.ip(), addr.port()).to_ascii_lowercase();
    let grants =
        HostGrantTable::from_entries(vec![(authority.clone(), MethodMask::new(&[Method::Get]))]);

    let wall_ms = 50u32;
    let started = Instant::now();
    let cause = run_with_wall_clock(wall_ms, |token| async move {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://{authority}/slow"))
            .body(empty_body())
            .unwrap();
        let config = OutgoingRequestConfig {
            use_tls: false,
            connect_timeout: Duration::from_secs(30),
            first_byte_timeout: Duration::from_secs(30),
            between_bytes_timeout: Duration::from_secs(30),
        };
        let mut fut =
            send_request_with_grants(&grants, &token, request, config).expect("grant allows");

        // Drive the pending response until cancel completes it.
        fut.ready().await;
        let ready = match fut {
            HostFutureIncomingResponse::Ready(r) => r,
            other => panic!("expected ready, got {other:?}"),
        };
        match ready {
            Err(err) => {
                let msg = format!("{err}");
                assert!(
                    msg.contains(WALL_CLOCK_TRAP_MSG)
                        || msg.to_ascii_lowercase().contains("wall-clock"),
                    "expected wall-clock trap, got {msg}"
                );
                Err::<(), KillCause>(KillCause::WallClock)
            }
            Ok(Err(_)) => Err(KillCause::WallClock),
            Ok(Ok(_)) => panic!("tarpit must not complete under short wall clock"),
        }
    })
    .await
    .expect_err("wall clock");

    assert_eq!(cause, KillCause::WallClock);
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(u64::from(wall_ms.saturating_sub(15))));
    assert!(elapsed < Duration::from_millis(u64::from(wall_ms) + 2000));

    stop.cancel();
    let _ = server.await;
}

/// Ungranted authority: `HttpRequestDenied` and mock server accept counter stays 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ungranted_authority_never_opens_socket() {
    let accepts = Arc::new(AtomicUsize::new(0));
    let (addr, stop, server) = spawn_mock_counter(Arc::clone(&accepts)).await;
    let live = format!("{}:{}", addr.ip(), addr.port()).to_ascii_lowercase();

    let grants = HostGrantTable::from_entries(vec![(
        "127.0.0.1:1".into(),
        MethodMask::new(&[Method::Get]),
    )]);
    let uri: Uri = format!("http://{live}/").parse().unwrap();
    assert!(matches!(
        check_host_grant(&grants, &uri, &http::Method::GET, false),
        Err(ErrorCode::HttpRequestDenied)
    ));

    let token = CancellationToken::new();
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{live}/"))
        .body(empty_body())
        .unwrap();
    let config = OutgoingRequestConfig {
        use_tls: false,
        connect_timeout: Duration::from_secs(2),
        first_byte_timeout: Duration::from_secs(2),
        between_bytes_timeout: Duration::from_secs(2),
    };
    let err = send_request_with_grants(&grants, &token, request, config).expect_err("denied");
    let code = err.downcast_ref();
    assert!(
        matches!(code, Some(ErrorCode::HttpRequestDenied)),
        "expected HttpRequestDenied, got {err:?} code={code:?}"
    );

    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "ungranted request must not open a socket"
    );

    stop.cancel();
    let _ = server.await;
}

/// `http_get`: granted GET against local mock returns 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_get_against_local_mock() {
    let accepts = Arc::new(AtomicUsize::new(0));
    let (addr, stop, server) = spawn_mock_counter(Arc::clone(&accepts)).await;
    let uri = format!("http://{addr}/");
    let token = CancellationToken::new();
    let status = host_http_get_status(&token, &uri).await.expect("http get");
    assert_eq!(status, 200);
    assert!(accepts.load(Ordering::SeqCst) >= 1);

    let authority = format!("{}:{}", addr.ip(), addr.port()).to_ascii_lowercase();
    let caps = caps_http(&authority, &[Method::Get]);
    let engine = test_engine();
    let _linker = link::<WasiHost>(&engine, &caps).expect("link http");
    let host = WasiHost::from_capability_set(&caps).expect("host");
    assert!(host.host_grants().allows(&authority, Method::Get));

    stop.cancel();
    let _ = server.await;
}

#[test]
fn method_not_in_mask_denied() {
    let grants = HostGrantTable::from_entries(vec![(
        "api.example.com:443".into(),
        MethodMask::new(&[Method::Get]),
    )]);
    let uri: Uri = "https://api.example.com/v1".parse().unwrap();
    assert_eq!(
        normalize_authority(&uri, true).as_deref(),
        Some("api.example.com:443")
    );
    let err = check_host_grant(&grants, &uri, &http::Method::POST, true).unwrap_err();
    assert!(matches!(err, ErrorCode::HttpRequestDenied));
}
