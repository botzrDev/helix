//! AUD-6 / AUD-7 end-to-end through the gateway (HLX-36): `-32030`, no instantiate.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::*;
use helix_audit::{FaultSite, InjectedIoFault};
use helix_gateway::ToolRuntime;
use helix_runtime::digest_of_bytes;
use serde_json::json;
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread")]
async fn aud6_enospc_invoke_is_32030_no_instantiate() {
    let dir = tempdir().unwrap();
    let fault = InjectedIoFault::always(FaultSite::Write, 28); // ENOSPC
    let (art, writer, caps) = open_audit_fault(dir.path(), fault).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = Arc::new(ToolRuntime::new(&tools_dir).unwrap());
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::clone(&tools));
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"x"}}}"#,
    )
    .await;
    assert_eq!(v["error"]["code"], json!(-32030));
    assert_eq!(tools.instantiate_count(), 0);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn aud7_rotation_unwritable_invoke_32030() {
    let dir = tempdir().unwrap();
    // Use directory writer with rotate fault — open_dir_with_fail_closed
    let fault = InjectedIoFault::always(FaultSite::RotateOpen, 13); // EACCES
    let fatal = helix_audit::RecordingFatal::new();
    let fc = helix_audit::FailClosedConfig::for_test(fault, fatal).with_max_consecutive_errors(3);
    let mut n = 0u8;
    let ulid_source: helix_audit::UlidSource = Box::new(move || {
        n = n.wrapping_add(1);
        let mut a = [0u8; 16];
        a[15] = n;
        a
    });
    let art = helix_audit::AuditWriterRuntime::open_dir_with_fail_closed(
        dir.path(),
        "gw-aud7",
        200, // tiny rotate_bytes to force rotation quickly
        Arc::new(helix_audit::NoopSyncHook),
        16,
        ulid_source,
        fc,
    )
    .await
    .expect("dir writer");
    let writer = art.writer();
    let caps = helix_audit::CapsStore::open(dir.path()).unwrap();

    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = Arc::new(ToolRuntime::new(&tools_dir).unwrap());
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::clone(&tools));
    let rt = start(state).await;

    // Fill past rotate boundary with many invokes; at least one should hit -32030
    let mut saw_32030 = false;
    for i in 0..40 {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{i},"method":"helix.invoke","params":{{"tool":"hello","input":{{"text":"x"}}}}}}"#
        );
        let v = post_rpc(&rt.base_url(), &access_token(), &body).await;
        if v["error"]["code"] == json!(-32030) {
            saw_32030 = true;
            break;
        }
    }
    assert!(saw_32030, "expected a -32030 after rotation fault");
    rt.shutdown().await;
    drop(art);
}
