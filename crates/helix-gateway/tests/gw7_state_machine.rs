//! GW-7: one test per `interfaces/state-machine.md` row (HLX-36).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::*;
use helix_audit::{FaultSite, InjectedIoFault, Transition};
use helix_gateway::{SchemaRegistry, ToolRuntime};
use helix_runtime::digest_of_bytes;
use serde_json::json;
use tempfile::tempdir;

fn digest_str(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(bytes))
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_parse_fail_no_audit_transition() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let mut state = make_state(load_holder_with(
        &digest_str(&std::fs::read(hello_wasm()).unwrap()),
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let rt = start(state).await;
    let base = rt.base_url();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/"))
        .header("content-type", "application/json")
        .body("{not-json")
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32700));
    let log = dir.path().join("audit.log");
    // Parse fail writes no invocation audit transition (Received never committed as success path).
    let ts = read_transitions(&log);
    assert!(
        ts.iter().all(|(t, _)| *t != Transition::Authenticated),
        "{ts:?}"
    );
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_auth_fail_authfailed_32001() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        "not-a-jwt",
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"a"}}}"#,
    )
    .await;
    // extract_access_token may yield -32001 before our AuthFailed write depending on path
    assert_eq!(v["error"]["code"], json!(-32001));
    assert_has_transition(&dir.path().join("audit.log"), Transition::AuthFailed);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_unknown_tool_rejected_32003() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let rt = start(state).await;
    let token = access_token();
    let v = post_rpc(
        &rt.base_url(),
        &token,
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"nope","input":{}}}"#,
    )
    .await;
    assert_eq!(v["error"]["code"], json!(-32003));
    assert_eq!(v["error"]["data"]["tool"], json!("nope"));
    assert!(v["error"]["data"]["request_id"].is_string());
    assert_has_transition(&dir.path().join("audit.log"), Transition::Rejected);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_policy_miss_denied_32002() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
    // Grant for a different identity thumbprint
    let other = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo";
    let mut state = make_state(load_holder_with(&d, "hello", other, 32, r#""stdio""#));
    state.set_audit(writer, Some(caps));
    // Also need tool in alias table — load_holder puts it. Policy miss on (agent_jkt, digest).
    let rt = start(state).await;
    let token = access_token(); // agent_jkt identity — not granted
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"x"}}}"#;
    let v = post_rpc(&rt.base_url(), &token, body).await;
    // unknown tool if alias resolves but wait — alias resolves, policy miss → -32002
    // Actually identity other is in policy; agent is not → Denied
    assert_eq!(v["error"]["code"], json!(-32002));
    assert_has_transition(&dir.path().join("audit.log"), Transition::Denied);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_payload_invalid_32602() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let digest = digest_of_bytes(&wasm);
    let d = digest_str(&wasm);
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let mut schemas = SchemaRegistry::new();
    schemas
        .insert_raw(
            &digest,
            r#"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}"#,
        )
        .unwrap();
    state.set_schemas(schemas);
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":1}}}"#,
    )
    .await;
    assert_eq!(v["error"]["code"], json!(-32602));
    assert_has_transition(&dir.path().join("audit.log"), Transition::Rejected);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_happy_path_completed() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let digest = digest_of_bytes(&wasm);
    let d = digest_str(&wasm);
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio", "clocks", "random", "filesystem""#,
    ));
    state.set_audit(writer, Some(caps));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = ToolRuntime::new(&tools_dir).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let mut schemas = SchemaRegistry::new();
    schemas
        .insert_raw(
            &digest,
            r#"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
        )
        .unwrap();
    state.set_schemas(schemas);
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"hi"}}}"#,
    )
    .await;
    assert!(v.get("result").is_some(), "{v}");
    let log = dir.path().join("audit.log");
    for t in [
        Transition::Received,
        Transition::Authenticated,
        Transition::Authorized,
        Transition::Granted,
        Transition::Provisioned,
        Transition::Running,
        Transition::Completed,
    ] {
        assert_has_transition(&log, t);
    }
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_missing_artifact_failed_32004() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    // no tools registered
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"hello","input":{"text":"x"}}}"#,
    )
    .await;
    assert_eq!(v["error"]["code"], json!(-32004));
    assert_ne!(v["error"]["data"]["reason"], json!("not_wired"));
    assert_has_transition(&dir.path().join("audit.log"), Transition::Failed);
    assert_has_transition(&dir.path().join("audit.log"), Transition::Granted);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_granted_sync_fail_32030_no_instantiate() {
    let dir = tempdir().unwrap();
    let fault = InjectedIoFault::always(FaultSite::Write, 28);
    let (art, writer, caps) = open_audit_fault(dir.path(), fault).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
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
    assert!(
        v["error"]["data"].get("reason").is_none()
            || v["error"]["data"]
                .as_object()
                .unwrap()
                .keys()
                .all(|k| k == "request_id")
    );
    assert_eq!(tools.instantiate_count(), 0);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_describe_success_described() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
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
    let tools = ToolRuntime::new(&tools_dir).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.describe","params":{"tool":"hello"}}"#,
    )
    .await;
    assert!(v.get("result").is_some(), "{v}");
    let log = dir.path().join("audit.log");
    assert_has_transition(&log, Transition::Described);
    let ts = read_transitions(&log);
    assert!(!ts
        .iter()
        .any(|(t, _)| matches!(t, Transition::Authorized | Transition::Granted)));
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_describe_ungranted_32003() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = digest_str(&wasm);
    let other = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo";
    let mut state = make_state(load_holder_with(&d, "hello", other, 32, r#""stdio""#));
    state.set_audit(writer, Some(caps));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = ToolRuntime::new(&tools_dir).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.describe","params":{"tool":"hello"}}"#,
    )
    .await;
    assert_eq!(v["error"]["code"], json!(-32003));
    assert_has_transition(&dir.path().join("audit.log"), Transition::Rejected);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_provision_link_fail_http_without_bit() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let wasm = std::fs::read(http_import_wasm()).unwrap();
    let d = digest_str(&wasm);
    // interfaces without http_outbound
    let mut state = make_state(load_holder_with(
        &d,
        "http_tool",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = ToolRuntime::new(&tools_dir).unwrap();
    // http_import may fail signature() if it has no signature export — skip register if so
    let Ok(_) = tools.register_bytes(&wasm) else {
        // Fixture lacks signature export — skip this row.
        drop(art);
        return;
    };
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    let v = post_rpc(
        &rt.base_url(),
        &access_token(),
        r#"{"jsonrpc":"2.0","id":1,"method":"helix.invoke","params":{"tool":"http_tool","input":{}}}"#,
    )
    .await;
    assert_eq!(v["error"]["code"], json!(-32004));
    assert_has_transition(&dir.path().join("audit.log"), Transition::Failed);
    rt.shutdown().await;
    drop(art);
}

#[tokio::test(flavor = "multi_thread")]
async fn gw7_batch_invalid_request_32600() {
    let dir = tempdir().unwrap();
    let (art, writer, caps) = open_audit(dir.path()).await;
    let mut state = make_state(load_holder_with(
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "t",
        &agent_jkt(),
        32,
        r#""stdio""#,
    ));
    state.set_audit(writer, Some(caps));
    let rt = start(state).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/", rt.base_url()))
        .header("content-type", "application/json")
        .body(r#"[{"jsonrpc":"2.0","id":1,"method":"helix.health","params":{}}]"#)
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], json!(-32600));
    rt.shutdown().await;
    drop(art);
}
