//! GW-16: describe ungranted ≡ nonexistent (byte-identical except `request_id`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use common::*;
use helix_gateway::ToolRuntime;
use helix_runtime::digest_of_bytes;
use serde_json::{json, Value};
use tempfile::tempdir;

fn other_jkt() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xAAu8; 32])
}

#[tokio::test(flavor = "multi_thread")]
async fn gw16_ungranted_and_nonexistent_byte_identical() {
    let dir = tempdir().unwrap();
    let wasm = std::fs::read(hello_wasm()).unwrap();
    let d = format!(
        "sha256:{}",
        helix_runtime::digest_hex(&digest_of_bytes(&wasm))
    );
    let mut state = make_state(load_holder_with(
        &d,
        "hello",
        &other_jkt(),
        32,
        r#""stdio""#,
    ));
    let tools_dir = dir.path().join("artifacts");
    std::fs::create_dir_all(&tools_dir).unwrap();
    let tools = ToolRuntime::new(&tools_dir).unwrap();
    tools.register_bytes(&wasm).unwrap();
    state.set_tools(Arc::new(tools));
    let rt = start(state).await;
    let token = access_token();

    // Ungranted: alias exists, no grant for this identity.
    let a = post_rpc(
        &rt.base_url(),
        &token,
        r#"{"jsonrpc":"2.0","id":"1","method":"helix.describe","params":{"tool":"hello"}}"#,
    )
    .await;
    rt.shutdown().await;

    // Nonexistent: no alias named hello.
    let empty_toml = format!(
        r#"
version = 1
[tools]
[budgets.default]
wall_clock_ms = 1000
memory_bytes = 1048576
output_bytes = 1024
[identities]
agent = "{}"
"#,
        agent_jkt()
    );
    let store = helix_policy::MemoryArtifactStore::new().with_runtime_max(256);
    let policy = helix_policy::PolicyHolder::load(
        &empty_toml,
        &store,
        &helix_policy::MapFs::new(),
        helix_policy::DEFAULT_MAX_SNAPSHOT_AGE_S,
    )
    .unwrap();
    let state = make_state(policy);
    let rt = start(state).await;
    let b = post_rpc(
        &rt.base_url(),
        &token,
        r#"{"jsonrpc":"2.0","id":"1","method":"helix.describe","params":{"tool":"hello"}}"#,
    )
    .await;

    assert_eq!(a["error"]["code"], json!(-32003));
    assert_eq!(b["error"]["code"], json!(-32003));
    assert_eq!(a["error"]["data"]["tool"], json!("hello"));
    assert_eq!(b["error"]["data"]["tool"], json!("hello"));

    let mut aa = a.clone();
    let mut bb = b.clone();
    aa["error"]["data"]["request_id"] = Value::Null;
    bb["error"]["data"]["request_id"] = Value::Null;
    assert_eq!(
        serde_json::to_vec(&aa["error"]).unwrap(),
        serde_json::to_vec(&bb["error"]).unwrap()
    );

    rt.shutdown().await;
}
