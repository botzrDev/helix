//! SDK-2: generated `signature` schema rejects the same inputs as Rust `Deserialize`.

use helix_policy::input_schema::{validate, Schema};
use helix_sdk::{helix_tool, ToolError};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
struct Input {
    text: String,
    count: u32,
}

#[derive(Debug, serde::Serialize, JsonSchema)]
struct Output {
    ok: bool,
}

#[helix_tool(name = "sdk2_sample", version = "0.1.0")]
#[allow(dead_code, clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
fn sdk2_sample(input: Input) -> Result<Output, ToolError> {
    Ok(Output {
        ok: !input.text.is_empty() && input.count > 0,
    })
}

fn schema() -> Schema {
    Schema::parse(&__helix_tool_schema_sdk2_sample::input_schema()).expect("schema json")
}

#[test]
fn sdk2_valid_payload_accepted_by_schema_and_deserialize() {
    let bytes = br#"{"text":"hello","count":3}"#;
    validate(&schema(), bytes).expect("schema accepts");
    let v: Input = serde_json::from_slice(bytes).expect("deserialize accepts");
    assert_eq!(v.text, "hello");
    assert_eq!(v.count, 3);
}

#[test]
fn sdk2_missing_required_rejected_by_schema_and_deserialize() {
    let bytes = br#"{"text":"hello"}"#;
    assert!(
        validate(&schema(), bytes).is_err(),
        "schema must reject missing count"
    );
    assert!(
        serde_json::from_slice::<Input>(bytes).is_err(),
        "Deserialize must reject missing count"
    );
}

#[test]
fn sdk2_wrong_type_rejected_by_schema_and_deserialize() {
    let bytes = br#"{"text":"hello","count":"nope"}"#;
    assert!(
        validate(&schema(), bytes).is_err(),
        "schema must reject wrong type"
    );
    assert!(
        serde_json::from_slice::<Input>(bytes).is_err(),
        "Deserialize must reject wrong type"
    );
}
