//! Author-guide §9 delegation example: returns `word_count`'s child result.

use helix_sdk::delegate;
use helix_sdk::{helix_tool, CapabilitySet, ToolError, ToolRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, JsonSchema)]
struct Input {
    /// Text forwarded to `word_count`.
    text: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct Output {
    words: usize,
}

/// Interface bits: stdio=0, clocks=1, filesystem=3 (matches cargo-component WASI imports).
const CHILD_INTERFACES: u64 = (1 << 0) | (1 << 1) | (1 << 3);

#[helix_tool(name = "delegate_count", version = "0.1.0")]
fn delegate_count(input: Input) -> Result<Output, ToolError> {
    let requested = CapabilitySet {
        interfaces: CHILD_INTERFACES,
        files: vec![],
        hosts: vec![],
    };
    let child = delegate::invoke::<Input, Output>(
        ToolRef::Alias("word_count".into()),
        requested,
        None,
        &input,
    )
    .map_err(|e| ToolError::Internal(format!("delegate: {e}")))?;
    Ok(child.output)
}
