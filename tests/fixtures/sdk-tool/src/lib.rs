//! SDK-1 fixture: `#[helix_tool]` builds a component exporting `signature` and `invoke`.

use helix_sdk::{helix_tool, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, JsonSchema)]
struct Input {
    /// Text to count.
    text: String,
}

#[derive(Serialize, JsonSchema)]
struct Output {
    words: usize,
}

#[helix_tool(name = "word_count", version = "0.1.0")]
fn word_count(input: Input) -> Result<Output, ToolError> {
    Ok(Output {
        words: input.text.split_whitespace().count(),
    })
}
