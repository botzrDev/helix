//! Author-guide §2 minimal tool (`word_count`).

use helix_sdk::{helix_tool, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, JsonSchema)]
struct Input {
    /// Text to count. Max 1 MiB enforced by the host output cap on the caller side.
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
