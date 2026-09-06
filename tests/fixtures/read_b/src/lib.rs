//! Guide §4 filesystem example used for SDK-4 / RT-2 against the reference runtime.

use helix_sdk::{helix_tool, ToolError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, JsonSchema)]
struct Input {
    /// Guest path relative to the granted preopen (e.g. `b.txt`).
    path: String,
}

#[derive(Serialize, JsonSchema)]
struct Output {
    /// File contents as UTF-8 (lossy).
    contents: String,
}

#[helix_tool(name = "read_b", version = "0.1.0")]
fn read_b(input: Input) -> Result<Output, ToolError> {
    let data = std::fs::read(&input.path)
        .map_err(|e| ToolError::CapabilityDenied(format!("{}: {e}", input.path)))?;
    Ok(Output {
        contents: String::from_utf8_lossy(&data).into_owned(),
    })
}
