use helix_sdk::{helix_tool, ToolError};

struct NotSerde {
    raw: *const u8,
}

#[helix_tool(name = "bad", version = "0.1.0")]
fn bad(input: NotSerde) -> Result<(), ToolError> {
    let _ = input;
    Ok(())
}

fn main() {}
