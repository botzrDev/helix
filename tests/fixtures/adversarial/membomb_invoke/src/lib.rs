#[allow(warnings)]
mod bindings;

use bindings::{Guest, InvokeError, ToolSignature};

struct Component;

impl Guest for Component {
    fn signature() -> ToolSignature {
        ToolSignature {
            name: "membomb".into(),
            version: "0.1.0".into(),
            input_schema: r#"{"type":"object"}"#.into(),
            output_schema: r#"{"type":"object"}"#.into(),
        }
    }

    fn invoke(_input: Vec<u8>) -> Result<Vec<u8>, InvokeError> {
        // Grow linear memory until HelixLimiter traps.
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        loop {
            chunks.push(vec![0u8; 64 * 1024]);
        }
    }
}

bindings::export!(Component with_types_in bindings);
