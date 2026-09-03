#[allow(warnings)]
mod bindings;

use bindings::{Guest, InvokeError, ToolSignature};

struct Component;

impl Guest for Component {
    fn signature() -> ToolSignature {
        ToolSignature {
            name: "hello-world".into(),
            version: "0.1.0".into(),
            input_schema: r#"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#.into(),
            output_schema: r#"{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}"#.into(),
        }
    }

    fn invoke(input: Vec<u8>) -> Result<Vec<u8>, InvokeError> {
        // Host already validated shape. Echo a tiny hello payload.
        let _ = input;
        Ok(br#"{"message":"hello, helix"}"#.to_vec())
    }
}

bindings::export!(Component with_types_in bindings);
