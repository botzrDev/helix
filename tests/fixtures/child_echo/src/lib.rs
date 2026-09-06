#[allow(warnings)]
mod bindings;

use bindings::{Guest, InvokeError, ToolSignature};

struct Component;

impl Guest for Component {
    fn signature() -> ToolSignature {
        ToolSignature {
            name: "child-echo".into(),
            version: "0.1.0".into(),
            input_schema: r#"{"type":"object"}"#.into(),
            output_schema: r#"{"type":"object"}"#.into(),
        }
    }

    fn invoke(input: Vec<u8>) -> Result<Vec<u8>, InvokeError> {
        Ok(input)
    }
}

bindings::export!(Component with_types_in bindings);
