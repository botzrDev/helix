#[allow(warnings)]
mod bindings;

use bindings::{Guest, InvokeError, ToolSignature};

struct Component;

impl Guest for Component {
    fn signature() -> ToolSignature {
        ToolSignature {
            name: "slow-child".into(),
            version: "0.1.0".into(),
            input_schema: r#"{"type":"object"}"#.into(),
            output_schema: r#"{"type":"object"}"#.into(),
        }
    }

    fn invoke(_input: Vec<u8>) -> Result<Vec<u8>, InvokeError> {
        // Busy-loop so preempt / wall-clock kills the child (RT-15).
        loop {
            core::hint::spin_loop();
        }
    }
}

bindings::export!(Component with_types_in bindings);
