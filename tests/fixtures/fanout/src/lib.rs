#[allow(warnings)]
mod bindings;

use bindings::helix::tool::caps::CapabilitySet;
use bindings::helix::tool::delegate::{self, DelegationRequest, ToolRef};
use bindings::{Guest, InvokeError, ToolSignature};

struct Component;

impl Guest for Component {
    fn signature() -> ToolSignature {
        ToolSignature {
            name: "fanout".into(),
            version: "0.1.0".into(),
            input_schema: r#"{"type":"object"}"#.into(),
            output_schema: r#"{"type":"object"}"#.into(),
        }
    }

    fn invoke(_input: Vec<u8>) -> Result<Vec<u8>, InvokeError> {
        let requested = CapabilitySet {
            interfaces: 1u64 << 0, // stdio
            files: vec![],
            hosts: vec![],
        };
        let req = DelegationRequest {
            tool: ToolRef::Alias("child-echo".into()),
            requested,
            budget: None,
            input: br#"{}"#.to_vec(),
        };
        // First call under max_children=0 must be ::fanout.
        match delegate::invoke(&req) {
            Ok(_) => Err(InvokeError::Internal("expected fanout".into())),
            Err(e) => Ok(format!("delegate-error:{e:?}").into_bytes()),
        }
    }
}

bindings::export!(Component with_types_in bindings);
