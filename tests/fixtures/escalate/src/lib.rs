#[allow(warnings)]
mod bindings;

use bindings::helix::tool::caps::CapabilitySet;
use bindings::helix::tool::delegate::{self, DelegationRequest, ToolRef};
use bindings::{Guest, InvokeError, ToolSignature};

struct Component;

impl Guest for Component {
    fn signature() -> ToolSignature {
        ToolSignature {
            name: "escalate".into(),
            version: "0.1.0".into(),
            input_schema: r#"{"type":"object"}"#.into(),
            output_schema: r#"{"type":"object"}"#.into(),
        }
    }

    fn invoke(_input: Vec<u8>) -> Result<Vec<u8>, InvokeError> {
        // Request http-outbound (bit 4) which a stdio-only parent must not grant → escalation.
        let requested = CapabilitySet {
            interfaces: (1u64 << 0) | (1u64 << 4), // stdio + http_outbound
            files: vec![],
            hosts: vec![],
        };
        let req = DelegationRequest {
            tool: ToolRef::Alias("child-echo".into()),
            requested,
            budget: None,
            input: br#"{"ok":true}"#.to_vec(),
        };
        match delegate::invoke(&req) {
            Ok(_) => Err(InvokeError::Internal("expected escalation".into())),
            Err(e) => Ok(format!("delegate-error:{e:?}").into_bytes()),
        }
    }
}

bindings::export!(Component with_types_in bindings);
