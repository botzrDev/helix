//! JSON-RPC 2.0 envelope parsing (one request per HTTP call).
//!
//! Batch arrays are rejected with `-32600` (GW-6). Parse failures are `-32700`.
//!
//! Cites: `interfaces/gateway-protocol.md` §§1,3,4; test-plan GW-6 / GW-8.

use serde_json::Value;

use crate::rpc::{self, RpcCode, RpcId};

/// A single parsed JSON-RPC 2.0 request (pre-dispatch).
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedRequest {
    /// Request id (absent for notifications).
    pub id: Option<RpcId>,
    /// Method name.
    pub method: String,
    /// Params object (defaults to empty object when omitted).
    pub params: Value,
}

/// Outcome of parsing an HTTP body as a JSON-RPC envelope.
#[derive(Clone, Debug, PartialEq)]
pub enum EnvelopeOutcome {
    /// One well-formed request object.
    Ok(ParsedRequest),
    /// Caller should reply with this JSON-RPC error object (HTTP 200).
    Err(Value),
}

/// Parse raw body bytes into a single JSON-RPC request.
///
/// This function is the fuzz entry point (`envelope` target). It must not panic
/// on any input.
#[must_use]
pub fn parse_envelope(body: &[u8]) -> EnvelopeOutcome {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return EnvelopeOutcome::Err(rpc::error(None, RpcCode::ParseError, None));
        }
    };
    parse_envelope_value(&value)
}

/// Parse an already-decoded JSON value.
#[must_use]
pub fn parse_envelope_value(value: &Value) -> EnvelopeOutcome {
    if value.is_array() {
        return EnvelopeOutcome::Err(rpc::invalid_request(None, "batch_not_supported"));
    }
    let Some(obj) = value.as_object() else {
        return EnvelopeOutcome::Err(rpc::invalid_request(None, "request_must_be_object"));
    };

    match obj.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => {}
        _ => {
            return EnvelopeOutcome::Err(rpc::invalid_request(None, "jsonrpc_version"));
        }
    }

    let id = match obj.get("id") {
        None => None,
        Some(v) => match RpcId::from_value(v) {
            Some(id) => Some(id),
            None => {
                return EnvelopeOutcome::Err(rpc::invalid_request(None, "bad_id"));
            }
        },
    };

    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return EnvelopeOutcome::Err(rpc::invalid_request(id.as_ref(), "missing_method"));
    };
    if method.is_empty() {
        return EnvelopeOutcome::Err(rpc::invalid_request(id.as_ref(), "missing_method"));
    }

    let params = match obj.get("params") {
        None => Value::Object(serde_json::Map::new()),
        Some(p @ (Value::Object(_) | Value::Array(_))) => p.clone(),
        Some(_) => {
            return EnvelopeOutcome::Err(rpc::invalid_request(id.as_ref(), "bad_params"));
        }
    };

    EnvelopeOutcome::Ok(ParsedRequest {
        id,
        method: method.to_owned(),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn batch_array_is_32600() {
        let out = parse_envelope(br#"[{"jsonrpc":"2.0","id":1,"method":"helix.health"}]"#);
        match out {
            EnvelopeOutcome::Err(v) => {
                assert_eq!(v["error"]["code"], json!(-32600));
                assert_eq!(v["error"]["data"]["reason"], json!("batch_not_supported"));
            }
            EnvelopeOutcome::Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn parse_error_is_32700() {
        let out = parse_envelope(br"{not json");
        match out {
            EnvelopeOutcome::Err(v) => assert_eq!(v["error"]["code"], json!(-32700)),
            EnvelopeOutcome::Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn single_object_ok() {
        let out =
            parse_envelope(br#"{"jsonrpc":"2.0","id":"abc","method":"helix.health","params":{}}"#);
        match out {
            EnvelopeOutcome::Ok(p) => {
                assert_eq!(p.method, "helix.health");
                assert_eq!(p.id, Some(RpcId::String("abc".into())));
            }
            EnvelopeOutcome::Err(e) => panic!("unexpected {e}"),
        }
    }
}
