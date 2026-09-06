//! JSON-RPC 2.0 response helpers and standard error codes.
//!
//! Cites: `interfaces/gateway-protocol.md` §4.

use serde_json::{json, Value};

/// JSON-RPC 2.0 error codes used by the gateway envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RpcCode {
    /// Malformed JSON.
    ParseError = -32700,
    /// Invalid request (including batch arrays).
    InvalidRequest = -32600,
    /// Unknown method.
    MethodNotFound = -32601,
    /// Invalid params.
    InvalidParams = -32602,
    /// Auth failure (HLX-33 / HLX-34).
    Unauthenticated = -32001,
    /// Policy denial.
    Denied = -32002,
    /// Unknown / ungranted tool.
    UnknownTool = -32003,
    /// Provision failed / pipeline not wired.
    ProvisionFailed = -32004,
}

impl RpcCode {
    /// Numeric JSON-RPC code.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Spec message string.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::Unauthenticated => "Unauthenticated",
            Self::Denied => "Denied",
            Self::UnknownTool => "Unknown tool",
            Self::ProvisionFailed => "Provision failed",
        }
    }
}

/// JSON-RPC request id: string, number, or null (notifications omit id entirely).
#[derive(Clone, Debug, PartialEq)]
pub enum RpcId {
    /// JSON string id.
    String(String),
    /// JSON number id (stored as `serde_json::Number` string form via Value).
    Number(serde_json::Number),
    /// Explicit JSON null.
    Null,
}

impl RpcId {
    /// Convert to a [`Value`] for responses.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::String(s) => Value::String(s.clone()),
            Self::Number(n) => Value::Number(n.clone()),
            Self::Null => Value::Null,
        }
    }

    /// Parse from a JSON value. Rejects bools/objects/arrays.
    #[must_use]
    pub fn from_value(v: &Value) -> Option<Self> {
        match v {
            Value::String(s) => Some(Self::String(s.clone())),
            Value::Number(n) => Some(Self::Number(n.clone())),
            Value::Null => Some(Self::Null),
            _ => None,
        }
    }
}

/// Build a JSON-RPC 2.0 success envelope.
#[must_use]
pub fn success(id: Option<&RpcId>, result: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.map_or(Value::Null, RpcId::to_value),
        "result": result,
    })
}

/// Build a JSON-RPC 2.0 error envelope.
#[must_use]
pub fn error(id: Option<&RpcId>, code: RpcCode, data: Option<Value>) -> Value {
    let mut err = json!({
        "code": code.as_i32(),
        "message": code.message(),
    });
    if let Some(data) = data {
        err["data"] = data;
    }
    json!({
        "jsonrpc": "2.0",
        "id": id.map_or(Value::Null, RpcId::to_value),
        "error": err,
    })
}

/// Convenience: `-32600` with a `reason` string in `data`.
#[must_use]
pub fn invalid_request(id: Option<&RpcId>, reason: &str) -> Value {
    error(
        id,
        RpcCode::InvalidRequest,
        Some(json!({ "reason": reason })),
    )
}
