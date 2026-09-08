//! Payload validation against a tool's registered `input-schema` (HLX-35 / M5-04).
//!
//! Pure entry point [`payload`] runs at Authenticated → Authorized, before any
//! instantiation. The same function is reused by `helix-runtime::delegate` for
//! child input (via [`helix_policy::input_schema`]).
//!
//! Failure maps to JSON-RPC `-32602` with `data.path` (JSON Pointer) and
//! `data.reason` — see [`invalid_params`].
//!
//! ## Schema library
//!
//! Hand-rolled Draft 2020-12 **subset** in [`helix_policy::input_schema`] because
//! `jsonschema` / `boon` are deny-blocked (`MIT-0`) and `valico` lacks 2020-12.
//! See that module's **HOLE** note for unsupported keywords.
//!
//! Cites: `HELIX_PRDv2.md` §5.2; `interfaces/gateway-protocol.md` §§3–4;
//! security-checklist A4; test-plan GW-5, GW-10.

use std::collections::HashMap;
use std::sync::Arc;

use helix_caps::ToolDigest;
use helix_policy::input_schema;
use serde_json::{json, Value};

use crate::rpc::{self, RpcCode, RpcId};

pub use helix_policy::input_schema::{PathError, Schema};

/// Validate `instance` bytes against `schema`.
///
/// # Errors
///
/// Returns [`PathError`] with a JSON Pointer `path` and `reason` on the first
/// violation (or when the instance is not JSON).
pub fn payload(schema: &Schema, instance: &[u8]) -> Result<(), PathError> {
    input_schema::validate(schema, instance)
}

/// Build a `-32602 Invalid params` envelope with `data.path` + `data.reason`
/// (and optional `request_id` once past `Received`).
#[must_use]
pub fn invalid_params(id: Option<&RpcId>, err: &PathError, request_id: Option<&str>) -> Value {
    let mut data = json!({
        "path": err.path,
        "reason": err.reason,
    });
    if let Some(rid) = request_id {
        data["request_id"] = Value::String(rid.to_owned());
    }
    rpc::error(id, RpcCode::InvalidParams, Some(data))
}

/// In-memory digest → compiled [`Schema`] map (from artifact-store signatures).
///
/// Populated at artifact load (HLX-24 signature cache) and consulted on the
/// invoke path before instantiation.
#[derive(Debug, Default, Clone)]
pub struct SchemaRegistry {
    by_digest: HashMap<[u8; 32], Arc<Schema>>,
}

impl SchemaRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert / replace the input-schema for `digest` (parsed from signature).
    ///
    /// # Errors
    ///
    /// Schema JSON parse failures.
    pub fn insert_raw(
        &mut self,
        digest: &ToolDigest,
        input_schema_json: &str,
    ) -> Result<(), PathError> {
        let schema = Schema::parse(input_schema_json)?;
        self.by_digest.insert(*digest.as_bytes(), Arc::new(schema));
        Ok(())
    }

    /// Insert a pre-parsed schema.
    pub fn insert(&mut self, digest: &ToolDigest, schema: Schema) {
        self.by_digest.insert(*digest.as_bytes(), Arc::new(schema));
    }

    /// Look up the schema for a tool digest.
    #[must_use]
    pub fn get(&self, digest: &ToolDigest) -> Option<Arc<Schema>> {
        self.by_digest.get(digest.as_bytes()).cloned()
    }

    /// Number of registered schemas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }
}

/// Fuzz entry (GW-10): never panics.
///
/// Layout: `[schema_len:u16 LE][schema bytes][instance bytes…]`. When the
/// length prefix is missing or short, a fixed object schema is used.
pub fn fuzz_payload_validator(data: &[u8]) {
    const DEFAULT_SCHEMA: &str = r#"{
        "type":"object",
        "properties":{
            "text":{"type":"string","minLength":1},
            "n":{"type":"integer","minimum":0},
            "tags":{"type":"array","items":{"type":"string"},"maxItems":8}
        },
        "required":["text"],
        "additionalProperties":false
    }"#;

    let (schema_src, instance) = if data.len() >= 2 {
        let n = u16::from_le_bytes([data[0], data[1]]) as usize;
        let rest = &data[2..];
        if n <= rest.len() {
            (
                std::str::from_utf8(&rest[..n]).unwrap_or(DEFAULT_SCHEMA),
                &rest[n..],
            )
        } else {
            (DEFAULT_SCHEMA, data)
        }
    } else {
        (DEFAULT_SCHEMA, data)
    };

    let Ok(schema) = Schema::parse(schema_src) else {
        return;
    };
    let _ = payload(&schema, instance);
}

/// Build a [`SchemaRegistry`] from `(digest, input_schema_json)` pairs (artifact
/// signature cache / HLX-24 load path).
///
/// # Errors
///
/// Returns the first schema parse failure.
pub fn registry_from_signatures<'a>(
    entries: impl IntoIterator<Item = (&'a ToolDigest, &'a str)>,
) -> Result<SchemaRegistry, PathError> {
    let mut reg = SchemaRegistry::new();
    for (digest, schema_json) in entries {
        reg.insert_raw(digest, schema_json)?;
    }
    Ok(reg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_caps::ToolDigest;

    #[test]
    fn gw5_path_and_rpc_shape() {
        let schema = Schema::parse(
            r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}"#,
        )
        .unwrap();
        let err = payload(&schema, br#"{"query":42}"#).unwrap_err();
        assert_eq!(err.path, "/query");
        let body = invalid_params(Some(&RpcId::String("1".into())), &err, Some("01TEST"));
        assert_eq!(body["error"]["code"], -32602);
        assert_eq!(body["error"]["data"]["path"], "/query");
        assert!(body["error"]["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("type"));
        assert_eq!(body["error"]["data"]["request_id"], "01TEST");
    }

    #[test]
    fn registry_roundtrip() {
        let digest = ToolDigest::from_bytes([7u8; 32]);
        let mut reg = SchemaRegistry::new();
        reg.insert_raw(
            &digest,
            r#"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
        )
        .unwrap();
        let schema = reg.get(&digest).unwrap();
        assert!(payload(&schema, br#"{"text":"ok"}"#).is_ok());
        assert!(payload(&schema, br"{}").is_err());
    }
}
