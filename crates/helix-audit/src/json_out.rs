//! JSON views for `helix-ctl audit dump` / `audit caps` (ADR-009 D.1).

use crate::naming::{encode_ulid_bytes, hex_encode};
use crate::record::{AuditRecord, ResourceUsage, Transition};
use minicbor::data::Type;
use minicbor::Decoder;
use serde_json::{json, Map, Number, Value as JsonValue};
use thiserror::Error;

/// One audit record as a JSON object (operator dump).
#[must_use]
pub fn record_to_json(rec: &AuditRecord) -> JsonValue {
    json!({
        "version": rec.version,
        "request_id": encode_ulid_bytes(&rec.request_id),
        "parent": rec.parent.as_ref().map(encode_ulid_bytes),
        "identity": hex_encode(&rec.identity),
        "digest": hex_encode(&rec.digest),
        "transition": transition_name(rec.transition),
        "reason": rec.reason,
        "caps_hash": rec.caps_hash.as_ref().map(|h| hex_encode(h)),
        "budget": rec.budget.map(usage_to_json),
        "usage": rec.usage.map(usage_to_json),
        "wall_time_ns": rec.wall_time_ns,
        "sequence": rec.sequence,
    })
}

fn usage_to_json(u: ResourceUsage) -> JsonValue {
    json!({
        "preempt_ticks": u.preempt_ticks,
        "wall_clock_ms": u.wall_clock_ms,
        "memory_bytes": u.memory_bytes,
        "output_bytes": u.output_bytes,
    })
}

#[must_use]
pub fn transition_name(t: Transition) -> &'static str {
    match t {
        Transition::Received => "Received",
        Transition::Authenticated => "Authenticated",
        Transition::AuthFailed => "AuthFailed",
        Transition::Authorized => "Authorized",
        Transition::Rejected => "Rejected",
        Transition::Denied => "Denied",
        Transition::DelegationRefused => "DelegationRefused",
        Transition::Granted => "Granted",
        Transition::Provisioned => "Provisioned",
        Transition::Running => "Running",
        Transition::Completed => "Completed",
        Transition::ToolError => "ToolError",
        Transition::Failed => "Failed",
        Transition::Killed => "Killed",
        Transition::Described => "Described",
    }
}

/// Decode caps side-file CBOR into JSON.
///
/// Prefers the real [`CapabilitySet`] schema via [`crate::caps::decode_capability_set`]
/// plus [`crate::caps::capability_set_to_json`]. Falls back to a generic CBOR walk
/// when the bytes are not a valid `CapabilitySet` encoding (legacy fixtures).
pub fn cbor_to_json(bytes: &[u8]) -> Result<JsonValue, JsonOutError> {
    if let Ok(set) = crate::caps::decode_capability_set(bytes) {
        return Ok(crate::caps::capability_set_to_json(&set));
    }
    cbor_to_json_generic(bytes)
}

/// Generic CBOR to JSON walk (fallback / non-`CapabilitySet` CBOR).
pub fn cbor_to_json_generic(bytes: &[u8]) -> Result<JsonValue, JsonOutError> {
    let mut d = Decoder::new(bytes);
    let v = decode_value(&mut d)?;
    if d.position() != bytes.len() {
        // Allow trailing zeros only if fully consumed; otherwise reject.
        // minicbor may leave position at end for a single top-level value.
        let rest = &bytes[d.position()..];
        if !rest.is_empty() {
            // Try whether decoder already finished a complete value — if extra
            // bytes remain that aren't whitespace (CBOR has none), error.
            return Err(JsonOutError::Trailing(rest.len()));
        }
    }
    Ok(v)
}

fn decode_value(d: &mut Decoder<'_>) -> Result<JsonValue, JsonOutError> {
    match d
        .datatype()
        .map_err(|e| JsonOutError::Decode(e.to_string()))?
    {
        Type::Bool => Ok(JsonValue::Bool(
            d.bool().map_err(|e| JsonOutError::Decode(e.to_string()))?,
        )),
        Type::Null | Type::Undefined => {
            d.skip().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(JsonValue::Null)
        }
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            let n = d.u64().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(JsonValue::Number(Number::from(n)))
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
            let n = d.i64().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(JsonValue::Number(Number::from(n)))
        }
        Type::F16 | Type::F32 | Type::F64 => {
            let n = d.f64().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Number::from_f64(n)
                .map(JsonValue::Number)
                .ok_or(JsonOutError::NonFiniteFloat)
        }
        Type::Bytes => {
            let b = d.bytes().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(JsonValue::String(hex_encode(b)))
        }
        Type::String => {
            let s = d.str().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(JsonValue::String(s.to_owned()))
        }
        Type::Array => {
            let n = d
                .array()
                .map_err(|e| JsonOutError::Decode(e.to_string()))?
                .ok_or(JsonOutError::Indefinite)?;
            let mut arr = Vec::with_capacity(usize::try_from(n).unwrap_or(usize::MAX));
            for _ in 0..n {
                arr.push(decode_value(d)?);
            }
            Ok(JsonValue::Array(arr))
        }
        Type::Map => {
            let n = d
                .map()
                .map_err(|e| JsonOutError::Decode(e.to_string()))?
                .ok_or(JsonOutError::Indefinite)?;
            let mut map = Map::new();
            for _ in 0..n {
                let key = map_key(d)?;
                let val = decode_value(d)?;
                map.insert(key, val);
            }
            Ok(JsonValue::Object(map))
        }
        Type::Tag => {
            let _tag = d.tag().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            decode_value(d)
        }
        other => Err(JsonOutError::Unsupported(format!("{other:?}"))),
    }
}

fn map_key(d: &mut Decoder<'_>) -> Result<String, JsonOutError> {
    match d
        .datatype()
        .map_err(|e| JsonOutError::Decode(e.to_string()))?
    {
        Type::String => Ok(d
            .str()
            .map_err(|e| JsonOutError::Decode(e.to_string()))?
            .to_owned()),
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            let n = d.u64().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(n.to_string())
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
            let n = d.i64().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(n.to_string())
        }
        Type::Bytes => {
            let b = d.bytes().map_err(|e| JsonOutError::Decode(e.to_string()))?;
            Ok(hex_encode(b))
        }
        other => Err(JsonOutError::Unsupported(format!("map key type {other:?}"))),
    }
}

#[derive(Debug, Error)]
pub enum JsonOutError {
    #[error("cbor decode: {0}")]
    Decode(String),
    #[error("indefinite-length CBOR rejected")]
    Indefinite,
    #[error("unsupported CBOR type: {0}")]
    Unsupported(String),
    #[error("non-finite float")]
    NonFiniteFloat,
    #[error("trailing {0} bytes after CBOR value")]
    Trailing(usize),
}
