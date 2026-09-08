//! Draft 2020-12–oriented payload validation (HLX-35 / M5-04).
//!
//! Pure: no I/O. Validates JSON instance bytes against a tool `input-schema`.
//!
//! ## License / crate choice
//!
//! The `jsonschema` crate (and `boon`) pull `MIT-0` via `borrow-or-share`, which
//! `deny.toml` rejects. `valico` is license-clean but stops at Draft 2019-09.
//! Helix therefore ships a **hand-rolled subset** sufficient for schemars-style
//! tool signatures (objects, properties, required, additionalProperties, items /
//! prefixItems, type, enum, const, numeric/string bounds, combinators, local
//! `$ref` / `$defs`).
//!
//! ## HOLE
//!
//! Not a full Draft 2020-12 implementation. Unsupported / ignored keywords
//! include: `pattern`, `format`, `patternProperties`, `dependentSchemas`,
//! `dependentRequired`, `unevaluatedProperties` / `unevaluatedItems`,
//! `contentEncoding` / `contentMediaType`, remote `$ref`, `$dynamicRef`,
//! `if`/`then`/`else`, and vocabulary / annotation-only keywords. Schemas that
//! rely on those for security-sensitive constraints are a residual risk until a
//! deny-compatible full validator lands (or `MIT-0` is allow-listed).
//!
//! Cites: `HELIX_PRDv2.md` §5.2 / §5.4; `interfaces/gateway-protocol.md` §3;
//! security-checklist A4.

use serde_json::{Map, Number, Value};
use thiserror::Error;

/// Parsed JSON Schema document (typically a tool `input-schema` string).
#[derive(Debug, Clone, PartialEq)]
pub struct Schema {
    root: Value,
}

impl Schema {
    /// Parse a JSON Schema document from a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] with path `""` when the schema is not valid JSON.
    pub fn parse(schema_json: &str) -> Result<Self, PathError> {
        let root: Value = serde_json::from_str(schema_json).map_err(|e| PathError {
            path: String::new(),
            reason: format!("schema is not JSON: {e}"),
        })?;
        Ok(Self { root })
    }

    /// Wrap an already-parsed schema value.
    #[must_use]
    pub fn from_value(root: Value) -> Self {
        Self { root }
    }

    /// Borrow the root schema value.
    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.root
    }
}

/// Schema violation with a JSON Pointer (`data.path`) and human reason.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{path}: {reason}")]
pub struct PathError {
    /// JSON Pointer to the offending instance location (RFC 6901). Empty string
    /// means the document root.
    pub path: String,
    /// Short machine-oriented reason (type mismatch, required, etc.).
    pub reason: String,
}

impl PathError {
    fn at(path: &Pointer, reason: impl Into<String>) -> Self {
        Self {
            path: path.as_str(),
            reason: reason.into(),
        }
    }
}

/// Validate `instance` bytes as JSON against `schema`.
///
/// # Errors
///
/// - Non-JSON instance → path `""`, reason mentions parse failure.
/// - Schema violation → first failing pointer + reason.
pub fn validate(schema: &Schema, instance: &[u8]) -> Result<(), PathError> {
    let value: Value = serde_json::from_slice(instance).map_err(|e| PathError {
        path: String::new(),
        reason: format!("instance is not JSON: {e}"),
    })?;
    let mut path = Pointer::new();
    apply(&schema.root, &schema.root, &value, &mut path)
}

/// JSON Pointer builder (RFC 6901).
#[derive(Debug, Default)]
struct Pointer {
    segments: Vec<String>,
}

impl Pointer {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    fn push(&mut self, raw: &str) {
        self.segments.push(escape_pointer_token(raw));
    }

    fn pop(&mut self) {
        self.segments.pop();
    }

    fn as_str(&self) -> String {
        if self.segments.is_empty() {
            String::new()
        } else {
            format!("/{}", self.segments.join("/"))
        }
    }
}

fn escape_pointer_token(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

fn apply(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &mut Pointer,
) -> Result<(), PathError> {
    let schema = resolve_ref(root, schema, path)?;

    // boolean schemas
    match schema {
        Value::Bool(true) => return Ok(()),
        Value::Bool(false) => {
            return Err(PathError::at(path, "false schema rejects all values"));
        }
        Value::Object(_) => {}
        _ => {
            return Err(PathError::at(path, "schema must be a boolean or object"));
        }
    }

    if let Some(c) = schema.get("const") {
        if instance != c {
            return Err(PathError::at(path, "const mismatch"));
        }
    }

    if let Some(Value::Array(opts)) = schema.get("enum") {
        if !opts.iter().any(|o| o == instance) {
            return Err(PathError::at(path, "value not in enum"));
        }
    }

    check_type(schema, instance, path)?;

    // combinators
    if let Some(Value::Array(all)) = schema.get("allOf") {
        for sub in all {
            apply(root, sub, instance, path)?;
        }
    }
    if let Some(Value::Array(any)) = schema.get("anyOf") {
        if !any.is_empty() {
            let mut last = None;
            let mut ok = false;
            for sub in any {
                match apply(root, sub, instance, path) {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => last = Some(e),
                }
            }
            if !ok {
                return Err(last.unwrap_or_else(|| PathError::at(path, "anyOf failed")));
            }
        }
    }
    if let Some(Value::Array(one)) = schema.get("oneOf") {
        let mut matched = 0;
        for sub in one {
            if apply(root, sub, instance, path).is_ok() {
                matched += 1;
            }
        }
        if matched != 1 {
            return Err(PathError::at(
                path,
                format!("oneOf matched {matched} schemas, expected 1"),
            ));
        }
    }
    if let Some(not_schema) = schema.get("not") {
        if apply(root, not_schema, instance, path).is_ok() {
            return Err(PathError::at(
                path,
                "not: instance matched forbidden schema",
            ));
        }
    }

    match instance {
        Value::Object(map) => apply_object(root, schema, map, path)?,
        Value::Array(items) => apply_array(root, schema, items, path)?,
        Value::String(s) => apply_string(schema, s, path)?,
        Value::Number(n) => apply_number(schema, n, path)?,
        Value::Bool(_) | Value::Null => {}
    }

    Ok(())
}

fn resolve_ref<'a>(
    root: &'a Value,
    schema: &'a Value,
    path: &Pointer,
) -> Result<&'a Value, PathError> {
    let Some(Value::String(r)) = schema.get("$ref") else {
        return Ok(schema);
    };
    // Local refs only: "#/..." or "#/$defs/..."
    if !r.starts_with('#') {
        return Err(PathError::at(
            path,
            format!("remote $ref not supported: {r}"),
        ));
    }
    if r == "#" {
        return Ok(root);
    }
    let Some(ptr) = r.strip_prefix('#') else {
        return Err(PathError::at(path, format!("invalid $ref: {r}")));
    };
    follow_pointer(root, ptr).ok_or_else(|| PathError::at(path, format!("$ref not found: {r}")))
}

fn follow_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(root);
    }
    let pointer = pointer.strip_prefix('/')?;
    let mut cur = root;
    for raw in pointer.split('/') {
        let token = unescape_pointer_token(raw);
        cur = match cur {
            Value::Object(m) => m.get(&token)?,
            Value::Array(a) => {
                let idx: usize = token.parse().ok()?;
                a.get(idx)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

fn unescape_pointer_token(s: &str) -> String {
    s.replace("~1", "/").replace("~0", "~")
}

fn check_type(schema: &Value, instance: &Value, path: &Pointer) -> Result<(), PathError> {
    let Some(ty) = schema.get("type") else {
        return Ok(());
    };
    let ok = match ty {
        Value::String(s) => type_matches(s, instance),
        Value::Array(arr) => arr
            .iter()
            .filter_map(Value::as_str)
            .any(|s| type_matches(s, instance)),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(PathError::at(
            path,
            format!("type mismatch: expected {ty}, got {}", type_name(instance)),
        ))
    }
}

fn type_matches(ty: &str, instance: &Value) -> bool {
    match ty {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "number" => instance.is_number(),
        "integer" => {
            instance.as_i64().is_some()
                || instance.as_u64().is_some()
                || instance
                    .as_f64()
                    .is_some_and(|f| f.fract() == 0.0 && f.is_finite())
        }
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        _ => true,
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn apply_object(
    root: &Value,
    schema: &Value,
    map: &Map<String, Value>,
    path: &mut Pointer,
) -> Result<(), PathError> {
    if let Some(Value::Array(req)) = schema.get("required") {
        for key in req.iter().filter_map(Value::as_str) {
            if !map.contains_key(key) {
                path.push(key);
                let err = PathError::at(path, format!("missing required property '{key}'"));
                path.pop();
                return Err(err);
            }
        }
    }

    let props = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");

    for (key, value) in map {
        path.push(key);
        if let Some(prop_schema) = props.and_then(|p| p.get(key)) {
            apply(root, prop_schema, value, path)?;
        } else {
            match additional {
                None | Some(Value::Bool(true)) => {}
                Some(Value::Bool(false)) => {
                    let err = PathError::at(path, "additional properties not allowed");
                    path.pop();
                    return Err(err);
                }
                Some(sub) => apply(root, sub, value, path)?,
            }
        }
        path.pop();
    }

    if let Some(names_schema) = schema.get("propertyNames") {
        for key in map.keys() {
            path.push(key);
            let name_val = Value::String(key.clone());
            apply(root, names_schema, &name_val, path)?;
            path.pop();
        }
    }

    if let Some(m) = schema.get("minProperties").and_then(Value::as_u64) {
        if (map.len() as u64) < m {
            return Err(PathError::at(
                path,
                format!("minProperties: have {}, need {m}", map.len()),
            ));
        }
    }
    if let Some(m) = schema.get("maxProperties").and_then(Value::as_u64) {
        if (map.len() as u64) > m {
            return Err(PathError::at(
                path,
                format!("maxProperties: have {}, max {m}", map.len()),
            ));
        }
    }

    Ok(())
}

fn apply_array(
    root: &Value,
    schema: &Value,
    items: &[Value],
    path: &mut Pointer,
) -> Result<(), PathError> {
    if let Some(m) = schema.get("minItems").and_then(Value::as_u64) {
        if (items.len() as u64) < m {
            return Err(PathError::at(
                path,
                format!("minItems: have {}, need {m}", items.len()),
            ));
        }
    }
    if let Some(m) = schema.get("maxItems").and_then(Value::as_u64) {
        if (items.len() as u64) > m {
            return Err(PathError::at(
                path,
                format!("maxItems: have {}, max {m}", items.len()),
            ));
        }
    }
    if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
        for i in 0..items.len() {
            for j in (i + 1)..items.len() {
                if items[i] == items[j] {
                    return Err(PathError::at(path, "uniqueItems violated"));
                }
            }
        }
    }

    // Draft 2020-12: prefixItems then items (schema for remaining)
    let prefix = schema
        .get("prefixItems")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);

    // Draft 2020-12 items (schema) vs legacy draft-07 tuple (array of schemas).
    let items_kw = schema.get("items");
    let legacy_tuple = if schema.get("prefixItems").is_none() {
        items_kw.and_then(Value::as_array).map(Vec::as_slice)
    } else {
        None
    };
    let items_schema = match items_kw {
        Some(Value::Object(_) | Value::Bool(_)) => items_kw,
        _ => None,
    };

    for (i, item) in items.iter().enumerate() {
        path.push(&i.to_string());
        if i < prefix.len() {
            apply(root, &prefix[i], item, path)?;
        } else if let Some(tuple) = legacy_tuple {
            if i < tuple.len() {
                apply(root, &tuple[i], item, path)?;
            }
        } else {
            match items_schema {
                None | Some(Value::Bool(true)) => {}
                Some(Value::Bool(false)) => {
                    let err = PathError::at(path, "items beyond prefixItems not allowed");
                    path.pop();
                    return Err(err);
                }
                Some(sub) => apply(root, sub, item, path)?,
            }
        }
        path.pop();
    }

    Ok(())
}

fn apply_string(schema: &Value, s: &str, path: &Pointer) -> Result<(), PathError> {
    let len = s.chars().count() as u64;
    if let Some(m) = schema.get("minLength").and_then(Value::as_u64) {
        if len < m {
            return Err(PathError::at(
                path,
                format!("minLength: have {len}, need {m}"),
            ));
        }
    }
    if let Some(m) = schema.get("maxLength").and_then(Value::as_u64) {
        if len > m {
            return Err(PathError::at(
                path,
                format!("maxLength: have {len}, max {m}"),
            ));
        }
    }
    // pattern / format: HOLE (see module docs)
    let _ = schema.get("pattern");
    let _ = schema.get("format");
    Ok(())
}

fn apply_number(schema: &Value, n: &Number, path: &Pointer) -> Result<(), PathError> {
    let f = n
        .as_f64()
        .ok_or_else(|| PathError::at(path, "non-finite number"))?;

    if let Some(m) = schema.get("minimum").and_then(Value::as_f64) {
        if f < m {
            return Err(PathError::at(path, format!("minimum {m}")));
        }
    }
    if let Some(m) = schema.get("maximum").and_then(Value::as_f64) {
        if f > m {
            return Err(PathError::at(path, format!("maximum {m}")));
        }
    }
    if let Some(m) = schema.get("exclusiveMinimum").and_then(Value::as_f64) {
        if f <= m {
            return Err(PathError::at(path, format!("exclusiveMinimum {m}")));
        }
    }
    if let Some(m) = schema.get("exclusiveMaximum").and_then(Value::as_f64) {
        if f >= m {
            return Err(PathError::at(path, format!("exclusiveMaximum {m}")));
        }
    }
    if let Some(m) = schema.get("multipleOf").and_then(Value::as_f64) {
        if m != 0.0 {
            let q = f / m;
            if (q - q.round()).abs() > 1e-10 {
                return Err(PathError::at(path, format!("multipleOf {m}")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sch(v: Value) -> Schema {
        Schema::from_value(v)
    }

    #[test]
    fn type_and_required_path() {
        let schema = sch(json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        }));
        validate(&schema, br#"{"text":"hi"}"#).unwrap();
        let e = validate(&schema, br#"{"text":1}"#).unwrap_err();
        assert_eq!(e.path, "/text");
        let e = validate(&schema, br"{}").unwrap_err();
        assert_eq!(e.path, "/text");
    }

    #[test]
    fn additional_properties_false() {
        let schema = sch(json!({
            "type": "object",
            "properties": { "a": { "type": "number" } },
            "additionalProperties": false
        }));
        let e = validate(&schema, br#"{"a":1,"b":2}"#).unwrap_err();
        assert_eq!(e.path, "/b");
    }

    #[test]
    fn local_ref_defs() {
        let schema = sch(json!({
            "type": "object",
            "properties": {
                "n": { "$ref": "#/$defs/Name" }
            },
            "required": ["n"],
            "$defs": {
                "Name": { "type": "string", "minLength": 1 }
            }
        }));
        validate(&schema, br#"{"n":"x"}"#).unwrap();
        let e = validate(&schema, br#"{"n":""}"#).unwrap_err();
        assert_eq!(e.path, "/n");
    }

    #[test]
    fn nested_pointer() {
        let schema = sch(json!({
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": { "inner": { "type": "boolean" } },
                    "required": ["inner"]
                }
            },
            "required": ["outer"]
        }));
        let e = validate(&schema, br#"{"outer":{"inner":"no"}}"#).unwrap_err();
        assert_eq!(e.path, "/outer/inner");
    }
}
