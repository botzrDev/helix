//! Read the component `signature` export (registration / load).

use wasmtime::component::{ComponentType, Lift, Lower};
use wasmtime::{Engine, Store};

use crate::error::RuntimeError;
use crate::pool::PooledPre;

/// WIT `tool-signature` record fields used by Helix.
#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub struct ToolSignatureRecord {
    /// Tool name (becomes the policy alias suggestion).
    pub name: String,
    /// Tool version string.
    pub version: String,
    /// JSON Schema for inputs.
    #[component(name = "input-schema")]
    pub input_schema: String,
    /// JSON Schema for outputs.
    #[component(name = "output-schema")]
    pub output_schema: String,
}

/// Public signature info (no wasmtime derives on the API type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSignatureInfo {
    /// Alias / name from `signature`.
    pub name: String,
    /// Version from `signature`.
    pub version: String,
    /// Input JSON Schema.
    pub input_schema: String,
    /// Output JSON Schema.
    pub output_schema: String,
}

impl From<ToolSignatureRecord> for ToolSignatureInfo {
    fn from(r: ToolSignatureRecord) -> Self {
        Self {
            name: r.name,
            version: r.version,
            input_schema: r.input_schema,
            output_schema: r.output_schema,
        }
    }
}

/// Instantiate from `pre` (M4-01 template) and call `signature`.
///
/// # Errors
///
/// Instantiation or typed-call failures.
pub fn read_signature(engine: &Engine, pre: &PooledPre) -> Result<ToolSignatureInfo, RuntimeError> {
    let mut store = Store::new(engine, ());
    // Signature is pure and fast; generous deadline.
    store.set_epoch_deadline(u64::from(u32::MAX));
    let start = std::time::Instant::now();
    let instance = pre
        .inner()
        .instantiate(&mut store)
        .map_err(RuntimeError::from)?;
    metrics::histogram!(crate::METRIC_INSTANTIATE_SECONDS).record(start.elapsed().as_secs_f64());

    let typed = instance
        .get_typed_func::<(), (ToolSignatureRecord,)>(&mut store, "signature")
        .map_err(RuntimeError::from)?;
    let (record,) = typed.call(&mut store, ()).map_err(RuntimeError::from)?;
    typed.post_return(&mut store).map_err(RuntimeError::from)?;
    Ok(record.into())
}
