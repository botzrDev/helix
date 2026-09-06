//! HELIX author-facing SDK (`HELIX_PRD_v2` §5.4, M6-01 / HLX-38).
//!
//! - [`helix_tool`] — proc macro generating `signature` / `invoke` exports
//! - [`ToolError`] — maps to `invoke-error` / JSON-RPC `-32005`/`-32006`/`-32007`
//! - [`delegate`] — typed wrapper over `helix:delegate/invoke`

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use helix_sdk_macro::helix_tool;

mod error;
pub use error::ToolError;

pub mod types;
pub use types::{
    CapabilitySet, FileGrant, FileMode, HostGrant, KillCause, ResourceBudget, ResourceUsage,
    ToolRef,
};

mod delegate_api;

pub use delegate_api::{delegate, DelegateError, DelegationResult};

/// Namespace matching `tool-author-guide.md` §9 (`delegate::invoke`).
pub mod delegate {
    pub use crate::delegate_api::{delegate as invoke, DelegateError, DelegationResult};
}

#[doc(hidden)]
pub mod __wit {
    //! WIT world bindings (re-export for `#[helix_tool]`).
    pub use helix_sdk_wit::*;
}

#[doc(hidden)]
pub mod __private {
    //! Helpers for `#[helix_tool]` expansion.
    use schemars::JsonSchema;
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    pub use schemars;
    pub use serde;
    pub use serde_json;

    /// Pointed bound for tool input types (SDK-3).
    #[diagnostic::on_unimplemented(
        message = "#[helix_tool] input type `{Self}` must be Deserialize + JsonSchema (serde-serializable)",
        label = "this input type is not usable as a HELIX tool argument",
        note = "add `#[derive(serde::Deserialize, schemars::JsonSchema)]` (and ensure all fields are serializable)"
    )]
    pub trait HelixToolInput: DeserializeOwned + JsonSchema {}
    impl<T: DeserializeOwned + JsonSchema> HelixToolInput for T {}

    /// Pointed bound for tool output types (SDK-3).
    #[diagnostic::on_unimplemented(
        message = "#[helix_tool] output type `{Self}` must be Serialize + JsonSchema",
        label = "this output type is not usable as a HELIX tool result",
        note = "add `#[derive(serde::Serialize, schemars::JsonSchema)]`"
    )]
    pub trait HelixToolOutput: Serialize + JsonSchema {}
    impl<T: Serialize + JsonSchema> HelixToolOutput for T {}

    /// Build a root JSON Schema for `T` (schemars 1.x).
    #[must_use]
    pub fn schema_for<T: JsonSchema>() -> schemars::Schema {
        schemars::SchemaGenerator::default().into_root_schema_for::<T>()
    }
}
