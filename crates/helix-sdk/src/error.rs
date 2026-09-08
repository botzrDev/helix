//! Tool-facing errors and JSON-RPC code mapping.

use helix_sdk_wit::InvokeError;

/// Errors a HELIX tool may return from an `#[helix_tool]` function.
///
/// Host mapping to JSON-RPC (see `interfaces/gateway-protocol.md` §4 and
/// `tool-author-guide.md` §3):
///
/// | Variant | `invoke-error` | JSON-RPC |
/// |---|---|---|
/// | [`InvalidInput`](Self::InvalidInput) | `invalid-input` | `-32005` |
/// | [`CapabilityDenied`](Self::CapabilityDenied) | `capability-denied` | `-32006` |
/// | [`Internal`](Self::Internal) | `internal` | `-32007` (message logged, not returned verbatim) |
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolError {
    /// Domain validation failed after the host already checked shape against `signature`.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The tool attempted an operation and the host refused it. Do not retry.
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    /// Anything else. Surfaced to the caller as `-32007` without the message body.
    #[error("internal: {0}")]
    Internal(String),
}

impl ToolError {
    /// JSON-RPC error code the gateway emits for this variant (`-32005` / `-32006` / `-32007`).
    #[must_use]
    pub const fn json_rpc_code(&self) -> i32 {
        match self {
            Self::InvalidInput(_) => -32005,
            Self::CapabilityDenied(_) => -32006,
            Self::Internal(_) => -32007,
        }
    }

    /// WIT `invoke-error` discriminant string (`invalid-input`, `capability-denied`, `internal`).
    #[must_use]
    pub const fn invoke_error_kind(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "invalid-input",
            Self::CapabilityDenied(_) => "capability-denied",
            Self::Internal(_) => "internal",
        }
    }

    /// Convert into the WIT `invoke-error` used by the generated `invoke` export.
    #[must_use]
    pub fn into_invoke_error(self) -> InvokeError {
        match self {
            Self::InvalidInput(msg) => InvokeError::InvalidInput(msg),
            Self::CapabilityDenied(msg) => InvokeError::CapabilityDenied(msg),
            Self::Internal(msg) => InvokeError::Internal(msg),
        }
    }
}

impl From<ToolError> for InvokeError {
    fn from(value: ToolError) -> Self {
        value.into_invoke_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_maps_to_documented_json_rpc_codes() {
        assert_eq!(ToolError::InvalidInput("x".into()).json_rpc_code(), -32005);
        assert_eq!(
            ToolError::CapabilityDenied("x".into()).json_rpc_code(),
            -32006
        );
        assert_eq!(ToolError::Internal("x".into()).json_rpc_code(), -32007);
    }
}
