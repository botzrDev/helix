//! Fatal policy-load errors. Numbered variants match `policy-format.md` §2.

use std::path::PathBuf;

/// Fatal validation or parse error. All twelve rules are represented.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// TOML syntax or type error (not a numbered rule).
    #[error("invalid TOML: {0}")]
    Toml(String),
    /// Rule 1: `version` must be `1`.
    #[error("rule 1: version must be 1, got {got}")]
    Version {
        /// Observed version.
        got: u32,
    },
    /// Rule 2: `[tools]` digest is not in the artifact store.
    #[error("rule 2: artifact digest not in store: {alias} = {digest}")]
    MissingArtifact {
        /// Tool alias.
        alias: String,
        /// Digest string from the file.
        digest: String,
    },
    /// Rule 3: `grants[].identity` is not a key in `[identities]`.
    #[error("rule 3: grant identity {identity:?} is not in [identities]")]
    UnknownIdentity {
        /// Grant identity alias.
        identity: String,
    },
    /// Rule 3: `grants[].tool` is not a key in `[tools]`.
    #[error("rule 3: grant tool {tool:?} is not in [tools]")]
    UnknownTool {
        /// Grant tool alias.
        tool: String,
    },
    /// Rule 4: `(identity, tool)` pair is not unique.
    #[error("rule 4: duplicate grant ({identity}, {tool})")]
    DuplicateGrant {
        /// Identity alias.
        identity: String,
        /// Tool alias.
        tool: String,
    },
    /// Rule 5: path is not absolute.
    #[error("rule 5: path is not absolute: {0}")]
    PathNotAbsolute(PathBuf),
    /// Rule 5: a symlink component at a granted path.
    #[error("rule 5: symlink at granted path: {0}")]
    Symlink(PathBuf),
    /// Rule 5: canonicalize failed.
    #[error("rule 5: path does not canonicalize: {path}: {reason}")]
    NotCanonical {
        /// Original path.
        path: PathBuf,
        /// Host error.
        reason: String,
    },
    /// Rule 5: `files[].path` did not resolve to a regular file.
    #[error("rule 5: expected regular file at {0}")]
    NotFile(PathBuf),
    /// Rule 5: `dirs[].path` did not resolve to a directory.
    #[error("rule 5: expected directory at {0}")]
    NotDirectory(PathBuf),
    /// Rule 6: `files` or `dirs` non-empty without `filesystem`.
    #[error("rule 6: files/dirs require filesystem interface (grant {identity}/{tool})")]
    FilesystemRequired {
        /// Identity alias.
        identity: String,
        /// Tool alias.
        tool: String,
    },
    /// Rule 6: `hosts` non-empty without `http_outbound`.
    #[error("rule 6: hosts require http_outbound interface (grant {identity}/{tool})")]
    HttpOutboundRequired {
        /// Identity alias.
        identity: String,
        /// Tool alias.
        tool: String,
    },
    /// Rule 7: authority is not lowercase `host:port` with an explicit port.
    #[error("rule 7: authority must be lowercase host:port with explicit port: {0}")]
    Authority(String),
    /// Rule 8: referenced budget name is missing from `[budgets]`.
    #[error("rule 8: budget {name:?} does not exist")]
    UnknownBudget {
        /// Budget table name.
        name: String,
    },
    /// Rule 9: method is not one of the six defined names.
    #[error("rule 9: unknown HTTP method {0:?}")]
    UnknownMethod(String),
    /// Rule 10: grant is missing `digest`.
    #[error("rule 10: grant for {tool} is missing digest")]
    MissingGrantDigest {
        /// Tool alias.
        tool: String,
    },
    /// Rule 10: grant digest disagrees with `[tools]` for the alias.
    #[error("rule 10: grant digest {grant} != [tools.{alias}] {alias_digest}")]
    DigestMismatch {
        /// Tool alias.
        alias: String,
        /// Digest on the grant.
        grant: String,
        /// Digest in `[tools]`.
        alias_digest: String,
    },
    /// Rule 11: `preempt_ticks` exceeds `wall_clock_ms`.
    #[error("rule 11: preempt_ticks {preempt} exceeds wall_clock_ms {wall} (budget {budget})")]
    PreemptTicks {
        /// Budget name.
        budget: String,
        /// Explicit preempt ticks.
        preempt: u32,
        /// Wall clock milliseconds.
        wall: u32,
    },
    /// Rule 12: `max_concurrent_instances` is less than 1.
    #[error("rule 12: max_concurrent_instances must be at least 1 (budget {budget})")]
    ConcurrentInstances {
        /// Budget name.
        budget: String,
    },
    /// Identity value is not a 32-byte base64url thumbprint (ADR-008 B.1).
    #[error("malformed identity thumbprint {name}: {reason}")]
    BadIdentity {
        /// Identity alias.
        name: String,
        /// Parse reason.
        reason: String,
    },
    /// Tool value is not `sha256:` plus 64 hex chars.
    #[error("malformed tool digest {alias}: {reason}")]
    BadDigest {
        /// Tool alias.
        alias: String,
        /// Parse reason.
        reason: String,
    },
    /// Interface name is not one of the five defined variants.
    #[error("unknown interface {0:?}")]
    UnknownInterface(String),
    /// File/dir mode is not `read` or `read_write`.
    #[error("unknown file mode {0:?}")]
    UnknownMode(String),
    /// `CapabilitySet::new` rejected the interned grant.
    #[error("capability construction: {0}")]
    Caps(String),
}

impl PolicyError {
    /// Numbered rule this error represents, if any.
    #[must_use]
    pub const fn rule(&self) -> Option<u8> {
        match self {
            Self::Version { .. } => Some(1),
            Self::MissingArtifact { .. } => Some(2),
            Self::UnknownIdentity { .. } | Self::UnknownTool { .. } => Some(3),
            Self::DuplicateGrant { .. } => Some(4),
            Self::PathNotAbsolute(_)
            | Self::Symlink(_)
            | Self::NotCanonical { .. }
            | Self::NotFile(_)
            | Self::NotDirectory(_) => Some(5),
            Self::FilesystemRequired { .. } | Self::HttpOutboundRequired { .. } => Some(6),
            Self::Authority(_) => Some(7),
            Self::UnknownBudget { .. } => Some(8),
            Self::UnknownMethod(_) => Some(9),
            Self::MissingGrantDigest { .. } | Self::DigestMismatch { .. } => Some(10),
            Self::PreemptTicks { .. } => Some(11),
            Self::ConcurrentInstances { .. } => Some(12),
            Self::Toml(_)
            | Self::BadIdentity { .. }
            | Self::BadDigest { .. }
            | Self::UnknownInterface(_)
            | Self::UnknownMode(_)
            | Self::Caps(_) => None,
        }
    }
}
