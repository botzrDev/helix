//! Raw TOML shape ([`PolicyFile`]). No intern, no I/O.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::PolicyError;

const fn default_max_delegation_depth() -> u32 {
    2
}

const fn default_max_children() -> u32 {
    8
}

const fn default_max_concurrent_instances() -> u32 {
    32
}

/// Raw policy document as deserialized from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    /// Format version. Must be `1` (rule 1).
    pub version: u32,
    /// Alias → `sha256:<hex>` digest.
    #[serde(default)]
    pub tools: BTreeMap<String, String>,
    /// Named resource budgets.
    #[serde(default)]
    pub budgets: BTreeMap<String, BudgetTable>,
    /// Alias → RFC 7638 JWK thumbprint (base64url).
    #[serde(default)]
    pub identities: BTreeMap<String, String>,
    /// One grant per `(identity, tool)` (rule 4).
    #[serde(default)]
    pub grants: Vec<GrantTable>,
}

/// One `[budgets.<name>]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetTable {
    /// Guest preemption deadline in milliseconds. Absent → `wall_clock_ms`.
    pub preempt_ticks: Option<u32>,
    /// Hard deadline including host calls, in milliseconds.
    pub wall_clock_ms: u32,
    /// Linear memory ceiling in bytes.
    pub memory_bytes: u64,
    /// Maximum result size returned to the caller.
    pub output_bytes: u32,
    /// Depth counted from the root request. Default 2.
    #[serde(default = "default_max_delegation_depth")]
    pub max_delegation_depth: u32,
    /// Fan-out per parent. Default 8.
    #[serde(default = "default_max_children")]
    pub max_children: u32,
    /// Live instances for one identity on one gateway. Default 32.
    #[serde(default = "default_max_concurrent_instances")]
    pub max_concurrent_instances: u32,
}

/// One `[[grants]]` entry. Pins both alias and digest (rule 10).
#[derive(Debug, Clone, Deserialize)]
pub struct GrantTable {
    /// Identity alias; must be a key in `[identities]`.
    pub identity: String,
    /// Tool alias; must be a key in `[tools]`.
    pub tool: String,
    /// Digest; must equal `[tools.<alias>]`.
    pub digest: Option<String>,
    /// Interface names (`stdio`, `clocks`, `random`, `filesystem`, `http_outbound`).
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Budget table name.
    pub budget: String,
    /// Regular-file grants.
    #[serde(default)]
    pub files: Vec<FileGrantTable>,
    /// Directory grants (not expanded; ADR-008 A.2).
    #[serde(default)]
    pub dirs: Vec<DirGrantTable>,
    /// Outbound HTTP grants.
    #[serde(default)]
    pub hosts: Vec<HostGrantTable>,
}

/// One `files[]` row.
#[derive(Debug, Clone, Deserialize)]
pub struct FileGrantTable {
    /// Host path. Must be absolute and canonicalize to a regular file (rule 5).
    pub path: String,
    /// `read` or `read_write`.
    pub mode: String,
}

/// One `dirs[]` row.
#[derive(Debug, Clone, Deserialize)]
pub struct DirGrantTable {
    /// Host path. Must be absolute and canonicalize to a directory (rule 5).
    pub path: String,
    /// `read` or `read_write`.
    pub mode: String,
}

/// One `hosts[]` row.
#[derive(Debug, Clone, Deserialize)]
pub struct HostGrantTable {
    /// Lowercase `host:port` with an explicit port (rule 7).
    pub authority: String,
    /// `GET` / `HEAD` / `POST` / `PUT` / `PATCH` / `DELETE` (rule 9).
    #[serde(default)]
    pub methods: Vec<String>,
}

impl PolicyFile {
    /// Parse a TOML document into the raw file shape. Does not validate rules.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Toml`] when the document is not a valid `PolicyFile`.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        toml::from_str(text).map_err(|e| PolicyError::Toml(e.to_string()))
    }
}
