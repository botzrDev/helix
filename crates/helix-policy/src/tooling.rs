//! Operator tooling helpers for `helix-ctl policy` (policy-format.md §5).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use helix_caps::{CapabilitySet, ResourceBudget};
use serde::Serialize;

use crate::file::PolicyFile;
use crate::fs::StdFs;
use crate::ids::parse_tool_digest;
use crate::resolve::{resolve_host, PolicySnapshot};
use crate::store::{DirArtifactStore, MemoryArtifactStore};
use crate::validate::validate_structural;
use crate::PolicyError;

/// Which validation passes `policy check` ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckPasses {
    /// Structural only (`--artifacts` omitted).
    StructuralOnly,
    /// Structural + host resolve (`--artifacts <dir>`).
    StructuralAndHost,
}

/// One file or directory grant row printed by `policy check`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathGrantLine {
    /// `file` or `dir`.
    pub kind: &'static str,
    /// Absolute path (raw for structural; canonical for host).
    pub path: String,
    /// `read` or `read_write`.
    pub mode: String,
}

/// One `[[grants]]` listing for check output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantListing {
    /// Identity alias.
    pub identity: String,
    /// Tool alias.
    pub tool: String,
    /// File and directory grants (not expanded).
    pub paths: Vec<PathGrantLine>,
}

/// Successful `policy check` report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport {
    /// Passes that ran.
    pub passes: CheckPasses,
    /// Every file and dir grant across all `[[grants]]`.
    pub grants: Vec<GrantListing>,
    /// Host-pass warnings (empty in structural-only mode).
    pub warnings: Vec<String>,
}

impl CheckReport {
    /// Human-readable check output (stdout body).
    #[must_use]
    pub fn display_text(&self) -> String {
        let mut out = String::new();
        match self.passes {
            CheckPasses::StructuralOnly => {
                writeln!(out, "passes: structural").ok();
                writeln!(out, "mode: structural only").ok();
            }
            CheckPasses::StructuralAndHost => {
                writeln!(out, "passes: structural, host").ok();
                writeln!(out, "mode: structural + host").ok();
            }
        }
        writeln!(out, "status: ok").ok();
        if !self.warnings.is_empty() {
            writeln!(out, "warnings:").ok();
            for w in &self.warnings {
                writeln!(out, "  - {w}").ok();
            }
        }
        writeln!(out, "grants:").ok();
        if self.grants.is_empty() {
            writeln!(out, "  (none)").ok();
        }
        for g in &self.grants {
            writeln!(out, "  {} / {}", g.identity, g.tool).ok();
            if g.paths.is_empty() {
                writeln!(out, "    (no file or dir grants)").ok();
            }
            for p in &g.paths {
                writeln!(out, "    {}  {}  {}", p.kind, p.path, p.mode).ok();
            }
        }
        out
    }
}

/// Run `helix-ctl policy check` logic.
///
/// Always runs the structural pass. When `artifacts` is `Some`, also runs the
/// host resolve pass against [`DirArtifactStore`] + [`StdFs`].
///
/// # Errors
///
/// Parse / validation errors. Structural-only success never fails solely because
/// host paths or artifacts are missing.
pub fn check_policy(
    policy_path: &Path,
    artifacts: Option<&Path>,
) -> Result<CheckReport, Vec<PolicyError>> {
    let text = fs::read_to_string(policy_path).map_err(|e| {
        vec![PolicyError::Toml(format!(
            "read {}: {e}",
            policy_path.display()
        ))]
    })?;
    let file = PolicyFile::parse(&text).map_err(|e| vec![e])?;

    match artifacts {
        None => {
            validate_structural(&file)?;
            Ok(CheckReport {
                passes: CheckPasses::StructuralOnly,
                grants: listings_from_file(&file),
                warnings: Vec::new(),
            })
        }
        Some(dir) => {
            let store = DirArtifactStore::new(dir);
            let snapshot = resolve_host(&file, &store, &StdFs)?;
            Ok(CheckReport {
                passes: CheckPasses::StructuralAndHost,
                grants: listings_from_snapshot(&snapshot),
                warnings: snapshot.warnings().to_vec(),
            })
        }
    }
}

fn listings_from_file(file: &PolicyFile) -> Vec<GrantListing> {
    file.grants
        .iter()
        .map(|g| {
            let mut paths = Vec::new();
            for f in &g.files {
                paths.push(PathGrantLine {
                    kind: "file",
                    path: f.path.clone(),
                    mode: f.mode.clone(),
                });
            }
            for d in &g.dirs {
                paths.push(PathGrantLine {
                    kind: "dir",
                    path: d.path.clone(),
                    mode: d.mode.clone(),
                });
            }
            GrantListing {
                identity: g.identity.clone(),
                tool: g.tool.clone(),
                paths,
            }
        })
        .collect()
}

fn listings_from_snapshot(snapshot: &PolicySnapshot) -> Vec<GrantListing> {
    let mut grants: Vec<_> = snapshot.grants().collect();
    grants.sort_by(|a, b| {
        (a.identity_alias(), a.tool_alias()).cmp(&(b.identity_alias(), b.tool_alias()))
    });
    grants
        .into_iter()
        .map(|g| {
            let caps = g.caps();
            let intern = caps.interner();
            let mut paths = Vec::new();
            for f in caps.files() {
                paths.push(PathGrantLine {
                    kind: "file",
                    path: intern.path(f.path()).display().to_string(),
                    mode: mode_name(f.mode()),
                });
            }
            for d in caps.dirs() {
                paths.push(PathGrantLine {
                    kind: "dir",
                    path: intern.path(d.root()).display().to_string(),
                    mode: mode_name(d.mode()),
                });
            }
            GrantListing {
                identity: g.identity_alias().to_owned(),
                tool: g.tool_alias().to_owned(),
                paths,
            }
        })
        .collect()
}

fn mode_name(mode: helix_caps::FileMode) -> String {
    match mode {
        helix_caps::FileMode::Read => "read".to_owned(),
        helix_caps::FileMode::ReadWrite => "read_write".to_owned(),
    }
}

/// Wire JSON for `CapabilitySet` + sibling `budget` (gateway-protocol.md §5).
///
/// # Errors
///
/// JSON serialization failure (should not occur for well-formed sets).
pub fn caps_budget_wire_json(
    caps: &CapabilitySet,
    budget: &ResourceBudget,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Wire<'a> {
        #[serde(flatten)]
        caps: &'a CapabilitySet,
        budget: &'a ResourceBudget,
    }
    serde_json::to_string_pretty(&Wire { caps, budget })
}

/// Load a snapshot for `policy explain`.
///
/// When `artifacts` is omitted, digests from the file's `[tools]` table are
/// treated as present (explain-only). Host path checks still use [`StdFs`].
///
/// # Errors
///
/// Parse / host-resolve errors.
pub fn load_snapshot_for_explain(
    policy_path: &Path,
    artifacts: Option<&Path>,
) -> Result<PolicySnapshot, Vec<PolicyError>> {
    let text = fs::read_to_string(policy_path).map_err(|e| {
        vec![PolicyError::Toml(format!(
            "read {}: {e}",
            policy_path.display()
        ))]
    })?;
    let file = PolicyFile::parse(&text).map_err(|e| vec![e])?;
    if let Some(dir) = artifacts {
        resolve_host(&file, &DirArtifactStore::new(dir), &StdFs)
    } else {
        let mut store = MemoryArtifactStore::new();
        for (alias, digest_str) in &file.tools {
            if let Ok(d) = parse_tool_digest(alias, digest_str) {
                store = store.with_digest(d);
            }
        }
        resolve_host(&file, &store, &StdFs)
    }
}

/// Look up `(identity_alias, tool_alias)` and return wire JSON.
///
/// # Errors
///
/// Missing grant, or JSON encoding failure wrapped as a single [`PolicyError::Toml`].
pub fn explain_grant_json(
    snapshot: &PolicySnapshot,
    identity_alias: &str,
    tool_alias: &str,
) -> Result<String, PolicyError> {
    let identity =
        snapshot
            .identities()
            .get(identity_alias)
            .ok_or_else(|| PolicyError::UnknownIdentity {
                identity: identity_alias.to_owned(),
            })?;
    let digest =
        snapshot
            .tools()
            .get(tool_alias)
            .copied()
            .ok_or_else(|| PolicyError::UnknownTool {
                tool: tool_alias.to_owned(),
            })?;
    let (caps, budget) = snapshot.policy(identity, &digest).ok_or_else(|| {
        PolicyError::Toml(format!(
            "no grant for identity {identity_alias:?} tool {tool_alias:?}"
        ))
    })?;
    caps_budget_wire_json(caps, budget).map_err(|e| PolicyError::Toml(format!("json encode: {e}")))
}

/// Format validation errors for CLI stderr.
#[must_use]
pub fn format_policy_errors(errors: &[PolicyError]) -> String {
    let mut out = String::new();
    for e in errors {
        match e.rule() {
            Some(n) => writeln!(out, "error (rule {n}): {e}").ok(),
            None => writeln!(out, "error: {e}").ok(),
        };
    }
    out
}

/// Send `SIGHUP` to `pid` via the host `kill` binary (no `unsafe` in-process).
///
/// Runbook §4 does not name a pid source; callers pass `--pid`.
///
/// # Errors
///
/// `kill` failed to launch or returned non-zero.
pub fn send_sighup(pid: u32) -> Result<(), String> {
    let status = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .map_err(|e| format!("failed to spawn kill: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "kill -HUP {pid} exited {}",
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |c| c.to_string())
        ))
    }
}
