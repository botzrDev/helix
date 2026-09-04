//! `helix-ctl tool register` / `reregister-all` logic.

use std::fs;
use std::path::Path;

use helix_caps::ToolDigest;
use wasmtime::Engine;

use crate::artifact::{
    artifact_paths, build_instance_pre, digest_hex, ensure_artifact_dir, write_artifact,
};
use crate::error::RuntimeError;
use crate::signature::{read_signature, ToolSignatureInfo};

/// Outcome of registering one wasm component.
#[derive(Debug, Clone)]
pub struct RegisterOutcome {
    /// Content digest.
    pub digest: ToolDigest,
    /// Compile wall time in milliseconds.
    pub compile_ms: u128,
    /// Signature export.
    pub signature: ToolSignatureInfo,
    /// Suggested `[tools]` TOML line.
    pub tools_line: String,
    /// Grant snippets that reference the alias (when `--policy` given).
    pub grant_hints: Vec<String>,
}

/// Summary of `reregister-all`.
#[derive(Debug, Clone, Default)]
pub struct ReregisterReport {
    /// Digests successfully recompiled.
    pub ok: Vec<ToolDigest>,
    /// Failures as `(path, message)`.
    pub errors: Vec<(String, String)>,
}

/// Register `wasm_path` into `artifact_dir` using `engine`.
///
/// Computes digest, compiles, serializes, reads `signature`, and formats the
/// `[tools]` line. When `policy_path` is set, lists `[[grants]]` that use the
/// signature name as `tool` (ADR-008 C.1 — operator edit aid).
///
/// # Errors
///
/// I/O, compile, or signature call failures.
pub fn register_wasm(
    engine: &Engine,
    artifact_dir: &Path,
    wasm_path: &Path,
    policy_path: Option<&Path>,
) -> Result<RegisterOutcome, RuntimeError> {
    let wasm_bytes = fs::read(wasm_path).map_err(|source| RuntimeError::Io {
        path: wasm_path.to_path_buf(),
        source,
    })?;
    let (digest, compile_ms, component) = write_artifact(engine, artifact_dir, &wasm_bytes)?;
    let pre = build_instance_pre(engine, &component)?;
    let signature = read_signature(engine, &pre)?;
    let hex = digest_hex(&digest);
    let tools_line = format!("{} = \"sha256:{hex}\"", signature.name);
    let grant_hints = policy_path
        .map(|p| grants_for_alias(p, &signature.name))
        .transpose()?
        .unwrap_or_default();
    Ok(RegisterOutcome {
        digest,
        compile_ms,
        signature,
        tools_line,
        grant_hints,
    })
}

/// Recompile every `*.wasm` in `artifact_dir` (wasmtime upgrade path, runbook §8).
///
/// # Errors
///
/// Only directory read failures; per-file errors are collected in the report.
pub fn reregister_all(
    engine: &Engine,
    artifact_dir: &Path,
) -> Result<ReregisterReport, RuntimeError> {
    ensure_artifact_dir(artifact_dir)?;
    let mut report = ReregisterReport::default();
    let entries = fs::read_dir(artifact_dir).map_err(|source| RuntimeError::Io {
        path: artifact_dir.to_path_buf(),
        source,
    })?;
    let mut wasm_files: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|ext| ext == "wasm")
        })
        .collect();
    wasm_files.sort();

    for path in wasm_files {
        match fs::read(&path).map_err(|source| RuntimeError::Io {
            path: path.clone(),
            source,
        }) {
            Ok(bytes) => match write_artifact(engine, artifact_dir, &bytes) {
                Ok((digest, _, _)) => report.ok.push(digest),
                Err(e) => report
                    .errors
                    .push((path.display().to_string(), e.to_string())),
            },
            Err(e) => report
                .errors
                .push((path.display().to_string(), e.to_string())),
        }
    }
    Ok(report)
}

/// Format operator-facing register lines (stdout).
#[must_use]
pub fn format_register_output(outcome: &RegisterOutcome) -> String {
    let hex = digest_hex(&outcome.digest);
    let mut out = format!(
        "sha256:{hex}  compiled in {}ms  signature: {} {}\n",
        outcome.compile_ms, outcome.signature.name, outcome.signature.version
    );
    out.push_str("# add to policy.toml:\n");
    out.push_str("[tools]\n");
    out.push_str(&outcome.tools_line);
    out.push('\n');
    if outcome.grant_hints.is_empty() {
        out.push_str("# no [[grants]] referencing this alias were found (pass --policy to scan)\n");
    } else {
        out.push_str(
            "# [[grants]] that reference this alias (update digest= to the new sha256):\n",
        );
        for g in &outcome.grant_hints {
            out.push_str(g);
            out.push('\n');
        }
    }
    out
}

fn grants_for_alias(policy_path: &Path, alias: &str) -> Result<Vec<String>, RuntimeError> {
    let text = fs::read_to_string(policy_path).map_err(|source| RuntimeError::Io {
        path: policy_path.to_path_buf(),
        source,
    })?;
    let value: toml::Value = text
        .parse()
        .map_err(|e| RuntimeError::Policy(format!("parse {}: {e}", policy_path.display())))?;
    let mut hints = Vec::new();
    let Some(grants) = value.get("grants").and_then(|g| g.as_array()) else {
        return Ok(hints);
    };
    for grant in grants {
        let tool = grant.get("tool").and_then(|t| t.as_str()).unwrap_or("");
        if tool != alias {
            continue;
        }
        let digest = grant
            .get("digest")
            .and_then(|d| d.as_str())
            .unwrap_or("<missing>");
        let identity = grant
            .get("identity")
            .and_then(|i| i.as_str())
            .unwrap_or("<identity>");
        hints.push(format!(
            "[[grants]] identity = \"{identity}\" tool = \"{alias}\" digest = \"{digest}\"  # <- set digest to new value"
        ));
    }
    Ok(hints)
}

/// Path helpers re-exported for ctl.
#[must_use]
pub fn paths_for(artifact_dir: &Path, digest: &ToolDigest) -> crate::artifact::ArtifactPaths {
    artifact_paths(artifact_dir, digest)
}
