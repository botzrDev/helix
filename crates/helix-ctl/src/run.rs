//! `helix-ctl run` — local invoke with `--caps` or `--policy` (HLX-39 / M6-02).

#![allow(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::option_if_let_else,
    clippy::items_after_statements
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use clap::Args;
use helix_caps::{CapabilitySet, RequestId, ResourceBudget, ToolDigest};
use helix_policy::{
    format_policy_errors, load_snapshot_for_explain, PolicyGuard, DEFAULT_MAX_SNAPSHOT_AGE_S,
};
use helix_runtime::{
    build_engine, digest_hex, digest_of_bytes, invoke_with_delegation, DelegationCtx, EpochTicker,
    IdentitySemaphore, InvokeError, MapToolResolver, NopDelegationAudit, RecordingHook,
    RuntimeConfig, TerminalKind,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use wasmtime::component::Component;

/// Default budget when `--caps` JSON omits the sibling `budget` object.
fn default_budget() -> ResourceBudget {
    ResourceBudget::new(500, 2000, 64 * 1024 * 1024, 1024 * 1024, 2, 8, 32)
}

/// `helix-ctl run …`
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Wasm component path (`.wasm`).
    pub wasm: PathBuf,
    /// JSON input payload for `invoke`.
    #[arg(long)]
    pub input: String,
    /// `CapabilitySet` JSON file (`budget` sibling). Throwaway Interner.
    #[arg(long, conflicts_with_all = ["policy", "identity", "tool"])]
    pub caps: Option<PathBuf>,
    /// Policy.toml for the real loader (snapshot Interner).
    #[arg(long, requires_all = ["identity", "tool"])]
    pub policy: Option<PathBuf>,
    /// Identity alias from `[identities]` (with `--policy`).
    #[arg(long)]
    pub identity: Option<String>,
    /// Tool alias from `[tools]` (with `--policy`).
    #[arg(long)]
    pub tool: Option<String>,
    /// Artifact directory for child tool resolution / host digest checks.
    #[arg(long)]
    pub artifacts: Option<PathBuf>,
}

/// Run a tool locally. Returns a process exit code.
#[must_use]
pub fn run(args: RunArgs) -> i32 {
    run_sync(args)
}

fn run_sync(args: RunArgs) -> i32 {
    let artifact_dir = args
        .artifacts
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("helix-ctl-run-artifacts"));
    if let Err(e) = fs::create_dir_all(&artifact_dir) {
        eprintln!("artifacts dir: {e}");
        return 1;
    }

    let cfg = RuntimeConfig::new(&artifact_dir, 16, 64 * 1024 * 1024);
    let engine = match build_engine(&cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            return 1;
        }
    };
    let _ticker = EpochTicker::start(engine.clone());

    let wasm_bytes = match fs::read(&args.wasm) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read wasm {}: {e}", args.wasm.display());
            return 1;
        }
    };
    let digest = digest_of_bytes(&wasm_bytes);
    let component = match Component::new(&engine, &wasm_bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("component: {e}");
            return 1;
        }
    };

    let input_bytes = args.input.into_bytes();

    let prepared = if let Some(caps_path) = args.caps.as_ref() {
        match load_caps_file(caps_path) {
            Ok((caps, budget)) => Prepared {
                caps,
                budget,
                delegation: None,
            },
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        }
    } else if let (Some(policy), Some(identity), Some(tool)) = (
        args.policy.as_ref(),
        args.identity.as_ref(),
        args.tool.as_ref(),
    ) {
        match load_policy_invoke(
            &engine,
            policy,
            args.artifacts.as_deref(),
            identity,
            tool,
            digest,
            &component,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        }
    } else {
        eprintln!("provide --caps <json> or --policy <file> --identity <name> --tool <alias>");
        return 2;
    };

    let mut hook = RecordingHook::default();
    let result = invoke_with_delegation(
        &engine,
        &component,
        &prepared.caps,
        &prepared.budget,
        &input_bytes,
        prepared.delegation,
        &mut hook,
    );
    print_outcome(&result, &hook)
}

struct Prepared {
    caps: CapabilitySet,
    budget: ResourceBudget,
    delegation: Option<DelegationCtx>,
}

fn load_caps_file(path: &Path) -> Result<(CapabilitySet, ResourceBudget), String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("read caps {}: {e}", path.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse caps {}: {e}", path.display()))?;
    let budget = match value.get("budget").cloned() {
        Some(b) => {
            serde_json::from_value::<ResourceBudget>(b).map_err(|e| format!("parse budget: {e}"))?
        }
        None => default_budget(),
    };
    if let Some(obj) = value.as_object_mut() {
        obj.remove("budget");
    }
    // Checked constructor via Deserialize `try_from` (throwaway Interner).
    let caps: CapabilitySet = serde_json::from_value(value).map_err(|e| format!("caps: {e}"))?;
    Ok((caps, budget))
}

fn load_policy_invoke(
    engine: &wasmtime::Engine,
    policy_path: &Path,
    artifacts: Option<&Path>,
    identity_alias: &str,
    tool_alias: &str,
    wasm_digest: ToolDigest,
    root_component: &Component,
) -> Result<Prepared, String> {
    let snapshot = load_snapshot_for_explain(policy_path, artifacts)
        .map_err(|errs| format_policy_errors(&errs))?;
    let guard = PolicyGuard::from_snapshot(snapshot, DEFAULT_MAX_SNAPSHOT_AGE_S);

    let identity = *guard
        .snapshot()
        .identities()
        .get(identity_alias)
        .ok_or_else(|| format!("unknown identity alias {identity_alias}"))?;

    let table_digest = guard
        .resolve_alias(tool_alias)
        .ok_or_else(|| format!("unknown tool alias {tool_alias}"))?;
    if table_digest != wasm_digest {
        return Err(format!(
            "wasm digest mismatch for alias {tool_alias}: policy has {}, file has {}",
            digest_hex(&table_digest),
            digest_hex(&wasm_digest)
        ));
    }

    let (caps, budget) = guard
        .policy(&identity, &table_digest)
        .map(|(c, b)| (c.clone(), *b))
        .ok_or_else(|| format!("no grant for {identity_alias} / {tool_alias}"))?;

    let tools = Arc::new(MapToolResolver::new());
    tools.insert(wasm_digest, root_component.clone(), r#"{"type":"object"}"#);
    if let Some(dir) = artifacts {
        load_artifacts_into_resolver(engine, dir, &tools)?;
    }

    let ctx = DelegationCtx {
        request_id: next_request_id(),
        parent: None,
        identity,
        digest: wasm_digest,
        depth: 0,
        guard,
        effective: caps.clone(),
        budget,
        semaphore: Arc::new(IdentitySemaphore::new(budget.max_concurrent_instances())),
        token: CancellationToken::new(),
        children: JoinSet::new(),
        tools,
        audit: Arc::new(NopDelegationAudit),
        caps_store: None,
        store_creations: Arc::new(AtomicUsize::new(0)),
        engine: engine.clone(),
    };

    Ok(Prepared {
        caps,
        budget,
        delegation: Some(ctx),
    })
}

fn load_artifacts_into_resolver(
    engine: &wasmtime::Engine,
    dir: &Path,
    tools: &MapToolResolver,
) -> Result<(), String> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("read artifacts {}: {e}", dir.display()))?;
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wasm") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let digest = digest_of_bytes(&bytes);
        let component = Component::new(engine, &bytes)
            .map_err(|e| format!("component {}: {e}", path.display()))?;
        tools.insert(digest, component, r#"{"type":"object"}"#);
    }
    Ok(())
}

fn next_request_id() -> RequestId {
    use std::sync::atomic::{AtomicU64, Ordering as Ord};
    static CTR: AtomicU64 = AtomicU64::new(1);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let n = u128::from(CTR.fetch_add(1, Ord::SeqCst));
    RequestId::from_u128((ms << 16) | (n & 0xffff))
}

fn print_outcome(
    result: &Result<helix_runtime::InvokeSuccess, InvokeError>,
    hook: &RecordingHook,
) -> i32 {
    match result {
        Ok(success) => {
            match serde_json::from_slice::<serde_json::Value>(&success.output) {
                Ok(v) => println!("{v}"),
                Err(_) => println!("{}", String::from_utf8_lossy(&success.output)),
            }
            0
        }
        Err(err) => {
            if let Some(rec) = hook.records.last() {
                match &rec.kind {
                    TerminalKind::Completed { output } => {
                        println!("{}", String::from_utf8_lossy(output));
                    }
                    other => println!("terminal: {other:?}"),
                }
            } else {
                println!("error: {err}");
            }
            1
        }
    }
}
