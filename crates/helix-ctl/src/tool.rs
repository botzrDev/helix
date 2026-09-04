//! `helix-ctl tool register` / `reregister-all`.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use helix_runtime::{
    build_engine, format_register_output, register_wasm, reregister_all, RuntimeConfig,
};

/// `helix-ctl tool …`
#[derive(Debug, Args)]
pub struct ToolArgs {
    #[command(subcommand)]
    command: ToolCommand,
}

#[derive(Debug, Subcommand)]
enum ToolCommand {
    /// Compile a wasm component into the artifact cache and print policy hints.
    Register {
        /// Path to a WebAssembly component (`.wasm`).
        wasm: PathBuf,
        /// Artifact directory (`runtime.artifact_dir`).
        #[arg(long)]
        artifacts: PathBuf,
        /// Optional policy.toml to list grants referencing the tool alias.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Pool size for the compile engine (default 4; registration is offline).
        #[arg(long, default_value_t = 4)]
        max_concurrent_instances: u32,
        /// Pool memory ceiling in bytes (default 16 MiB).
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        pool_max_memory_bytes: usize,
    },
    /// Recompile every `*.wasm` in the artifact dir after a wasmtime upgrade.
    ReregisterAll {
        /// Artifact directory (`runtime.artifact_dir`).
        #[arg(long)]
        artifacts: PathBuf,
        #[arg(long, default_value_t = 4)]
        max_concurrent_instances: u32,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        pool_max_memory_bytes: usize,
    },
}

/// Run a `tool` subcommand. Returns a process exit code.
#[must_use]
pub fn run(args: ToolArgs) -> i32 {
    match args.command {
        ToolCommand::Register {
            wasm,
            artifacts,
            policy,
            max_concurrent_instances,
            pool_max_memory_bytes,
        } => run_register(
            &wasm,
            &artifacts,
            policy.as_deref(),
            max_concurrent_instances,
            pool_max_memory_bytes,
        ),
        ToolCommand::ReregisterAll {
            artifacts,
            max_concurrent_instances,
            pool_max_memory_bytes,
        } => run_reregister_all(&artifacts, max_concurrent_instances, pool_max_memory_bytes),
    }
}

fn run_register(
    wasm: &std::path::Path,
    artifacts: &std::path::Path,
    policy: Option<&std::path::Path>,
    max_concurrent_instances: u32,
    pool_max_memory_bytes: usize,
) -> i32 {
    let cfg = RuntimeConfig::new(artifacts, max_concurrent_instances, pool_max_memory_bytes);
    let engine = match build_engine(&cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            return 1;
        }
    };
    match register_wasm(&engine, artifacts, wasm, policy) {
        Ok(outcome) => {
            print!("{}", format_register_output(&outcome));
            0
        }
        Err(e) => {
            eprintln!("register failed: {e}");
            1
        }
    }
}

fn run_reregister_all(
    artifacts: &std::path::Path,
    max_concurrent_instances: u32,
    pool_max_memory_bytes: usize,
) -> i32 {
    let cfg = RuntimeConfig::new(artifacts, max_concurrent_instances, pool_max_memory_bytes);
    let engine = match build_engine(&cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            return 1;
        }
    };
    match reregister_all(&engine, artifacts) {
        Ok(report) => {
            println!(
                "reregister-all: {} ok, {} errors",
                report.ok.len(),
                report.errors.len()
            );
            for d in &report.ok {
                let hex = helix_runtime::digest_hex(d);
                println!("  ok sha256:{hex}");
            }
            for (path, err) in &report.errors {
                eprintln!("  fail {path}: {err}");
            }
            i32::from(!report.errors.is_empty())
        }
        Err(e) => {
            eprintln!("reregister-all failed: {e}");
            1
        }
    }
}
