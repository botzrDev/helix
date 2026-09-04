//! `helix-ctl policy` subcommands — thin clap wrappers over `helix-policy::tooling`.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use helix_policy::{
    check_policy, explain_grant_json, format_policy_errors, load_snapshot_for_explain, send_sighup,
};

/// `helix-ctl policy …`
#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Validate a policy file (structural always; host with `--artifacts`).
    Check {
        /// Path to `policy.toml`.
        file: PathBuf,
        /// Artifact directory; when set, also runs the host resolve pass.
        #[arg(long)]
        artifacts: Option<PathBuf>,
    },
    /// Print effective `CapabilitySet` + `ResourceBudget` as wire JSON.
    Explain {
        /// Identity alias from `[identities]`.
        identity: String,
        /// Tool alias from `[tools]`.
        tool: String,
        /// Path to `policy.toml`.
        #[arg(long)]
        policy: PathBuf,
        /// Optional artifact directory (otherwise digests from the file are trusted).
        #[arg(long)]
        artifacts: Option<PathBuf>,
    },
    /// Send `SIGHUP` to a gateway pid (runbook §4; pid required — no default named).
    Reload {
        /// Process id that should reload policy (typically `helix-gateway`).
        #[arg(long)]
        pid: u32,
    },
}

/// Run a `policy` subcommand. Returns a process exit code.
#[must_use]
pub fn run(args: PolicyArgs) -> i32 {
    match args.command {
        PolicyCommand::Check { file, artifacts } => run_check(&file, artifacts.as_deref()),
        PolicyCommand::Explain {
            identity,
            tool,
            policy,
            artifacts,
        } => run_explain(&policy, artifacts.as_deref(), &identity, &tool),
        PolicyCommand::Reload { pid } => run_reload(pid),
    }
}

fn run_check(file: &std::path::Path, artifacts: Option<&std::path::Path>) -> i32 {
    match check_policy(file, artifacts) {
        Ok(report) => {
            print!("{}", report.display_text());
            0
        }
        Err(errors) => {
            eprint!("{}", format_policy_errors(&errors));
            1
        }
    }
}

fn run_explain(
    policy: &std::path::Path,
    artifacts: Option<&std::path::Path>,
    identity: &str,
    tool: &str,
) -> i32 {
    match load_snapshot_for_explain(policy, artifacts) {
        Ok(snapshot) => match explain_grant_json(&snapshot, identity, tool) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(e) => {
                eprint!("{}", format_policy_errors(&[e]));
                1
            }
        },
        Err(errors) => {
            eprint!("{}", format_policy_errors(&errors));
            1
        }
    }
}

fn run_reload(pid: u32) -> i32 {
    match send_sighup(pid) {
        Ok(()) => {
            println!("sent SIGHUP to pid {pid}");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
