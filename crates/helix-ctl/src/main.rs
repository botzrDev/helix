//! `helix-ctl` — operator CLI. Keep this file under 100 lines; logic lives in
//! library crates and thin modules under this crate.

#![forbid(unsafe_code)]

mod audit;
mod policy;
mod run;
mod tool;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "helix-ctl", about = "Helix operator CLI", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Policy check, explain, and reload (M2-04 / HLX-17).
    Policy(policy::PolicyArgs),
    /// Audit verify, dump, caps, witness-receive (M3-02 / M3-05).
    Audit(audit::AuditArgs),
    /// Tool register / reregister-all (M4-01 / HLX-24).
    Tool(tool::ToolArgs),
    /// Local invoke with caps JSON or policy snapshot (M6-02 / HLX-39).
    Run(run::RunArgs),
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Policy(args) => policy::run(args),
        Commands::Audit(args) => audit::run(args),
        Commands::Tool(args) => tool::run(args),
        Commands::Run(args) => run::run(args),
    };
    std::process::exit(code);
}
