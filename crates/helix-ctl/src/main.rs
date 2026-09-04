//! `helix-ctl` — operator CLI. Keep this file under 100 lines; logic lives in
//! `helix-policy` and thin modules under this crate.

#![forbid(unsafe_code)]

mod policy;

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
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Policy(args) => policy::run(args),
    };
    std::process::exit(code);
}
