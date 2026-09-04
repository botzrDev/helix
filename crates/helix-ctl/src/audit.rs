//! `helix-ctl audit` — verify / dump / caps (M3-02 / HLX-19).

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use helix_audit::{
    cbor_to_json, hex_decode_32, hex_encode, record_to_json, verify_dir, verify_file, FileHeader,
};

/// `helix-ctl audit …`
#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    command: AuditCommand,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Walk `helix-*.log` in ULID order; verify chains and caps side files.
    Verify {
        /// Audit directory (contains `helix-*.log` and optional `caps/`).
        dir: PathBuf,
    },
    /// Print records in a log file as JSON lines.
    Dump {
        /// Path to a single `helix-<ulid>.log` file.
        file: PathBuf,
    },
    /// Print a caps side file as JSON (`caps/<hash>.cbor`).
    Caps {
        /// Hex SHA-256 of the `CapabilitySet` (64 hex chars).
        hash: String,
        /// Audit directory containing `caps/`.
        #[arg(long)]
        dir: PathBuf,
    },
}

/// Run an `audit` subcommand. Returns a process exit code.
#[must_use]
pub fn run(args: AuditArgs) -> i32 {
    match args.command {
        AuditCommand::Verify { dir } => run_verify(&dir),
        AuditCommand::Dump { file } => run_dump(&file),
        AuditCommand::Caps { hash, dir } => run_caps(&dir, &hash),
    }
}

fn run_verify(dir: &Path) -> i32 {
    match verify_dir(dir) {
        Ok(report) => {
            println!(
                "ok: {} file(s) verified under {}",
                report.files.len(),
                dir.display()
            );
            for f in &report.files {
                println!(
                    "  {} frames={} head={}",
                    f.path.display(),
                    f.report.frames.len(),
                    hex_encode(&f.report.head_hash)
                );
            }
            0
        }
        Err(e) => {
            eprintln!("verify failed: {}", e.first_break_message());
            1
        }
    }
}

fn run_dump(file: &Path) -> i32 {
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("dump: read {}: {e}", file.display());
            return 1;
        }
    };
    match verify_file(&bytes) {
        Ok(report) => {
            for frame in &report.frames {
                match serde_json::to_string(&record_to_json(&frame.record)) {
                    Ok(line) => println!("{line}"),
                    Err(e) => {
                        eprintln!("dump: serialize: {e}");
                        return 1;
                    }
                }
            }
            0
        }
        Err(e) => {
            // Still try to dump what we can by walking frames after header.
            eprintln!("dump: chain verify warning: {e}");
            dump_best_effort(&bytes)
        }
    }
}

fn dump_best_effort(bytes: &[u8]) -> i32 {
    let (header, mut offset) = match FileHeader::decode_cbor(bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("dump: header: {e}");
            return 1;
        }
    };
    let _ = header;
    while offset < bytes.len() {
        match helix_audit::frame::decode_frame(&bytes[offset..]) {
            Ok((frame, n)) => {
                match serde_json::to_string(&record_to_json(&frame.record)) {
                    Ok(line) => println!("{line}"),
                    Err(e) => {
                        eprintln!("dump: serialize: {e}");
                        return 1;
                    }
                }
                offset += n;
            }
            Err(e) => {
                eprintln!("dump: stopped at offset {offset}: {e}");
                return 1;
            }
        }
    }
    0
}

fn run_caps(dir: &Path, hash: &str) -> i32 {
    let digest = match hex_decode_32(hash) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("caps: bad hash: {e}");
            return 1;
        }
    };
    let path = dir.join(format!("caps/{}.cbor", hex_encode(&digest)));
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("caps: read {}: {e}", path.display());
            return 1;
        }
    };
    let actual = helix_audit::sha256_32(&bytes);
    if actual != digest {
        eprintln!(
            "caps: content hash mismatch: expected {}, file hashes to {}",
            hex_encode(&digest),
            hex_encode(&actual)
        );
        return 1;
    }
    match cbor_to_json(&bytes) {
        Ok(v) => match serde_json::to_string_pretty(&v) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("caps: serialize: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("caps: decode CBOR: {e}");
            1
        }
    }
}
