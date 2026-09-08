//! `helix-ctl audit` — verify / dump / caps / witness-receive (M3-02 / M3-05).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use helix_audit::{
    cbor_to_json, hex_decode_32, hex_encode, load_token_file, record_to_json, verify_dir,
    verify_dir_with_witnesses, verify_file, FileHeader, WitnessAuth, WitnessHttpClient,
    WitnessReceiveRuntime,
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
        /// Off-host witness sink URL (`ADR-008` D.4 / `ADR-009` D.2).
        #[arg(long)]
        witnesses: Option<String>,
        /// Bearer token file for the witness sink (default when not `SigV4`).
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// `SigV4` credential file (`audit.witness_auth = sigv4`).
        #[arg(long)]
        sigv4_creds: Option<PathBuf>,
        /// Gateway id prefix for listing (default: inferred from logs).
        #[arg(long)]
        gateway_id: Option<String>,
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
    /// File-backed S3-style witness sink (PUT/GET/list; 412 on overwrite).
    WitnessReceive {
        /// Directory to store objects.
        #[arg(long)]
        dir: PathBuf,
        /// Listen address (e.g. `0.0.0.0:9292` or `127.0.0.1:0`).
        #[arg(long)]
        listen: String,
        /// Bearer token file (0600 recommended).
        #[arg(long)]
        token_file: PathBuf,
    },
}

/// Run an `audit` subcommand. Returns a process exit code.
#[must_use]
pub fn run(args: AuditArgs) -> i32 {
    match args.command {
        AuditCommand::Verify {
            dir,
            witnesses,
            token_file,
            sigv4_creds,
            gateway_id,
        } => {
            if let Some(url) = witnesses {
                run_verify_witnesses(
                    &dir,
                    &url,
                    token_file.as_deref(),
                    sigv4_creds.as_deref(),
                    gateway_id.as_deref(),
                )
            } else {
                run_verify(&dir)
            }
        }
        AuditCommand::Dump { file } => run_dump(&file),
        AuditCommand::Caps { hash, dir } => run_caps(&dir, &hash),
        AuditCommand::WitnessReceive {
            dir,
            listen,
            token_file,
        } => run_witness_receive(&dir, &listen, &token_file),
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

fn run_verify_witnesses(
    dir: &Path,
    sink_url: &str,
    token_file: Option<&Path>,
    sigv4_creds: Option<&Path>,
    gateway_id: Option<&str>,
) -> i32 {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("verify --witnesses: runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async move {
        let auth = if let Some(path) = sigv4_creds {
            WitnessAuth::SigV4 {
                cred_file: path.to_path_buf(),
            }
        } else if let Some(path) = token_file {
            WitnessAuth::Bearer {
                token_file: path.to_path_buf(),
            }
        } else {
            eprintln!("verify --witnesses: require --token-file or --sigv4-creds");
            return 1;
        };
        let client = match WitnessHttpClient::new(sink_url, auth) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("verify --witnesses: client: {e}");
                return 1;
            }
        };
        match verify_dir_with_witnesses(dir, &client, gateway_id).await {
            Ok(report) => {
                println!(
                    "ok: local {} file(s); {} witness(es) matched under {}",
                    report.local.files.len(),
                    report.witnesses_checked,
                    sink_url
                );
                0
            }
            Err(e) => {
                if e.is_tampering() {
                    eprintln!("verify --witnesses: TAMPERING: {}", e.first_break_message());
                } else {
                    eprintln!("verify --witnesses failed: {}", e.first_break_message());
                }
                1
            }
        }
    })
}

fn run_witness_receive(dir: &Path, listen: &str, token_file: &Path) -> i32 {
    let addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("witness-receive: bad --listen {listen}: {e}");
            return 1;
        }
    };
    let token = match load_token_file(token_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("witness-receive: token-file: {e}");
            return 1;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("witness-receive: runtime: {e}");
            return 1;
        }
    };
    rt.block_on(async move {
        let server = match WitnessReceiveRuntime::start(dir, addr, token).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("witness-receive: bind: {e}");
                return 1;
            }
        };
        eprintln!(
            "witness-receive listening on {} storing under {}",
            server.local_addr,
            dir.display()
        );
        // Block until Ctrl-C.
        let _ = tokio::signal::ctrl_c().await;
        server.shutdown().await;
        0
    })
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
