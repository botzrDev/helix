//! AUD-1, AUD-2, AUD-5, AUD-8.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use helix_audit::{AuditRecord, ResourceUsage, Transition, REASON_MAX_BYTES};

#[cfg(not(miri))]
use helix_audit::{verify_file, AuditWriterRuntime, SequenceStampHook, GENESIS_PREV_HASH};
#[cfg(not(miri))]
use std::io::Read;
#[cfg(not(miri))]
use std::path::PathBuf;
#[cfg(not(miri))]
use std::process::{Command, Stdio};
#[cfg(not(miri))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(miri))]
use std::sync::Arc;
#[cfg(not(miri))]
use std::time::{SystemTime, UNIX_EPOCH};

fn ulidish(n: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[15] = n;
    a
}

fn identity(n: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = n;
    a
}

fn digest(n: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[31] = n;
    a
}

fn sample_record(transition: Transition, seq: u64) -> AuditRecord {
    AuditRecord::new(
        ulidish(1),
        None,
        identity(2),
        digest(3),
        transition,
        "ok",
        if matches!(transition, Transition::Granted) {
            Some(digest(9))
        } else {
            None
        },
        if matches!(transition, Transition::Granted) {
            Some(ResourceUsage::new(10, 20, 30, 40))
        } else {
            None
        },
        if matches!(
            transition,
            Transition::Completed | Transition::ToolError | Transition::Killed
        ) {
            Some(ResourceUsage::new(1, 2, 3, 4))
        } else {
            None
        },
        1_700_000_000_000_000_000,
        seq,
    )
}

#[cfg(not(miri))]
fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("helix-aud-{name}-{nanos}"))
}

/// AUD-5: every Transition variant and every record field round-trips through
/// deterministic CBOR to byte-identical output.
#[test]
fn aud5_deterministic_cbor_round_trip() {
    for (i, t) in Transition::all().into_iter().enumerate() {
        let mut rec = sample_record(t, i as u64);
        rec.reason = format!("reason-{i}");
        if i % 2 == 0 {
            rec.parent = Some(ulidish(7));
        }
        let bytes = rec.encode_cbor().unwrap();
        let decoded = AuditRecord::decode_cbor(&bytes).unwrap();
        assert_eq!(decoded, rec, "semantic equality for {t:?}");
        let re = decoded.encode_cbor().unwrap();
        assert_eq!(re, bytes, "byte-identical re-encode for {t:?}");
    }

    // reason cap
    let long = "x".repeat(REASON_MAX_BYTES + 50);
    let rec = AuditRecord::new(
        ulidish(1),
        None,
        identity(1),
        digest(1),
        Transition::AuthFailed,
        long,
        None,
        None,
        None,
        0,
        0,
    );
    assert!(rec.reason.len() <= REASON_MAX_BYTES);
    let bytes = rec.encode_cbor().unwrap();
    let decoded = AuditRecord::decode_cbor(&bytes).unwrap();
    assert_eq!(decoded.encode_cbor().unwrap(), bytes);
}

/// AUD-1: clean chain verifies; single byte flip fails at exact index.
#[tokio::test]
#[cfg(not(miri))]
async fn aud1_chain_verify_and_byte_flip() {
    let path = tmp_path("aud1");
    let rt = AuditWriterRuntime::open_genesis(&path, "gw-aud1", ulidish(0x11))
        .await
        .unwrap();
    let w = rt.writer();
    for i in 0..5u64 {
        let t = if i == 0 {
            Transition::Granted
        } else if i == 4 {
            Transition::Completed
        } else {
            Transition::Running
        };
        let wait = t.is_synced();
        w.append(sample_record(t, 0), wait).await.unwrap();
    }
    drop(w);
    rt.join().await.unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let report = verify_file(&bytes).unwrap();
    assert_eq!(report.frames.len(), 5);
    assert_eq!(report.header.prev_hash, GENESIS_PREV_HASH);

    // Flip one byte inside the CBOR of record index 2 (after header + frames 0,1).
    let (header, hdr_len) = helix_audit::FileHeader::decode_cbor(&bytes).unwrap();
    assert_eq!(header.gateway_id, "gw-aud1");
    let mut offset = hdr_len;
    for _ in 0..2 {
        let (_f, n) = helix_audit::frame::decode_frame(&bytes[offset..]).unwrap();
        offset += n;
    }
    // length prefix then first byte of CBOR
    let flip_at = offset + 4;
    let mut corrupted = bytes.clone();
    corrupted[flip_at] ^= 0x01;
    let err = verify_file(&corrupted).unwrap_err();
    assert_eq!(err.break_index(), Some(2), "fail at exact index: {err}");

    let _ = std::fs::remove_file(&path);
}

/// AUD-2: SIGKILL between Granted and terminal; chain intact through Granted.
#[test]
#[cfg(not(miri))]
fn aud2_sigkill_after_granted() {
    let path = tmp_path("aud2");
    let bin = env!("CARGO_BIN_EXE_aud2_crash_child");
    let mut child = Command::new(bin)
        .env("HELIX_AUD2_PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aud2_crash_child");

    let mut stdout = child.stdout.take().expect("stdout");
    let mut buf = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "timeout waiting for AUD-2 child; buf={buf:?}"
        );
        let mut tmp = [0u8; 256];
        match stdout.read(&mut tmp) {
            Ok(0) => {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                panic!("child exited before READY; stderr={err} buf={buf:?}");
            }
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf
                    .windows(b"HELIX_AUD2_READY".len())
                    .any(|w| w == b"HELIX_AUD2_READY")
                {
                    break;
                }
            }
            Err(e) => panic!("read child stdout: {e}"),
        }
    }

    // SIGKILL (Command::kill sends SIGKILL on Unix).
    let _ = child.kill();
    let _ = child.wait();

    let bytes = std::fs::read(&path).expect("Granted file must survive SIGKILL after fdatasync");
    let report = verify_file(&bytes).expect("chain intact through Granted");
    assert_eq!(report.frames.len(), 1);
    assert_eq!(report.frames[0].record.transition, Transition::Granted);

    let _ = std::fs::remove_file(&path);
}

/// AUD-8: under 64 concurrent synced writes, sync count < synced records;
/// every response preceded by a covering sync (sequence-stamping hook).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(not(miri))]
async fn aud8_group_commit_and_sync_stamp() {
    let path = tmp_path("aud8");
    let hook = SequenceStampHook::new();
    let rt = AuditWriterRuntime::open_genesis_with_hook(
        &path,
        "gw-aud8",
        ulidish(0x88),
        hook.clone(),
        256,
    )
    .await
    .unwrap();
    let w = rt.writer();

    let synced_records = Arc::new(AtomicU64::new(0));
    let mut set = tokio::task::JoinSet::new();
    for i in 0..64u64 {
        let w = w.clone();
        let synced_records = Arc::clone(&synced_records);
        set.spawn(async move {
            // Non-synced noise sharing the channel.
            w.append_async(sample_record(Transition::Authorized, 0))
                .await
                .unwrap();
            let receipt = w
                .append_synced(sample_record(Transition::Granted, 0))
                .await
                .unwrap();
            // Response is only "sent" after observing a sync stamp covering us.
            assert!(receipt.sync_stamp > 0, "response {i} missing sync stamp");
            synced_records.fetch_add(1, Ordering::SeqCst);
            receipt
        });
    }

    let mut receipts = Vec::new();
    while let Some(res) = set.join_next().await {
        receipts.push(res.unwrap());
    }

    drop(w);
    rt.join().await.unwrap();

    let syncs = hook.sync_count();
    let n_synced = synced_records.load(Ordering::SeqCst);
    assert_eq!(n_synced, 64);
    assert!(
        syncs < n_synced,
        "group commit: sync_count {syncs} must be < synced records {n_synced}"
    );
    for r in &receipts {
        assert!(r.sync_stamp > 0);
        assert!(r.sync_stamp <= syncs);
    }

    let bytes = std::fs::read(&path).unwrap();
    let report = verify_file(&bytes).unwrap();
    // 64 Authorized + 64 Granted
    assert_eq!(report.frames.len(), 128);

    let _ = std::fs::remove_file(&path);
}
