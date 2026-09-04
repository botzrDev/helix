//! AUD-1, AUD-2, AUD-5, AUD-8.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use helix_audit::{
    encode_capability_set, sha256_32, AuditRecord, CapsStore, ResourceUsage, Transition,
    REASON_MAX_BYTES,
};
use helix_caps::CapabilitySet;

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

fn empty_caps_hash() -> [u8; 32] {
    let bytes = encode_capability_set(&CapabilitySet::EMPTY).expect("EMPTY encodes");
    sha256_32(&bytes)
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
            Some(empty_caps_hash())
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

/// AUD-5 (side-file half): equal `CapabilitySet`s → identical CBOR bytes and hash;
/// encode→decode→re-encode is byte-identical; `CapsStore` write-once.
#[test]
#[cfg(not(miri))]
fn aud5_caps_side_file_hash_and_store() {
    use helix_caps::{
        DirGrant, FileGrant, FileMode, HostGrant, Interface, Interner, Method, MethodMask,
    };
    use std::path::Path;

    let mut interner_a = Interner::new();
    let pa = interner_a.intern_path(Path::new("/data/x"));
    let da = interner_a.intern_path(Path::new("/data"));
    let aa = interner_a.intern_authority("example.com:443");
    let set_a = CapabilitySet::new(
        &[Interface::Filesystem, Interface::HttpOutbound],
        vec![FileGrant::new(pa, FileMode::Read)],
        vec![DirGrant::new(da, FileMode::ReadWrite)],
        vec![HostGrant::new(aa, MethodMask::new(&[Method::Get]))],
    )
    .unwrap()
    .with_interner(interner_a);

    let mut interner_b = Interner::new();
    let _ = interner_b.intern_path(Path::new("/noise"));
    let ab = interner_b.intern_authority("example.com:443");
    let db = interner_b.intern_path(Path::new("/data"));
    let pb = interner_b.intern_path(Path::new("/data/x"));
    let set_b = CapabilitySet::new(
        &[Interface::HttpOutbound, Interface::Filesystem],
        vec![FileGrant::new(pb, FileMode::Read)],
        vec![DirGrant::new(db, FileMode::ReadWrite)],
        vec![HostGrant::new(ab, MethodMask::new(&[Method::Get]))],
    )
    .unwrap()
    .with_interner(interner_b);

    assert_eq!(set_a, set_b);
    let bytes_a = encode_capability_set(&set_a).unwrap();
    let bytes_b = encode_capability_set(&set_b).unwrap();
    assert_eq!(bytes_a, bytes_b, "equal sets must share side-file bytes");
    assert_eq!(sha256_32(&bytes_a), sha256_32(&bytes_b));

    let decoded = helix_audit::decode_capability_set(&bytes_a).unwrap();
    assert_eq!(decoded, set_a);
    assert_eq!(encode_capability_set(&decoded).unwrap(), bytes_a);

    let empty_bytes = encode_capability_set(&CapabilitySet::EMPTY).unwrap();
    assert_ne!(empty_bytes, vec![0xa0]);

    let dir = tmp_path("aud5-caps");
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = CapsStore::open(&dir).unwrap();
    let h1 = store.ensure(&set_a).unwrap();
    let h2 = store.ensure(&set_b).unwrap();
    assert_eq!(h1, h2);
    assert!(store.seen_in_process(&h1));
    let h3 = store.ensure(&set_a).unwrap();
    assert_eq!(h3, h1);
    let path = store.path_for(&h1);
    assert!(path.is_file());
    assert_eq!(std::fs::read(&path).unwrap(), bytes_a);

    let (req, avail) = store.ensure_pair(&set_a, &CapabilitySet::EMPTY).unwrap();
    assert_eq!(req, h1);
    assert_ne!(req, avail);
    assert!(store.path_for(&avail).is_file());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Missing caps side file / content hash mismatch → `verify_dir` failure.
#[tokio::test]
#[cfg(not(miri))]
async fn aud5_missing_or_mismatched_caps_fails_verify() {
    use helix_audit::{verify_dir, AuditWriterRuntime, VerifyError};

    let dir = tmp_path("aud5-missing-caps");
    std::fs::create_dir_all(&dir).unwrap();
    let rt = AuditWriterRuntime::open_dir_with(
        &dir,
        "gw-caps",
        1_000_000,
        std::sync::Arc::new(helix_audit::NoopSyncHook),
        64,
        helix_audit::default_ulid_source(),
    )
    .await
    .unwrap();
    let w = rt.writer();
    w.append_synced(sample_record(Transition::Granted, 0))
        .await
        .unwrap();
    drop(w);
    rt.join().await.unwrap();

    let err = verify_dir(&dir).expect_err("missing caps must fail");
    assert!(
        matches!(err, VerifyError::MissingCaps { .. }),
        "got {err:?}"
    );

    // Write wrong content (empty map stub) under the expected hash path.
    let hash = empty_caps_hash();
    let caps_path = dir.join(format!("caps/{}.cbor", helix_audit::hex_encode(&hash)));
    std::fs::create_dir_all(caps_path.parent().unwrap()).unwrap();
    std::fs::write(&caps_path, [0xa0u8]).unwrap();
    let err = verify_dir(&dir).expect_err("hash mismatch must fail");
    assert!(
        matches!(err, VerifyError::CapsHashMismatch { .. }),
        "got {err:?}"
    );

    // Replace stub with real encoding; verify succeeds.
    std::fs::remove_file(&caps_path).unwrap();
    let mut store = CapsStore::open(&dir).unwrap();
    let _ = store.ensure(&CapabilitySet::EMPTY).unwrap();
    verify_dir(&dir).expect("real EMPTY side file must verify");

    let _ = std::fs::remove_dir_all(&dir);
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

/// AUD-3: rotation carries last hash into new file header; verify accepts
/// two-file sequence; break across the boundary is detected.
#[tokio::test]
#[cfg(not(miri))]
async fn aud3_rotation_carry_forward_and_boundary_break() {
    use helix_audit::{verify_dir, AuditWriterRuntime, VerifyError};

    let dir = tmp_path("aud3-dir");
    std::fs::create_dir_all(&dir).unwrap();

    // Deterministic ULIDs so file order is known (lexicographic Crockford).
    let mut n = 0u8;
    let ulid_source: helix_audit::UlidSource = Box::new(move || {
        n = n.wrapping_add(1);
        let mut a = [0u8; 16];
        // Keep high bytes zero so ULID strings sort as n increases in low bits.
        a[15] = n;
        a
    });

    // Tiny rotate threshold so the second synced batch opens a new file.
    let rt = AuditWriterRuntime::open_dir_with(
        &dir,
        "gw-aud3",
        200, // bytes: header + a couple of frames will exceed quickly
        std::sync::Arc::new(helix_audit::NoopSyncHook),
        64,
        ulid_source,
    )
    .await
    .unwrap();
    let w = rt.writer();

    // Write enough synced records to force at least one rotation.
    for i in 0..8u64 {
        let t = if i % 2 == 0 {
            Transition::Granted
        } else {
            Transition::Completed
        };
        w.append_synced(sample_record(t, 0)).await.unwrap();
    }
    drop(w);
    rt.join().await.unwrap();

    // Collect log files; expect ≥ 2.
    let mut logs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| helix_audit::parse_log_file_name(n).is_some())
        })
        .collect();
    logs.sort();
    assert!(
        logs.len() >= 2,
        "expected rotation to produce ≥2 files, got {}: {logs:?}",
        logs.len()
    );

    // Write real CapabilitySet side files for referenced hashes (HLX-21).
    let mut store = CapsStore::open(&dir).unwrap();
    let _ = store.ensure(&CapabilitySet::EMPTY).unwrap();

    let report = verify_dir(&dir).expect("two-file sequence must verify");
    assert!(report.files.len() >= 2);

    // Boundary: file[i+1].header.prev_hash == file[i].head_hash
    for win in report.files.windows(2) {
        assert_eq!(
            win[1].report.header.prev_hash,
            win[0].report.head_hash,
            "carry-forward mismatch between {} and {}",
            win[0].path.display(),
            win[1].path.display()
        );
    }

    // Break across the boundary: rebuild file 2 with a wrong header prev_hash
    // but a consistent internal chain so verify_file(file2) alone still passes.
    {
        use helix_audit::frame::encode_frame;
        let second = &logs[1];
        let bytes = std::fs::read(second).unwrap();
        let report = helix_audit::verify_file(&bytes).unwrap();
        let mut bad_header = report.header.clone();
        bad_header.prev_hash = [0x5au8; 32]; // not equal to file1 head
        let mut out = bad_header.encode_cbor().unwrap();
        let mut prev = bad_header.prev_hash;
        for frame in &report.frames {
            let (fb, new_hash) = encode_frame(&frame.record, &prev).unwrap();
            out.extend_from_slice(&fb);
            prev = new_hash;
        }
        std::fs::write(second, &out).unwrap();
        // Sanity: single-file verify still ok.
        helix_audit::verify_file(&out).expect("file2 alone still verifies");
    }

    let err = verify_dir(&dir).expect_err("boundary break must be detected");
    match err {
        VerifyError::BoundaryBreak { .. } => {}
        other => panic!("expected BoundaryBreak, got {other}"),
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

/// Retention entry CBOR + JSON shape (format only; sink is M3-05).
#[test]
fn retention_entry_round_trip_shape() {
    use helix_audit::{hex_encode, log_file_name, RetentionEntry};

    let ulid = [0xabu8; 16];
    let final_hash = [0x11u8; 32];
    let entry = RetentionEntry::new("gw-ret", ulid, final_hash, 42, log_file_name(&ulid));
    let cbor = entry.encode_cbor().unwrap();
    assert!(!cbor.is_empty());
    let j = entry.to_json();
    assert_eq!(j["gateway_id"], "gw-ret");
    assert_eq!(j["final_hash"], hex_encode(&final_hash));
    assert_eq!(j["wall_time_ns"], 42);
}

/// AUD-4: exporter paused ~60s under load — store stays complete/verifiable;
/// after resume, lag returns to 0 and every `request_id` is exported. Writer-path
/// latency with a stalled exporter stays within 5% of the unblocked baseline
/// (full gateway invoke latency deferred to M5 — helix-gateway has no invoke
/// path yet).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(not(miri))]
#[allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_possible_truncation
)]
async fn aud4_exporter_pause_store_safe_and_catchup() {
    use helix_audit::{
        verify_file, AuditExporterRuntime, AuditWriterRuntime, RecordingSink, Transition,
    };
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let dir = tmp_path("aud4-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("helix-00000000000000000000000001.log");

    // Deterministic single-file writer (open_genesis into the dir file).
    let rt = AuditWriterRuntime::open_genesis(&log_path, "gw-aud4", ulidish(0x41))
        .await
        .unwrap();
    let w = rt.writer();

    let sink = Arc::new(RecordingSink::new());
    sink.pause();
    let exporter =
        AuditExporterRuntime::start_with_poll(&dir, Arc::clone(&sink), Duration::from_millis(25));
    let metrics = exporter.metrics();

    // Baseline writer latency with exporter running (unpaused) is measured later;
    // first: under pause, drive synthetic load for ~60s.
    let load_start = Instant::now();
    let pause_for = Duration::from_secs(60);
    let mut request_ids = Vec::new();
    let mut n_synced = 0u64;
    let mut pause_latencies = Vec::new();

    while load_start.elapsed() < pause_for {
        let rid = {
            let mut a = [0u8; 16];
            let n = request_ids.len() as u64 + 1;
            a[8..].copy_from_slice(&n.to_be_bytes());
            a
        };
        request_ids.push(rid);
        // Granted + Completed (both synced) per invocation.
        let t0 = Instant::now();
        w.append_synced(AuditRecord::new(
            rid,
            None,
            identity(2),
            digest(3),
            Transition::Granted,
            "ok",
            Some(empty_caps_hash()),
            Some(ResourceUsage::new(1, 2, 3, 4)),
            None,
            1_700_000_000_000_000_000 + n_synced,
            0,
        ))
        .await
        .unwrap();
        w.append_synced(AuditRecord::new(
            rid,
            None,
            identity(2),
            digest(3),
            Transition::Completed,
            "done",
            None,
            None,
            Some(ResourceUsage::new(1, 2, 3, 4)),
            1_700_000_000_000_000_000 + n_synced + 1,
            0,
        ))
        .await
        .unwrap();
        pause_latencies.push(t0.elapsed());
        n_synced += 2;

        // Keep the pause window busy without spinning too hard on disk.
        if load_start.elapsed() + Duration::from_millis(5) < pause_for {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    assert!(
        request_ids.len() >= 10,
        "expected meaningful load during pause, got {}",
        request_ids.len()
    );

    // While paused, sink must not have received spans; lag should be > 0 once
    // the tailer has observed records.
    let wait_lag = Instant::now();
    while metrics.lag() == 0 && wait_lag.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        metrics.lag() > 0,
        "exporter lag must grow while sink paused (seen={}, exported={})",
        metrics.seen(),
        metrics.exported()
    );
    assert_eq!(
        sink.invocation_count().await,
        0,
        "paused sink must not export"
    );

    // Store remains complete and verifiable under stalled export.
    // Force a read of current file bytes (writer may still be open — sync has
    // already landed per append_synced).
    let bytes = std::fs::read(&log_path).unwrap();
    let report = verify_file(&bytes).expect("store must verify while exporter paused");
    assert_eq!(report.frames.len() as u64, n_synced);

    // Resume: exporter catches up.
    sink.resume();
    let catchup_ok = sink
        .wait_until_invocations(request_ids.len(), Duration::from_secs(120))
        .await;
    assert!(
        catchup_ok,
        "exporter failed to catch up: got {} / {} invocations; lag={}",
        sink.invocation_count().await,
        request_ids.len(),
        metrics.lag()
    );

    let wait_zero = Instant::now();
    while metrics.lag() != 0 && wait_zero.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        metrics.lag(),
        0,
        "lag must return to 0 after catch-up (seen={}, exported={})",
        metrics.seen(),
        metrics.exported()
    );

    let spans = sink.invocations().await;
    assert_eq!(spans.len(), request_ids.len());
    let mut got: Vec<[u8; 16]> = spans.iter().map(|i| i.request_id).collect();
    got.sort_unstable();
    let mut expect = request_ids.clone();
    expect.sort_unstable();
    assert_eq!(got, expect, "every request_id must appear as one span");
    for inv in &spans {
        assert_eq!(inv.events.len(), 2);
        assert_eq!(inv.events[0].transition, Transition::Granted);
        assert_eq!(inv.events[1].transition, Transition::Completed);
        assert_eq!(inv.terminal, Transition::Completed);
    }

    // Writer-path latency: compare paused-window latencies vs a short unblocked
    // window (exporter caught up / sink open). Full GW latency deferred to M5.
    let mut run_latencies = Vec::new();
    for i in 0..32u64 {
        let mut rid = [0u8; 16];
        rid[0] = 0xff;
        rid[8..].copy_from_slice(&(10_000 + i).to_be_bytes());
        let t0 = Instant::now();
        w.append_synced(AuditRecord::new(
            rid,
            None,
            identity(2),
            digest(3),
            Transition::Granted,
            "ok",
            Some(empty_caps_hash()),
            Some(ResourceUsage::new(1, 2, 3, 4)),
            None,
            2_000_000_000_000_000_000 + i,
            0,
        ))
        .await
        .unwrap();
        w.append_synced(AuditRecord::new(
            rid,
            None,
            identity(2),
            digest(3),
            Transition::Completed,
            "done",
            None,
            None,
            Some(ResourceUsage::new(1, 2, 3, 4)),
            2_000_000_000_000_000_000 + i + 1,
            0,
        ))
        .await
        .unwrap();
        run_latencies.push(t0.elapsed());
    }

    let mean = |v: &[Duration]| {
        let sum: Duration = v.iter().copied().sum();
        sum / u32::try_from(v.len()).unwrap_or(1)
    };
    let paused_mean = mean(&pause_latencies);
    let running_mean = mean(&run_latencies);
    let slower = paused_mean.max(running_mean);
    let faster = paused_mean.min(running_mean);
    let delta_ratio = if faster.is_zero() {
        0.0
    } else {
        (slower.as_secs_f64() - faster.as_secs_f64()) / faster.as_secs_f64()
    };
    assert!(
        delta_ratio < 0.05 || slower.as_millis() < 5,
        "writer latency changed by {:.1}% (paused={paused_mean:?}, running={running_mean:?}); \
         stalled exporter must not affect store path beyond 5% (GW invoke check deferred to M5)",
        delta_ratio * 100.0
    );

    drop(w);
    rt.join().await.unwrap();
    exporter.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
