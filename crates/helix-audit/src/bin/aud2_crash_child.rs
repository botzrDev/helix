//! Helper binary for AUD-2: write synced Granted, announce ready, sleep until SIGKILL.

use helix_audit::{AuditRecord, AuditWriterRuntime, ResourceUsage, Transition};
use std::io::Write;

fn main() {
    let path = std::env::var("HELIX_AUD2_PATH").expect("HELIX_AUD2_PATH");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let file_ulid = [0x22; 16];
        let runtime = AuditWriterRuntime::open_genesis(&path, "gw-aud2", file_ulid)
            .await
            .expect("open");
        let w = runtime.writer();
        let rec = AuditRecord::new(
            [1u8; 16],
            None,
            [2u8; 32],
            [3u8; 32],
            Transition::Granted,
            "granted",
            Some([9u8; 32]),
            Some(ResourceUsage::new(10, 20, 30, 40)),
            None,
            1,
            0,
        );
        w.append_synced(rec).await.expect("granted sync");
        println!("HELIX_AUD2_READY");
        let _ = std::io::stdout().flush();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
}
