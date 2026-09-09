//! GW-8: fuzz the JSON-RPC envelope parser (`cargo fuzz run envelope`).
//!
//! Must not panic on any input. PR CI runs a short smoke; full 10 minutes is
//! documented in `.github/workflows/ci.yml`; 4h nightly via nightly-fuzz.yml (HLX-43).

#![no_main]

use helix_gateway::parse_envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_envelope(data);
});
