//! GW-10: fuzz payload schema validation (`cargo fuzz run payload_validator`).
//!
//! Must not panic on any input. PR CI runs a short smoke; full duration is
//! `cargo fuzz run payload_validator -- -max_total_time=600` (10 min) per PR
//! when runners allow; 4h nightly via nightly-fuzz.yml (HLX-43).

#![no_main]

use helix_gateway::fuzz_payload_validator;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_payload_validator(data);
});
