//! GW-9: fuzz the DPoP proof parser/verifier (`cargo fuzz run dpop_proof`).
//!
//! Must not panic on any input. PR CI runs a short smoke; full 10 minutes is
//! the same schedule as GW-8 (`-max_total_time=600` per PR when runners allow;
//! 4h nightly via nightly-fuzz.yml (HLX-43)).

#![no_main]

use helix_gateway::fuzz_dpop_proof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_dpop_proof(data);
});
