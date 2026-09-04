# traverse.wasm (adversarial)

Guest opens `../../etc/passwd` (or a host canary) relative to a DirGrant
preopen. Expected: WASI `error-code::not-permitted` / tool
`invoke-error::capability-denied`; no host file opened.

## Verification in CI (HLX-26)

Unprivileged GitHub runners cannot reliably ptrace/`strace -e openat` the
test process. HELIX asserts the equivalent property in
`crates/helix-runtime/tests/rt2_rt3_rt4_fs.rs::traverse_canary_unread`:

1. Place a canary file outside the preopen root.
2. Attempt `../../canary` via the WASI host `open_at` path.
3. Assert the open fails and canary bytes + mtime are unchanged.

Hole vs full strace gate: documented here and on the HLX-26 PR. A privileged
strace job remains a follow-up if CI gains ptrace capability.
