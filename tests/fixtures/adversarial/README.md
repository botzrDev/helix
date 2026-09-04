# Adversarial fixtures (HLX-27…HLX-29 / RT-5…RT-7, RT-10)

| File | Test | Behavior |
|---|---|---|
| `spin.wasm` / `spin.wat` | RT-5 | `run` = `loop {}`; killed by `preempt_ticks` |
| `membomb.wasm` / `membomb.wat` | RT-6 | `run` grows memory until `ResourceLimiter` traps |
| `trivial.wasm` / `trivial.wat` | RT-10 | `run` = `nop`; soak / pool accounting (HLX-29) |

Rebuild WASM with `wasm-tools parse <name>.wat -o <name>.wasm`.

RT-7 (`output_bytes + 1` → `Killed(Output)`, no partial output) is asserted on the
result channel via `BoundedWriter` / `deliver_output` (S4). A guest flood
fixture is not required for the channel bound.

BENCH-8 (p99 ≤ 12 ms at `preempt_ticks = 10`) is deferred to M7-01 / informational.
BENCH-7 (RSS after 100,000 at c=64) is deferred to M7-01; RT-10 covers the
10,000 sequential zero-leak gate.
