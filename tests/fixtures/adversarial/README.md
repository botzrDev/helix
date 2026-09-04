# Adversarial fixtures (HLX-27 / RT-5…RT-7)

| File | Test | Behavior |
|---|---|---|
| `spin.wasm` / `spin.wat` | RT-5 | `run` = `loop {}`; killed by `preempt_ticks` |
| `membomb.wasm` / `membomb.wat` | RT-6 | `run` grows memory until `ResourceLimiter` traps |

Rebuild WASM with `wasm-tools parse <name>.wat -o <name>.wasm`.

RT-7 (`output_bytes + 1` → `Killed(Output)`, no partial output) is asserted on the
result channel via `BoundedWriter` / `deliver_output` (S4). A guest flood
fixture is not required for the channel bound.

BENCH-8 (p99 ≤ 12 ms at `preempt_ticks = 10`) is deferred to M7-01 / informational.
