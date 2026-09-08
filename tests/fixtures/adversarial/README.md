# Adversarial fixtures (HLX-27…HLX-37)

| File | Test | Behavior |
|---|---|---|
| `spin.wasm` / `spin.wat` | RT-5 | `run` = `loop {}`; killed by `preempt_ticks` |
| `membomb.wasm` / `membomb.wat` | RT-6 | `run` grows memory until `ResourceLimiter` traps |
| `flood.wasm` | RT-7 / HLX-37 | invoke guest returns oversized output → `Killed(Output)` |
| `trivial.wasm` / `trivial.wat` | RT-10 | soak / pool accounting |
| `runtime/spin_invoke.wasm` | HLX-37 | helix tool `invoke` busy-loop → gateway `-32010` |
| `runtime/membomb_invoke.wasm` | HLX-37 | helix tool memory bomb → gateway `-32012` |
| `runtime/flood.wasm` | HLX-37 | helix tool output flood → gateway `-32013` |
| `runtime/escalate.wasm` / `fanout.wasm` | RT-13/14 | delegate-error variants |
| `runtime/child_echo.wasm` / `slow_child.wasm` | RT-13…16 | child helpers |

## Split

- `runtime/` — escalate / fanout / child_echo / slow_child / invoke kill guests
- `gateway/` — reserved corpora for gateway-only cases (logic lives in `adversarial_gateway` tests)

Rebuild WAT: `wasm-tools parse <name>.wat -o <name>.wasm`.
