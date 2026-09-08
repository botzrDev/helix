# Runtime adversarial fixtures (HLX-31 / HLX-37)

| File | Test | Behavior |
|---|---|---|
| `escalate.wasm` | RT-13 | capability superset → `::escalation` |
| `fanout.wasm` | RT-14 | `max_children = 0` → `::fanout` |
| `child_echo.wasm` | RT-13…16 | child echoes JSON |
| `slow_child.wasm` | RT-15 / RT-16 | busy-loop child |
| `spin_invoke.wasm` | HLX-37 | tool `invoke` spins → `Killed(Preempted)` through gateway |
| `membomb_invoke.wasm` | HLX-37 | tool grows memory → `Killed(Memory)` through gateway |
| `flood.wasm` | HLX-37 | tool returns huge output → `Killed(Output)` through gateway |

Gateway-namespace cases: `crates/helix-gateway/tests/adversarial_gateway.rs` / `tests/adversarial/gateway/`.
