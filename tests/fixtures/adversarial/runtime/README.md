# Runtime adversarial fixtures (HLX-31 / RT-13…RT-16)

| File | Test | Behavior |
|---|---|---|
| `escalate.wasm` | RT-13 | Calls `helix:delegate/invoke` with a capability superset → `::escalation` |
| `fanout.wasm` | RT-14 | First delegate under `max_children = 0` → `::fanout` |
| `child_echo.wasm` | RT-13…16 | Child that echoes JSON input |
| `slow_child.wasm` | RT-15 / RT-16 | Busy-loop `invoke` for budget / parent-drop kills |

Gateway-namespace adversarial cases live under `tests/fixtures/adversarial/gateway/` (M5-06 / HLX-37).

Rebuild: `cargo component build --release --target wasm32-wasip1` in each fixture crate under `tests/fixtures/{escalate,fanout,child_echo,slow_child}`.
