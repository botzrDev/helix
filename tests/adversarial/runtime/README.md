# Runtime adversarial namespace

| Component | Expected | Coverage |
|---|---|---|
| `spin.wasm` | `Killed(Preempted)` | `helix-runtime` `rt5_rt6_rt7_limits` + gateway e2e via `runtime/spin_invoke.wasm` |
| `membomb.wasm` | `Killed(Memory)` | same + `runtime/membomb_invoke.wasm` |
| `flood.wasm` | `Killed(Output)` | channel RT-7 + guest `runtime/flood.wasm` through gateway |
| `traverse.wasm` | capability-denied, no host file | **HOLE (guest):** host canary `rt2_rt3_rt4_fs::traverse_canary_unread` (strace stand-in) |
| `unlinked.wasm` | `Failed(Provision)` | `rt1_rt12_link` sockets never linked |
| `slowhost.wasm` | `Killed(WallClock)` | `rt8_http` / `rt8_rt9_cancel` (M4-07); **HOLE:** guest-through-gateway |
| `escalate.wasm` / `fanout.wasm` | `delegate-error` variants | `rt13_rt16_delegate` (**HOLE:** root gateway path does not link `helix:delegate`) |

Rebuild invoke guests: `cargo component build --release --target wasm32-wasip1 --manifest-path tests/fixtures/adversarial/{spin_invoke,membomb_invoke,flood}/Cargo.toml` then copy `*.wasm` into `tests/fixtures/adversarial/runtime/`.
