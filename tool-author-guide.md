# Writing a HELIX Tool

A HELIX tool is a WebAssembly component that exports one function. It starts with no access to anything. The operator decides, per caller, what it may touch.

## 1. Prerequisites

- Rust stable with `wasm32-wasip2` target: `rustup target add wasm32-wasip2`
- `cargo install cargo-component`
- `helix-sdk` from the workspace registry

## 2. Minimal tool

`Cargo.toml`:

```toml
[package]
name = "word_count"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
helix-sdk = "1"
serde = { version = "1", features = ["derive"] }
schemars = "1"
```

`src/lib.rs`:

```rust
use helix_sdk::{helix_tool, ToolError};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Deserialize, JsonSchema)]
struct Input {
    /// Text to count. Max 1 MiB enforced by the host output cap on the caller side.
    text: String,
}

#[derive(Serialize, JsonSchema)]
struct Output {
    words: usize,
}

#[helix_tool(name = "word_count", version = "0.1.0")]
fn word_count(input: Input) -> Result<Output, ToolError> {
    Ok(Output { words: input.text.split_whitespace().count() })
}
```

Build:

```
cargo component build --release
# target/wasm32-wasip2/release/word_count.wasm
```

The macro generates the `signature` export (JSON Schema derived from `Input` and `Output`) and the `invoke` export (deserialize, call, serialize, map errors).

## 3. Errors

```rust
pub enum ToolError {
    InvalidInput(String),      // caller gets -32005 with your message
    CapabilityDenied(String),  // caller gets -32006
    Internal(String),          // caller gets -32007; message goes to the operator log only
}
```

Return `InvalidInput` for domain problems (a date out of range). Do not use it for shape problems; the host already rejected those before your code ran.

## 4. Reading files

You do not choose paths. The operator grants specific files or directories, and they appear under a preopen. Use `std::fs` normally; open by the path the operator documented for your tool.

```rust
let data = std::fs::read("/data/report.csv")
    .map_err(|e| ToolError::CapabilityDenied(format!("report.csv: {e}")))?;
```

If the grant is absent, the open fails and you should surface `CapabilityDenied`. Never retry.

**A granted directory is live:** files placed under a `dirs` grant after policy load are readable without a reload. The runtime does not snapshot the directory tree at load time.

## 5. Making HTTP requests

Only works when the operator has granted `http_outbound` and the specific authority. Use `wasi::http::outgoing_handler` via the `waki` or `wstd` crate. Requests to ungranted hosts fail at the host boundary with a `capability-denied` style error; treat it the same as a missing file. Outbound HTTP is P0 (D-1 locked).

## 6. What you cannot do

- Spawn processes, open sockets directly, read environment variables (always empty in v1), or read the wall clock unless `clocks` is granted.
- Run longer than the caller's `wall_clock_ms` or use more memory than `memory_bytes`. Your tool is killed, not throttled. Guest code that never yields is preempted after `preempt_ticks` **milliseconds** (ticker pinned at 1 ms). Check the `usage` field in a successful response to see how close you are.
- Return more than `output_bytes`. Design outputs to be bounded; paginate if needed.

## 7. Registering

Send the `.wasm` to the operator. They run `helix-ctl tool register`, which prints the digest and your `signature`. Every rebuild is a new digest and needs a policy update; version your tool and tell the operator what changed.

## 8. Testing locally

```
helix-ctl run --caps ./caps.json ./target/wasm32-wasip2/release/word_count.wasm --input '{"text":"a b c"}'
```

instantiates your tool with the given `CapabilitySet` JSON (format in `interfaces/gateway-protocol.md` section 5; budget is a sibling) and prints the result or the terminal state.

Recommended production-denial reproduction:

```
helix-ctl run --policy /etc/helix/policy.toml --identity research_agent --tool summarize_pdf \
  ./target/wasm32-wasip2/release/summarize_pdf.wasm --input '...'
```

`--policy` runs the real loader and uses the snapshot's Interner. Use it to reproduce kills and denials before shipping.

## 9. Delegating to another tool

There is one way to create a child invocation: the `helix:delegate/invoke` host import (see `interfaces/delegate.md` and `wit/helix-tool.wit`). The child runs under **your** identity. You supply a requested capability set that must be a subset of your effective set; the host attenuates against policy for the child digest.

```rust
use helix_sdk::delegate;

let result = delegate::invoke(/* tool, requested, budget, input */)
    .map_err(|e| /* handle delegate-error::* */)?;
```

Bounds that refuse the child (surfaced as `delegate-error` variants, not HTTP `-32020`):

- `::escalation` — requested set is not a subset
- `::depth` / `::fanout` — tree bounds
- `::denied` — per-identity concurrency cap exhausted
- `::stale-snapshot` — parent's policy guard older than `max_snapshot_age_s`
- `::child-killed` — child hit its own budget

Your own `wall_clock_ms` keeps running while you wait. A killed child is an error value to you, not a kill of you. SDK-4's example tool delegates to `word_count`.
