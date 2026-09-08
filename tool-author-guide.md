# Writing a HELIX Tool

A HELIX tool is a WebAssembly component that exports one function. It starts with no access to anything. The operator decides, per caller, what it may touch.

This guide is enough to build, register, and invoke a tool using only `helix-sdk` (and the `helix-ctl` operatorship commands below). Workspace examples live under `tests/fixtures/word_count` and `tests/fixtures/delegate_count`.

## 1. Prerequisites

- Rust stable with the WASI target used by `cargo-component` (today: `wasm32-wasip1`):
  `rustup target add wasm32-wasip1`
- `cargo install cargo-component --locked --version 0.21.1`
- `helix-sdk` from this workspace (`path = ".../crates/helix-sdk"`) or a published registry version when available

## 2. Minimal tool

`Cargo.toml`:

```toml
[package]
name = "word_count"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
helix-sdk = { path = "../../crates/helix-sdk" }  # or helix-sdk = "0.1" when published
serde = { version = "1", features = ["derive"] }
schemars = "1"

[package.metadata.component]
package = "helix:word-count"

[package.metadata.component.target]
path = "../../wit"
world = "tool"
```

Point `package.metadata.component.target.dependencies` at the WASI WIT deps under `wit/deps/` (see `tests/fixtures/word_count/Cargo.toml`).

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
cargo component build --release --manifest-path Cargo.toml
# target/wasm32-wasip1/release/word_count.wasm
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

`FileGrant` for `/a/b.txt` makes that file readable and keeps sibling `/a/c.txt` invisible inside the sandbox (RT-2). See `tests/fixtures/read_b` for a complete example exercised by SDK-4.

## 5. Making HTTP requests

Only works when the operator has granted `http_outbound` and the specific authority. Use `wasi::http::outgoing_handler` via the `waki` or `wstd` crate. Requests to ungranted hosts fail at the host boundary with a `capability-denied` style error; treat it the same as a missing file. Outbound HTTP is P0 (D-1 locked).

## 6. What you cannot do

- Spawn processes, open sockets directly, read environment variables (always empty in v1), or read the wall clock unless `clocks` is granted.
- Run longer than the caller's `wall_clock_ms` or use more memory than `memory_bytes`. Your tool is killed, not throttled. Guest code that never yields is preempted after `preempt_ticks` **milliseconds** (ticker pinned at 1 ms). Check the `usage` field in a successful response to see how close you are.
- Return more than `output_bytes`. Design outputs to be bounded; paginate if needed.

## 7. Registering

Send the `.wasm` to the operator. They run:

```
helix-ctl tool register --artifacts /var/lib/helix/artifacts ./word_count.wasm
```

which prints the digest and your `signature`. Every rebuild is a new digest and needs a policy update; version your tool and tell the operator what changed.

## 8. Testing locally

Throwaway Interner from a caps file (checked `CapabilitySet` constructor via JSON `try_from`). `budget` is a sibling of the set (see `interfaces/gateway-protocol.md` §5):

```
helix-ctl run --caps ./caps.json \
  ./target/wasm32-wasip1/release/word_count.wasm \
  --input '{"text":"a b c"}'
```

Example `caps.json` (cargo-component tools typically need `stdio`, `clocks`, and `filesystem` linked even when unused):

```json
{
  "interfaces": ["stdio", "clocks", "filesystem"],
  "files": [],
  "dirs": [],
  "hosts": [],
  "budget": {
    "preempt_ticks": 500,
    "wall_clock_ms": 2000,
    "memory_bytes": 67108864,
    "output_bytes": 1048576,
    "max_delegation_depth": 2,
    "max_children": 8,
    "max_concurrent_instances": 32
  }
}
```

Prints the JSON result or the terminal state.

Recommended production-denial reproduction (real policy loader + snapshot Interner). Put child `.wasm` files under `--artifacts` so `helix:delegate` can resolve them by digest:

```
helix-ctl run --policy /etc/helix/policy.toml \
  --identity research_agent --tool summarize_pdf \
  --artifacts /var/lib/helix/artifacts \
  ./target/wasm32-wasip1/release/summarize_pdf.wasm \
  --input '...'
```

`--policy` runs the real loader and uses the snapshot's Interner. Use it to reproduce kills and denials before shipping.

## 9. Delegating to another tool

There is one way to create a child invocation: the `helix:delegate/invoke` host import (see `interfaces/delegate.md` and `wit/helix-tool.wit`). The child runs under **your** identity. You supply a requested capability set that must be a subset of your effective set; the host attenuates against policy for the child digest.

`helix-ctl run` and the reference runtime link `helix:delegate` on the local/root invoke path so tools that import it can instantiate (HLX-39).

```rust
use helix_sdk::delegate;
use helix_sdk::{CapabilitySet, ToolRef};

// Interface bits: stdio=0, clocks=1, filesystem=3
let requested = CapabilitySet {
    interfaces: (1 << 0) | (1 << 1) | (1 << 3),
    files: vec![],
    hosts: vec![],
};

let result = delegate::invoke::<Input, Output>(
    ToolRef::Alias("word_count".into()),
    requested,
    None,
    &input,
)
.map_err(|e| /* handle DelegateError / map to ToolError */)?;
// result.output is the child's typed Output
```

Complete example: `tests/fixtures/delegate_count` (SDK-4). It returns the child's `words` count.

Bounds that refuse the child (surfaced as `delegate-error` variants, not HTTP `-32020`):

- `::escalation` — requested set is not a subset
- `::depth` / `::fanout` — tree bounds
- `::denied` — per-identity concurrency cap exhausted
- `::stale-snapshot` — parent's policy guard older than `max_snapshot_age_s`
- `::child-killed` — child hit its own budget

Your own `wall_clock_ms` keeps running while you wait. A killed child is an error value to you, not a kill of you. SDK-4's example tool delegates to `word_count`.
