//! Host WIT bindings for `helix:tool/{types,caps,delegate}` (HLX-39).
//!
//! Empty `linker.instance(...)` stubs fail wasmtime's component typecheck because
//! guests require the type exports on `types` / `caps`. This bindgen emits a
//! correct `add_to_linker`.

#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(dead_code)]

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "delegate-host",
});
