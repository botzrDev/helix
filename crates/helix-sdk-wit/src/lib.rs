//! Generated `helix:tool` world bindings for guest tools.
//!
//! This crate intentionally does **not** `forbid(unsafe_code)`: `wit-bindgen`
//! emits CABI glue. Author-facing code lives in `helix-sdk`.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(missing_docs)]
#![allow(dead_code)]

#[allow(missing_docs)]
mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "tool",
        generate_all,
        pub_export_macro: true,
    });
}

pub use bindings::*;

// Re-export the export! macro for dependent crates (#[helix_tool]).
#[doc(hidden)]
pub use bindings::export;
