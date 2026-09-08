//! `#[helix_tool]` procedural macro.
//!
//! Expands a typed tool function into:
//! - compile-time `Serialize` / `Deserialize` / `JsonSchema` checks (SDK-3)
//! - `signature` / `invoke` Guest exports for `wasm32` via `helix-sdk-wit` (SDK-1)
//! - JSON Schema helpers used by SDK-2 tests

#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::Parser;
use syn::{
    parse_macro_input, spanned::Spanned, Error, FnArg, ItemFn, LitStr, Pat, ReturnType, Type,
};

fn parse_args(attr: TokenStream) -> syn::Result<(LitStr, LitStr)> {
    let mut name: Option<LitStr> = None;
    let mut version: Option<LitStr> = None;

    let attr2: proc_macro2::TokenStream = attr.into();
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("name") {
            name = Some(meta.value()?.parse::<LitStr>()?);
            Ok(())
        } else if meta.path.is_ident("version") {
            version = Some(meta.value()?.parse::<LitStr>()?);
            Ok(())
        } else {
            Err(meta.error("unsupported #[helix_tool] key; expected `name` or `version`"))
        }
    });
    parser.parse2(attr2)?;

    let name = name.ok_or_else(|| {
        Error::new(
            proc_macro2::Span::call_site(),
            "#[helix_tool] requires `name = \"...\"`",
        )
    })?;
    let version = version.ok_or_else(|| {
        Error::new(
            proc_macro2::Span::call_site(),
            "#[helix_tool] requires `version = \"...\"`",
        )
    })?;
    Ok((name, version))
}

fn extract_input_type(func: &ItemFn) -> syn::Result<&Type> {
    let mut inputs = func.sig.inputs.iter();
    let Some(arg) = inputs.next() else {
        return Err(Error::new(
            func.sig.span(),
            "#[helix_tool] function must take exactly one argument (the input type)",
        ));
    };
    if inputs.next().is_some() {
        return Err(Error::new(
            func.sig.span(),
            "#[helix_tool] function must take exactly one argument (the input type)",
        ));
    }
    match arg {
        FnArg::Typed(pat_type) => {
            if let Pat::Ident(_) = *pat_type.pat {
                Ok(&pat_type.ty)
            } else {
                Err(Error::new(
                    pat_type.pat.span(),
                    "#[helix_tool] argument must be a plain identifier pattern",
                ))
            }
        }
        FnArg::Receiver(_) => Err(Error::new(
            arg.span(),
            "#[helix_tool] does not support methods with self",
        )),
    }
}

fn extract_ok_type(func: &ItemFn) -> syn::Result<&Type> {
    match &func.sig.output {
        ReturnType::Type(_, ty) => extract_result_ok(ty).ok_or_else(|| {
            Error::new(
                ty.span(),
                "#[helix_tool] function must return Result<Output, helix_sdk::ToolError>",
            )
        }),
        ReturnType::Default => Err(Error::new(
            func.sig.span(),
            "#[helix_tool] function must return Result<Output, helix_sdk::ToolError>",
        )),
    }
}

fn extract_result_ok(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let seg = path.path.segments.last()?;
    if seg.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let mut iter = args.args.iter();
    let syn::GenericArgument::Type(ok) = iter.next()? else {
        return None;
    };
    Some(ok)
}

/// Marks a function as a HELIX tool component export.
///
/// ```ignore
/// #[helix_tool(name = "word_count", version = "0.1.0")]
/// fn word_count(input: Input) -> Result<Output, ToolError> { ... }
/// ```
#[allow(clippy::too_many_lines)]
#[proc_macro_attribute]
pub fn helix_tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    let (name, version) = match parse_args(attr) {
        Ok(v) => v,
        Err(e) => return e.to_compile_error().into(),
    };
    let func = parse_macro_input!(item as ItemFn);

    if func.sig.asyncness.is_some() {
        return Error::new(
            func.sig.span(),
            "#[helix_tool] does not support async functions",
        )
        .to_compile_error()
        .into();
    }
    if !func.sig.generics.params.is_empty() {
        return Error::new(
            func.sig.generics.span(),
            "#[helix_tool] does not support generic functions",
        )
        .to_compile_error()
        .into();
    }

    let input_ty = match extract_input_type(&func) {
        Ok(t) => t,
        Err(e) => return e.to_compile_error().into(),
    };
    let output_ty = match extract_ok_type(&func) {
        Ok(t) => t,
        Err(e) => return e.to_compile_error().into(),
    };

    let fn_name = &func.sig.ident;
    let schema_mod = format_ident!("__helix_tool_schema_{}", fn_name);
    let assert_fn = format_ident!("__helix_assert_tool_io_{}", fn_name);
    let export_mod = format_ident!("__helix_tool_guest_{}", fn_name);

    let expanded = quote! {
        #func

        /// Schema helpers generated by `#[helix_tool]` (SDK-2).
        #[allow(non_snake_case)]
        pub mod #schema_mod {
            use super::*;

            /// JSON Schema (draft 2020-12) for the tool input type.
            #[must_use]
            pub fn input_schema() -> ::std::string::String {
                let schema = ::helix_sdk::__private::schema_for::<#input_ty>();
                ::helix_sdk::__private::serde_json::to_string(&schema)
                    .expect("schemars Schema always serializes")
            }

            /// JSON Schema (draft 2020-12) for the tool output type.
            #[must_use]
            pub fn output_schema() -> ::std::string::String {
                let schema = ::helix_sdk::__private::schema_for::<#output_ty>();
                ::helix_sdk::__private::serde_json::to_string(&schema)
                    .expect("schemars Schema always serializes")
            }

            /// Tool name from `#[helix_tool]`.
            #[must_use]
            pub fn name() -> &'static str {
                #name
            }

            /// Tool version from `#[helix_tool]`.
            #[must_use]
            pub fn version() -> &'static str {
                #version
            }
        }

        // SDK-3: pointed compile-time error when Input/Output are not serializable
        // / schema-derivable.
        #[allow(dead_code)]
        fn #assert_fn() {
            fn assert<I, O>()
            where
                I: ::helix_sdk::__private::HelixToolInput,
                O: ::helix_sdk::__private::HelixToolOutput,
            {
            }
            assert::<#input_ty, #output_ty>();
        }

        // SDK-1: component exports (wasm guests only). Must be a real module so
        // `export!` can emit top-level cabi items.
        #[cfg(target_arch = "wasm32")]
        #[allow(non_snake_case)]
        mod #export_mod {
            use super::*;
            use ::helix_sdk::__wit::{export, Guest, InvokeError, ToolSignature};

            struct __HelixToolComponent;

            impl Guest for __HelixToolComponent {
                fn signature() -> ToolSignature {
                    ToolSignature {
                        name: #schema_mod::name().into(),
                        version: #schema_mod::version().into(),
                        input_schema: #schema_mod::input_schema(),
                        output_schema: #schema_mod::output_schema(),
                    }
                }

                fn invoke(
                    input: ::std::vec::Vec<u8>,
                ) -> ::std::result::Result<::std::vec::Vec<u8>, InvokeError> {
                    let value: #input_ty =
                        match ::helix_sdk::__private::serde_json::from_slice(&input) {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(InvokeError::InvalidInput(format!(
                                    "input deserialization failed: {e}"
                                )));
                            }
                        };
                    match #fn_name(value) {
                        Ok(out) => match ::helix_sdk::__private::serde_json::to_vec(&out) {
                            Ok(bytes) => Ok(bytes),
                            Err(e) => Err(InvokeError::Internal(format!(
                                "output serialization failed: {e}"
                            ))),
                        },
                        Err(err) => Err(::helix_sdk::ToolError::into_invoke_error(err)),
                    }
                }
            }

            export!(__HelixToolComponent with_types_in ::helix_sdk::__wit);
        }
    };

    expanded.into()
}
