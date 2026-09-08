//! RT-1 (http import with `HttpOutbound` clear fails at provision, `-32004`)
//! and RT-12 (`link` binds exactly interfaces whose bits are set).

use std::fs;
use std::path::PathBuf;

use helix_caps::{CapabilitySet, Interface};
use helix_runtime::{
    build_engine, link_with_names, linked_names, provision_pre, RuntimeConfig, RuntimeError,
    WasiHost,
};
use wasmtime::component::Component;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn test_engine() -> wasmtime::Engine {
    let tmp = tempfile::tempdir().unwrap();
    build_engine(&RuntimeConfig::for_test(tmp.path())).expect("engine")
}

#[test]
fn rt1_http_import_with_bit_clear_fails_provision_32004() {
    let engine = test_engine();
    let bytes = fs::read(fixture("http-import/http_import.wasm")).expect("http_import.wasm");
    let component = Component::new(&engine, &bytes).expect("parse component");

    // Any caps without HttpOutbound — EMPTY is the clear case.
    let caps = CapabilitySet::EMPTY;
    assert!(!caps.has(Interface::HttpOutbound));

    let Err(err) = provision_pre::<WasiHost>(&engine, &component, &caps) else {
        panic!("http import must fail when HttpOutbound bit is clear");
    };

    match &err {
        RuntimeError::Provision { reason } => {
            assert!(
                reason.contains("unlinked")
                    || reason.contains("not found")
                    || reason.contains("outgoing-handler")
                    || reason.contains("import"),
                "reason should mention missing import, got: {reason}"
            );
        }
        other => panic!("expected Provision error, got {other}"),
    }
    assert_eq!(err.gateway_code(), Some(RuntimeError::GATEWAY_CODE));
    assert_eq!(RuntimeError::GATEWAY_CODE, -32004);
}

#[test]
fn rt1_sockets_never_linked_fails_provision() {
    let engine = test_engine();
    let bytes = fs::read(fixture("sockets-import/unlinked.wasm")).expect("unlinked.wasm");
    let component = Component::new(&engine, &bytes).expect("parse component");

    // Even with every Interface bit set, sockets stay unlinked.
    let caps = CapabilitySet::new(
        &[
            Interface::Stdio,
            Interface::Clocks,
            Interface::Random,
            Interface::Filesystem,
            Interface::HttpOutbound,
        ],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();

    let Err(err) = provision_pre::<WasiHost>(&engine, &component, &caps) else {
        panic!("sockets import must always fail closed");
    };
    assert_eq!(err.gateway_code(), Some(-32004));
}

#[test]
fn rt12_link_binds_exactly_bits_set() {
    let engine = test_engine();

    let cases: &[(&[Interface], &[&str], &[&str])] = &[
        (
            &[],
            &[],
            &[
                "wasi:cli/",
                "wasi:clocks/",
                "wasi:random/",
                "wasi:filesystem/",
                "wasi:http/",
            ],
        ),
        (
            &[Interface::Stdio],
            &[
                "wasi:cli/stdin",
                "wasi:cli/stdout",
                "wasi:cli/stderr",
                "wasi:cli/exit",
            ],
            &[
                "wasi:clocks/",
                "wasi:random/",
                "wasi:filesystem/",
                "wasi:http/",
                "environment",
                "wasi:sockets/",
            ],
        ),
        (
            &[Interface::Clocks],
            &["wasi:clocks/wall-clock", "wasi:clocks/monotonic-clock"],
            &["wasi:cli/", "wasi:random/", "wasi:http/", "wasi:sockets/"],
        ),
        (
            &[Interface::Random],
            &[
                "wasi:random/random",
                "wasi:random/insecure",
                "wasi:random/insecure-seed",
            ],
            &["wasi:cli/", "wasi:clocks/", "wasi:http/"],
        ),
        (
            &[Interface::Filesystem],
            &["wasi:filesystem/types", "wasi:filesystem/preopens"],
            &["wasi:http/", "wasi:sockets/"],
        ),
        (
            &[Interface::HttpOutbound],
            &["wasi:http/outgoing-handler"],
            &["wasi:cli/", "wasi:sockets/", "environment"],
        ),
    ];

    for (ifaces, expect_present, expect_absent_prefixes) in cases {
        let caps = CapabilitySet::new(ifaces, vec![], vec![], vec![]).unwrap();
        let projected = linked_names(&caps);
        for name in *expect_present {
            assert!(
                projected.contains(name),
                "caps {ifaces:?}: expected {name} in {projected:?}"
            );
        }
        for prefix in *expect_absent_prefixes {
            assert!(
                !projected.iter().any(|n| n.contains(prefix)),
                "caps {ifaces:?}: did not expect {prefix} in {projected:?}"
            );
        }

        // Build the real linker and confirm the same name set is returned.
        let (_linker, names) = link_with_names::<WasiHost>(&engine, &caps).expect("link");
        assert_eq!(names, projected, "link_with_names must match linked_names");

        // Environment and sockets never appear.
        assert!(!names.iter().any(|n| n.contains("environment")));
        assert!(!names.iter().any(|n| n.starts_with("wasi:sockets/")));
    }
}

#[test]
fn rt12_all_bits_union_of_individuals() {
    let all = CapabilitySet::new(
        &[
            Interface::Stdio,
            Interface::Clocks,
            Interface::Random,
            Interface::Filesystem,
            Interface::HttpOutbound,
        ],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let names = linked_names(&all);
    assert!(names.contains(&"wasi:cli/stdin"));
    assert!(names.contains(&"wasi:clocks/wall-clock"));
    assert!(names.contains(&"wasi:random/random"));
    assert!(names.contains(&"wasi:filesystem/preopens"));
    assert!(names.contains(&"wasi:http/outgoing-handler"));
    assert!(!names.iter().any(|n| n.contains("environment")));
    assert!(!names.iter().any(|n| n.starts_with("wasi:sockets/")));
}
