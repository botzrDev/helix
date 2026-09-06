//! RT-11 (artifact version mismatch at startup) and ST-4 (single unsafe site).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use helix_runtime::{
    artifact::{deserialize_component, write_artifact},
    build_engine, load_artifact_dir, RuntimeConfig,
};

fn hello_wasm() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hello-world/hello_world.wasm")
}

fn test_engine(dir: &std::path::Path) -> wasmtime::Engine {
    build_engine(&RuntimeConfig::for_test(dir)).expect("engine")
}

#[test]
fn rt11_version_mismatched_artifact_fails_at_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = test_engine(tmp.path());
    let wasm = fs::read(hello_wasm()).expect("hello_world.wasm present");
    let (_digest, _ms, component) = write_artifact(&engine, tmp.path(), &wasm).unwrap();
    let mut bytes = component.serialize().unwrap();

    // Locate the embedded wasmtime version (e.g. "36.0.14") and rewrite it.
    let ver = find_semver_in_artifact(&bytes)
        .expect("wasmtime version string in artifact")
        .to_vec();
    let pos = bytes.windows(ver.len()).position(|w| w == ver).unwrap();
    let mut fake = ver.clone();
    // Flip major digit to force incompatible-version reject.
    fake[0] = if fake[0] == b'9' { b'8' } else { b'9' };
    assert_eq!(fake.len(), ver.len());
    bytes[pos..pos + ver.len()].copy_from_slice(&fake);

    let mut cwasm = None;
    for ent in fs::read_dir(tmp.path()).unwrap() {
        let p = ent.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) == Some("cwasm") {
            cwasm = Some(p);
            break;
        }
    }
    let cwasm = cwasm.expect("cwasm written");
    fs::write(&cwasm, &bytes).unwrap();

    let err = load_artifact_dir(&engine, tmp.path()).expect_err("must fail at startup");
    let msg = err.to_string();
    assert!(
        msg.contains("incompatible Wasmtime version")
            || msg.contains("reregister-all")
            || err.is_artifact_version_mismatch(),
        "expected clear version error, got: {msg}"
    );

    let Err(direct) = deserialize_component(&engine, &bytes) else {
        panic!("deserialize should fail for mismatched version");
    };
    assert!(
        direct.is_artifact_version_mismatch() || direct.to_string().contains("incompatible"),
        "direct: {direct}"
    );
}

#[test]
fn rt11_happy_path_loads_and_reads_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let engine = test_engine(tmp.path());
    let wasm = fs::read(hello_wasm()).unwrap();
    let (digest, _ms, component) = write_artifact(&engine, tmp.path(), &wasm).unwrap();
    let loaded = load_artifact_dir(&engine, tmp.path()).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].digest, digest);
    let sig = loaded[0].signature.as_ref().expect("signature");
    assert_eq!(sig.name, "hello-world");
    assert_eq!(sig.version, "0.1.0");
    let bytes = component.serialize().unwrap();
    deserialize_component(&engine, &bytes).unwrap();
}

#[test]
fn st4_exactly_one_unsafe_site_in_artifact_module() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = fs::read_to_string(root.join("lib.rs")).unwrap();
    // test-plan ST-4: forbid in every crate *except* helix-runtime.
    assert!(
        !lib.lines()
            .any(|l| l.trim_start().starts_with("#![forbid(unsafe_code)]")),
        "helix-runtime must not forbid unsafe_code at crate root (workspace exception)"
    );

    let mut allow_count = 0usize;
    let mut unsafe_sites = Vec::new();
    for ent in fs::read_dir(&root).unwrap() {
        let path = ent.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if text.lines().any(|l| {
            let s = l.trim_start();
            s.starts_with("#![allow(unsafe_code)]") || s.starts_with("#[allow(unsafe_code)]")
        }) {
            allow_count += 1;
            assert_eq!(
                name, "artifact.rs",
                "allow only in artifact.rs, found {name}"
            );
        }
        for (lineno, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains("allow(unsafe_code)") {
                continue;
            }
            if trimmed.contains("unsafe") {
                unsafe_sites.push(format!("{name}:{}:{trimmed}", lineno + 1));
            }
        }
    }
    assert_eq!(allow_count, 1, "exactly one #[allow(unsafe_code)]");
    assert_eq!(
        unsafe_sites.len(),
        1,
        "exactly one unsafe site, found {unsafe_sites:?}"
    );
    assert!(
        unsafe_sites[0].contains("Component::deserialize"),
        "unsafe site must be Component::deserialize, got {}",
        unsafe_sites[0]
    );

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new("grep")
        .args([
            "-R",
            "-l",
            "--include=*.rs",
            "forbid(unsafe_code)",
            "crates/helix-caps/src",
            "crates/helix-policy/src",
            "crates/helix-audit/src",
            "crates/helix-ctl/src",
            "crates/helix-gateway/src",
            "crates/helix-sdk/src",
        ])
        .current_dir(&workspace)
        .status()
        .expect("grep");
    assert!(status.success(), "sibling crates must forbid unsafe_code");
}

fn find_semver_in_artifact(bytes: &[u8]) -> Option<&[u8]> {
    let s = bytes;
    let mut i = 0;
    while i + 5 < s.len() {
        if s[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            i += 1;
            while i < s.len() {
                let c = s[i];
                if c == b'.' {
                    dots += 1;
                    i += 1;
                    continue;
                }
                if c.is_ascii_digit() {
                    i += 1;
                    continue;
                }
                break;
            }
            if dots == 2 && i - start >= 5 {
                return Some(&s[start..i]);
            }
        } else {
            i += 1;
        }
    }
    None
}
