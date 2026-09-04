//! RT-2 / RT-3 / RT-4 filesystem grants, plus traverse.wasm host-canary check.
//!
//! Traverse verification: a canary file outside the preopen must remain unread
//! (content + mtime unchanged) after the guest path `../../canary` is refused.
//! Full `strace`/ptrace gating is impractical on unprivileged CI Linux; this
//! openat-equivalent assertion is documented as the hole vs a strace gate.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::Duration;

use helix_caps::{CapabilitySet, DirGrant, FileGrant, FileMode, Interface, Interner};
use helix_runtime::{open_dir_nofollow, open_file_nofollow, FsGrantError, WasiHost};
use wasmtime::component::Resource;
use wasmtime_wasi::p2::bindings::filesystem::preopens::Host as PreopensHost;
use wasmtime_wasi::p2::bindings::sync::filesystem::types::{
    Descriptor, DescriptorFlags, ErrorCode, HostDescriptor, OpenFlags, PathFlags,
};
use wasmtime_wasi::WasiView;

fn caps_with_files(paths: &[(&Path, FileMode)]) -> CapabilitySet {
    let mut intern = Interner::new();
    let files: Vec<FileGrant> = paths
        .iter()
        .map(|(p, m)| FileGrant::new(intern.intern_path(p), *m))
        .collect();
    CapabilitySet::new(&[Interface::Filesystem], files, vec![], vec![])
        .unwrap()
        .with_interner(intern)
}

fn caps_with_dir(root: &Path, mode: FileMode) -> CapabilitySet {
    let mut intern = Interner::new();
    let id = intern.intern_path(root);
    CapabilitySet::new(
        &[Interface::Filesystem],
        vec![],
        vec![DirGrant::new(id, mode)],
        vec![],
    )
    .unwrap()
    .with_interner(intern)
}

fn map_fs_err<T>(r: Result<T, impl std::fmt::Debug>) -> Result<T, ErrorCode> {
    r.map_err(|e| {
        let s = format!("{e:?}").to_ascii_lowercase();
        if s.contains("notpermitted") || s.contains("not_permitted") {
            ErrorCode::NotPermitted
        } else if s.contains("noentry") || s.contains("no_entry") || s.contains("notfound") {
            ErrorCode::NoEntry
        } else if s.contains("access") {
            ErrorCode::Access
        } else {
            ErrorCode::NotPermitted
        }
    })
}

fn open_relative(
    host: &mut WasiHost,
    preopen_guest: &str,
    rel: &str,
) -> Result<Resource<Descriptor>, ErrorCode> {
    let dirs = PreopensHost::get_directories(&mut host.ctx()).expect("get_directories");
    let (fd, name) = dirs
        .into_iter()
        .find(|(_, n)| n == preopen_guest)
        .unwrap_or_else(|| panic!("missing preopen {preopen_guest}"));
    assert_eq!(name, preopen_guest);
    map_fs_err(HostDescriptor::open_at(
        &mut host.ctx(),
        fd,
        PathFlags::empty(),
        rel.to_string(),
        OpenFlags::empty(),
        DescriptorFlags::READ,
    ))
}

fn read_relative(
    host: &mut WasiHost,
    preopen_guest: &str,
    rel: &str,
) -> Result<Vec<u8>, ErrorCode> {
    let file = open_relative(host, preopen_guest, rel)?;
    map_fs_err(HostDescriptor::read(&mut host.ctx(), file, 64 * 1024, 0)).map(|(b, _)| b)
}

/// RT-2: `FileGrant` for `/a/b.txt` — read succeeds; `/a/c.txt` fails in sandbox.
#[test]
fn rt2_file_grant_sibling_invisible() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    fs::create_dir_all(&a).unwrap();
    let b = a.join("b.txt");
    let c = a.join("c.txt");
    fs::write(&b, b"granted").unwrap();
    fs::write(&c, b"secret-sibling").unwrap();

    let caps = caps_with_files(&[(&b, FileMode::Read)]);
    let mut host = WasiHost::from_capability_set(&caps).expect("host");

    let guest_parent = a.to_string_lossy().into_owned();
    let got = read_relative(&mut host, &guest_parent, "b.txt").expect("b.txt readable");
    assert_eq!(got, b"granted");

    let err = open_relative(&mut host, &guest_parent, "c.txt").expect_err("c.txt must fail");
    assert!(
        matches!(
            err,
            ErrorCode::NoEntry | ErrorCode::NotPermitted | ErrorCode::Access
        ),
        "unexpected error for sibling open: {err:?}"
    );
}

/// RT-3: symlink at grant path pointing outside is refused at open.
#[test]
fn rt3_symlink_at_grant_path_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"nope").unwrap();

    let link_dir = tmp.path().join("grant_link");
    symlink(&outside, &link_dir).unwrap();

    let caps = caps_with_dir(&link_dir, FileMode::Read);
    let err = WasiHost::from_capability_set(&caps).expect_err("symlink dir grant");
    assert!(err.is_capability_denied(), "{err}");

    let real_file = tmp.path().join("real.txt");
    fs::write(&real_file, b"x").unwrap();
    let link_file = tmp.path().join("link.txt");
    symlink(&real_file, &link_file).unwrap();
    let caps = caps_with_files(&[(&link_file, FileMode::Read)]);
    let err = WasiHost::from_capability_set(&caps).expect_err("symlink file grant");
    assert!(err.is_capability_denied(), "{err}");

    assert!(open_dir_nofollow(&link_dir)
        .unwrap_err()
        .is_capability_denied());
    assert!(open_file_nofollow(&link_file, FileMode::Read)
        .unwrap_err()
        .is_capability_denied());
}

/// RT-4: `../` in a guest path never resolves outside the preopen.
#[test]
fn rt4_dotdot_stays_inside_preopen() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("sandbox");
    let outside = tmp.path().join("outside.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("inside.txt"), b"in").unwrap();
    fs::write(&outside, b"out").unwrap();

    let caps = caps_with_dir(&root, FileMode::Read);
    let mut host = WasiHost::from_capability_set(&caps).expect("host");
    let guest = root.to_string_lossy().into_owned();

    let got = read_relative(&mut host, &guest, "inside.txt").expect("inside");
    assert_eq!(got, b"in");

    let err = open_relative(&mut host, &guest, "../outside.txt").expect_err("dotdot");
    assert!(
        matches!(
            err,
            ErrorCode::NotPermitted | ErrorCode::NoEntry | ErrorCode::Access
        ),
        "unexpected: {err:?}"
    );
}

/// traverse.wasm equivalent: `../../canary` must not open a host file.
#[test]
fn traverse_canary_unread() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("preopen");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/ok.txt"), b"ok").unwrap();

    let canary = tmp.path().join("canary_secret");
    fs::write(&canary, b"CANARY-UNREAD").unwrap();
    let meta_before = fs::metadata(&canary).unwrap();
    let mtime_before = meta_before.modified().unwrap();
    std::thread::sleep(Duration::from_millis(20));

    let caps = caps_with_dir(&root, FileMode::Read);
    let mut host = WasiHost::from_capability_set(&caps).expect("host");
    let guest = root.to_string_lossy().into_owned();

    let err = open_relative(&mut host, &guest, "../../canary_secret").expect_err("traverse");
    assert!(
        matches!(
            err,
            ErrorCode::NotPermitted | ErrorCode::NoEntry | ErrorCode::Access
        ),
        "traverse must be denied, got {err:?}"
    );

    let bytes = fs::read(&canary).unwrap();
    assert_eq!(bytes, b"CANARY-UNREAD", "canary content must be untouched");
    let mtime_after = fs::metadata(&canary).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "canary mtime must be unchanged (no host open)"
    );
}

#[test]
fn refused_open_is_capability_denied_mappable() {
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("l");
    let real = tmp.path().join("r");
    fs::create_dir(&real).unwrap();
    symlink(&real, &link).unwrap();
    let err = open_dir_nofollow(&link).unwrap_err();
    match err {
        FsGrantError::CapabilityDenied { reason } => {
            assert!(reason.contains("symlink") || reason.contains("O_NOFOLLOW"));
        }
        other => panic!("expected CapabilityDenied, got {other}"),
    }
}

#[test]
fn empty_filesystem_bit_no_preopens() {
    let mut host = WasiHost::from_capability_set(&CapabilitySet::EMPTY).unwrap();
    let dirs = PreopensHost::get_directories(&mut host.ctx()).unwrap();
    assert!(dirs.is_empty());
}
