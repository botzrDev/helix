//! POL-3, POL-4, POL-5 (test-plan.md). M2-02 / HLX-15.

use std::time::{Duration, Instant};

use helix_caps::{Interface, ToolDigest};
use helix_policy::{
    encode_thumbprint, parse_identity_thumbprint, parse_tool_digest, resolve_host, MapFs,
    MemoryArtifactStore, PathKind, PolicyFile, PolicyGuard, PolicyHolder,
    DEFAULT_MAX_SNAPSHOT_AGE_S, STALE_SNAPSHOT_REASON,
};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn thumb(byte: u8) -> String {
    encode_thumbprint(&[byte; 32])
}

fn valid_toml() -> String {
    format!(
        r#"
version = 1

[tools]
read_db = "{DIGEST_A}"
sum_pdf = "{DIGEST_B}"

[budgets.default]
wall_clock_ms = 2000
memory_bytes = 67108864
output_bytes = 1048576

[budgets.heavy]
preempt_ticks = 5000
wall_clock_ms = 30000
memory_bytes = 536870912
output_bytes = 8388608

[identities]
billing = "{billing}"
research = "{research}"

[[grants]]
identity = "billing"
tool = "read_db"
digest = "{DIGEST_A}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"
files = [{{ path = "/srv/data/customers.sqlite", mode = "read" }}]

[[grants]]
identity = "research"
tool = "sum_pdf"
digest = "{DIGEST_B}"
interfaces = ["stdio", "clocks", "random", "filesystem", "http_outbound"]
budget = "heavy"
dirs = [{{ path = "/srv/inbox", mode = "read" }}]
hosts = [{{ authority = "api.example.com:443", methods = ["GET", "POST"] }}]
"#,
        billing = thumb(1),
        research = thumb(2),
    )
}

/// Valid policy with an extra grant (used as a successful reload target).
fn valid_toml_with_extra_grant() -> String {
    format!(
        r#"
version = 1

[tools]
read_db = "{DIGEST_A}"
sum_pdf = "{DIGEST_B}"
extra = "{DIGEST_C}"

[budgets.default]
wall_clock_ms = 2000
memory_bytes = 67108864
output_bytes = 1048576

[budgets.heavy]
preempt_ticks = 5000
wall_clock_ms = 30000
memory_bytes = 536870912
output_bytes = 8388608

[identities]
billing = "{billing}"
research = "{research}"

[[grants]]
identity = "billing"
tool = "read_db"
digest = "{DIGEST_A}"
interfaces = ["stdio", "clocks", "filesystem"]
budget = "default"
files = [{{ path = "/srv/data/customers.sqlite", mode = "read" }}]

[[grants]]
identity = "research"
tool = "sum_pdf"
digest = "{DIGEST_B}"
interfaces = ["stdio", "clocks", "random", "filesystem", "http_outbound"]
budget = "heavy"
dirs = [{{ path = "/srv/inbox", mode = "read" }}]
hosts = [{{ authority = "api.example.com:443", methods = ["GET", "POST"] }}]

[[grants]]
identity = "billing"
tool = "extra"
digest = "{DIGEST_C}"
interfaces = ["stdio", "clocks"]
budget = "default"
"#,
        billing = thumb(1),
        research = thumb(2),
    )
}

fn invalid_toml_rule1() -> String {
    valid_toml().replacen("version = 1", "version = 99", 1)
}

fn map_fs_ok() -> MapFs {
    MapFs::new()
        .insert("/srv", PathKind::Directory)
        .insert("/srv/data", PathKind::Directory)
        .insert("/srv/data/customers.sqlite", PathKind::File)
        .insert("/srv/inbox", PathKind::Directory)
}

fn store_ok() -> MemoryArtifactStore {
    let a = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let b = parse_tool_digest("sum_pdf", DIGEST_B).unwrap();
    let c = parse_tool_digest("extra", DIGEST_C).unwrap();
    MemoryArtifactStore::new()
        .with_digest(a)
        .with_digest(b)
        .with_digest(c)
        .with_runtime_max(256)
}

fn holder() -> PolicyHolder {
    PolicyHolder::load(
        &valid_toml(),
        &store_ok(),
        &map_fs_ok(),
        DEFAULT_MAX_SNAPSHOT_AGE_S,
    )
    .expect("valid policy loads")
}

/// POL-3: Lookup miss returns `None`; hit returns the exact `CapabilitySet` and `ResourceBudget`.
#[test]
fn pol3_lookup_hit_and_miss() {
    let holder = holder();
    let guard = holder.guard();

    let billing = parse_identity_thumbprint("billing", &thumb(1)).unwrap();
    let research = parse_identity_thumbprint("research", &thumb(2)).unwrap();
    let digest_a = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let digest_b = parse_tool_digest("sum_pdf", DIGEST_B).unwrap();
    let unknown = ToolDigest::from_bytes([0xee; 32]);

    // Hit.
    let (caps, budget) = guard
        .policy(&billing, &digest_a)
        .expect("billing/read_db grant");
    assert!(caps.has(Interface::Filesystem));
    assert!(!caps.has(Interface::HttpOutbound));
    assert_eq!(budget.wall_clock_ms(), 2000);
    assert_eq!(budget.preempt_ticks(), 2000);
    assert_eq!(budget.max_delegation_depth(), 2);

    let (caps2, budget2) = guard
        .policy(&research, &digest_b)
        .expect("research/sum_pdf grant");
    assert!(caps2.has(Interface::HttpOutbound));
    assert_eq!(budget2.preempt_ticks(), 5000);
    assert_eq!(budget2.wall_clock_ms(), 30000);

    // Miss: wrong pairing / unknown digest.
    assert!(guard.policy(&billing, &digest_b).is_none());
    assert!(guard.policy(&research, &digest_a).is_none());
    assert!(guard.policy(&billing, &unknown).is_none());

    // Alias resolution + disagreement check (-32003 territory).
    assert_eq!(guard.resolve_alias("read_db"), Some(digest_a));
    assert!(guard.resolve_alias("nope").is_none());
    assert!(guard.check_alias_digest("read_db", &digest_a).is_ok());
    let disagree = guard.check_alias_digest("read_db", &digest_b).unwrap_err();
    assert!(matches!(
        disagree,
        helix_policy::AliasDigestError::Disagreement { .. }
    ));
}

/// POL-4: Reload with an invalid file leaves the prior snapshot live.
#[test]
fn pol4_invalid_reload_keeps_prior() {
    let holder = holder();
    let before = holder.policy_version();
    let guard_before = holder.guard();
    let billing = parse_identity_thumbprint("billing", &thumb(1)).unwrap();
    let digest_a = parse_tool_digest("read_db", DIGEST_A).unwrap();
    assert!(guard_before.policy(&billing, &digest_a).is_some());

    let err = holder
        .reload(&invalid_toml_rule1(), &store_ok(), &map_fs_ok())
        .expect_err("rule 1 must fail reload");
    assert!(
        err.iter().any(|e| e.rule() == Some(1)),
        "expected rule 1, got {err:?}"
    );

    assert_eq!(holder.policy_version(), before, "version must not advance");
    let guard_after = holder.guard();
    assert_eq!(guard_after.version(), before);
    assert!(
        guard_after.policy(&billing, &digest_a).is_some(),
        "prior grants must remain"
    );
    // Captured parent guard still resolves against the old snapshot Arc.
    assert!(guard_before.policy(&billing, &digest_a).is_some());
}

/// POL-5: Reload mid-parent; child resolves against the parent's snapshot;
/// a child delegated after `max_snapshot_age_s` is refused.
#[test]
fn pol5_reload_mid_parent_and_stale_age() {
    let holder = holder();
    let parent = holder.guard();
    let parent_version = parent.version();
    let billing = parse_identity_thumbprint("billing", &thumb(1)).unwrap();
    let digest_a = parse_tool_digest("read_db", DIGEST_A).unwrap();
    let digest_c = parse_tool_digest("extra", DIGEST_C).unwrap();

    // Parent sees original grants only.
    assert!(parent.policy(&billing, &digest_a).is_some());
    assert!(parent.policy(&billing, &digest_c).is_none());
    assert!(parent.check_age().is_ok());

    // Reload succeeds; live holder advances.
    let new_version = holder
        .reload(&valid_toml_with_extra_grant(), &store_ok(), &map_fs_ok())
        .expect("valid reload");
    assert_ne!(new_version, parent_version);
    assert_eq!(holder.policy_version(), new_version);

    let live = holder.guard();
    assert_eq!(live.version(), new_version);
    assert!(
        live.policy(&billing, &digest_c).is_some(),
        "new snapshot has extra grant"
    );

    // Child inherits parent's guard → still the pre-reload snapshot (ADR-008 C.3).
    let child = parent.clone();
    assert_eq!(child.version(), parent_version);
    assert!(
        child.policy(&billing, &digest_c).is_none(),
        "child must not observe the reloaded grant"
    );
    assert!(child.policy(&billing, &digest_a).is_some());

    // Age check: inject a clock past max_snapshot_age_s.
    let stale_now = parent.loaded_at() + Duration::from_secs(DEFAULT_MAX_SNAPSHOT_AGE_S + 1);
    assert!(parent.is_stale_at(stale_now));
    assert_eq!(parent.check_age_at(stale_now), Err(STALE_SNAPSHOT_REASON));

    // Fresh live guard is not stale.
    assert!(live.check_age_at(Instant::now()).is_ok());
}

#[test]
fn pol5_stale_with_zero_max_age() {
    // max_snapshot_age_s = 0 ⇒ any positive age is stale ("older than 0").
    let file = PolicyFile::parse(&valid_toml()).unwrap();
    let snap = resolve_host(&file, &store_ok(), &map_fs_ok()).unwrap();
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("clock");
    let guard = PolicyGuard::from_snapshot(snap.with_loaded_at(past), 0);
    assert_eq!(guard.check_age(), Err(STALE_SNAPSHOT_REASON));
}

#[test]
fn holder_load_rejects_invalid() {
    let result = PolicyHolder::load(
        &invalid_toml_rule1(),
        &store_ok(),
        &map_fs_ok(),
        DEFAULT_MAX_SNAPSHOT_AGE_S,
    );
    let Err(err) = result else {
        panic!("invalid policy must not load");
    };
    assert!(err.iter().any(|e| e.rule() == Some(1)));
}
