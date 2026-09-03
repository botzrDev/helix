# Policy File Format (v1)

One TOML file, loaded at startup and on `SIGHUP`. Parsing produces an immutable `PolicySnapshot` held in an `arc_swap::ArcSwap`. A snapshot that fails validation is rejected in full and the previous snapshot stays live.

## 1. Structure

```toml
version = 1

# Alias table. Every alias must resolve to a digest present in the artifact store.
[tools]
read_customer_db = "sha256:ab34c1...ff"
summarize_pdf    = "sha256:9e1d02...03"

# Budgets are named so grants can reference them.
# preempt_ticks defaults to wall_clock_ms (tick pinned at 1 ms); omit unless lower.
[budgets.default]
wall_clock_ms            = 2000
memory_bytes             = 67108864      # 64 MiB
output_bytes             = 1048576       # 1 MiB
max_delegation_depth     = 2
max_children             = 8
max_concurrent_instances = 32

[budgets.heavy]
preempt_ticks            = 5000
wall_clock_ms            = 30000
memory_bytes             = 536870912
output_bytes             = 8388608
max_delegation_depth     = 2
max_children             = 8
max_concurrent_instances = 32

# Identities are named for readability. Value is the RFC 7638 JWK thumbprint
# as base64url (same string as JWT `sub` / `cnf.jkt`).
[identities]
billing_agent   = "7c1ea0...base64url"
research_agent  = "44f9b3...base64url"

# One grant per (identity, tool). Missing = denied.
# Grants pin both alias and digest (rule 10).
[[grants]]
identity   = "billing_agent"
tool       = "read_customer_db"
digest     = "sha256:ab34c1...ff"
interfaces = ["stdio", "clocks", "filesystem"]
budget     = "default"
files = [
  { path = "/srv/data/customers.sqlite", mode = "read" },
]

[[grants]]
identity   = "research_agent"
tool       = "summarize_pdf"
digest     = "sha256:9e1d02...03"
interfaces = ["stdio", "clocks", "random", "filesystem", "http_outbound"]
budget     = "heavy"
dirs = [
  { path = "/srv/inbox", mode = "read" },
]
hosts = [
  { authority = "api.example.com:443", methods = ["GET", "POST"] },
]
```

## 2. Validation rules (all fatal)

Structural pass (`validate_structural`; no I/O): rules 1, 3, 4, 6, 7, 8, 9, 10, 11, 12.
Host resolve pass (`resolve_host`; needs artifact store and filesystem): rules 2 and 5.

1. `version` must be `1`.
2. Every `[tools]` digest must exist in the artifact store.
3. Every `grants[].identity` must be a key in `[identities]`; every `grants[].tool` a key in `[tools]`.
4. `(identity, tool)` pairs must be unique.
5. `files[].path` must be absolute and canonicalize to a regular file. `dirs[].path` must be absolute and canonicalize to a directory. Symlinks at either path are fatal at load. Directory grants are not expanded to descendant files; one `DirGrant` is one cap-std preopen. Enforcement of what may be opened beneath a directory root stays at open time (`O_NOFOLLOW`, cap-std, RT-3, RT-4).
6. `files` or `dirs` non-empty requires `"filesystem"` in `interfaces`; `hosts` non-empty requires `"http_outbound"`. The reverse is allowed (interface linked, no grants) but logged at `warn`.
7. `hosts[].authority` must include an explicit port and be lowercase.
8. Every referenced budget must exist.
9. Every `hosts[].methods` entry must be one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`.
10. Every `[[grants]]` entry carries both `tool` (alias) and `digest`. The grant's digest must equal the alias's entry in `[tools]`. Disagreement is fatal.
11. When `preempt_ticks` is present, `preempt_ticks <= wall_clock_ms`. Structural; the ticker is pinned at 1 ms so the derived default is `wall_clock_ms`.
12. `max_concurrent_instances` must be at least 1. Whether an identity's cap exceeds `runtime.max_concurrent_instances` is logged at `warn` in the host pass (not structurally checkable).

## 3. Evaluation

```
policy(identity, digest) -> Option<(CapabilitySet, ResourceBudget)>
```

A direct `HashMap<(Identity, ToolDigest), ...>` lookup. There are no rule orderings, wildcards, or precedence in v1. If you need "everyone can call `helix.health`", that is not a policy question; `helix.health` is unauthenticated by protocol.

**Authority composition (delegation).** Child effective authority:

```
attenuate(parent_effective, meet(policy(parent_identity, child_digest), requested))
```

There is no HTTP child path; composition runs in `runtime::delegate` (see `interfaces/delegate.md`).

**Resource composition.** `ResourceBudget` is a sibling of `CapabilitySet`, not part of the lattice. The child's budget must be `is_within` both the child's policy budget and the parent's budget. Every `[budgets.*]` table carries `max_delegation_depth` (default 2) and `max_children` (default 8). Depth is counted from the root request. Fan-out is per parent (`JoinSet::len()`). Exceeding either refuses the child (`delegate-error::depth` / `::fanout`). `max_concurrent_instances` (default 32) bounds live instances attributable to one identity on one gateway.

## 4. Reload

- `SIGHUP` or `helix-ctl policy reload`.
- New file is parsed and validated in full. On success the snapshot is swapped atomically; in-flight request trees keep the `PolicyGuard` they captured at admission.
- On failure the error is logged and the old snapshot remains. `helix.health` reports `policy_version` when `gateway.health_detail = full` so operators can confirm the swap.
- `policy.max_snapshot_age_s` (default 300) bounds how long an old snapshot may stay live through delegation.

## 5. Tooling

- `helix-ctl policy check <file>`: always runs the structural pass. With `--artifacts <dir>` also runs the host resolve pass. Prints which passes ran. Without the host pass, exits 0 with a clearly labeled `structural only` line. Does not expand directory grants into file lists.
- `helix-ctl policy explain <identity> <tool>`: prints the effective `CapabilitySet` and `ResourceBudget` as JSON.
