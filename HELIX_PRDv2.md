Product Requirements Document: Project HELIX

HELIX: Hardware-Enforced Logic & Interaction eXecution Target release: Q1 2027 Status: In design, v2 Document owner: Platform Engineering

1. Summary

HELIX is a Rust-native, capability-based execution bridge that sits between an agent network protocol and the host machine. It is a two-stage pipeline:

The Gateway converts a network request into a verified identity and a CapabilitySet.
The Runtime instantiates a blank WebAssembly sandbox and populates it with exactly that CapabilitySet, nothing more.

A tool running inside HELIX starts with zero ambient authority. Every file, network host, clock, and byte of memory it can touch was granted explicitly for that one invocation, is recorded in an audit log, and is revoked when the invocation ends.

1.1 Problem

Agent communication protocols (PAP, ACP, A2A, MCP) have matured. The execution layer has not. Current frameworks run tools with the permissions of the host process or a broad container, and rely on the model to respect boundaries. A prompt-injected or compromised upstream agent can therefore turn any exposed tool into a foothold on the host. Securing the transport does not secure execution.

1.2 Non-goals

HELIX will not:

Replace or implement an agent orchestration protocol. It consumes one.
Protect against a compromised host kernel or hypervisor.
Provide side-channel isolation between concurrently running sandboxes (timing, cache). This may be revisited in a later phase; it is explicitly out of scope for v1.
Run untrusted native code. Only WebAssembly components are executed.
Support more than one wire protocol in v1.
Target no_std or bare-metal environments in v1 (see Section 9).
2. Threat Model
2.1 Adversaries in scope
Adversary	Capability assumed	HELIX defense
Compromised or malicious calling agent	Holds a valid, possibly stolen, credential; sends arbitrary payloads; attempts privilege escalation via delegation	Key-bound tokens (DPoP), downhill-only delegation enforced by lattice check, payload validation before instantiation, output size cap
Authorized caller via delegation	Holds a valid credential and a grant; fans out or nests children to exhaust pool / host resources	A10: `max_delegation_depth`, `max_children`, and per-identity `max_concurrent_instances` (ADR-008 A.4, ADR-009 B.1); tests RT-14, GW-15
Malicious or replaced tool component	Arbitrary wasm code; attempts to reach files, network, or memory beyond its grant; attempts to run forever or exhaust memory	Content-digest tool identity, blank-linker instantiation, ResourceLimiter, epoch deadline, cancellable host calls
Network attacker	Replays or forwards captured requests	DPoP proof with jti replay cache and server nonce
2.2 Out of scope

Compromised host OS, hardware side channels, denial of service against the gateway's TCP listener (delegate to the deployment's ingress layer).

**Supersession (ADR-008/009 / HLX-9):** Sections 3, 4, and 5.5 below are retained for history. The authoritative shapes are `interfaces/helix-caps-api.rs`, `interfaces/state-machine.md`, `interfaces/audit-record.md`, `interfaces/delegate.md`, and `interfaces/gateway-protocol.md`. Prefer those files.

3. Core Data Model

The design flows from one type. Everything else is a pure function of it or a record of it.

3.1 CapabilitySet

Lives in the dependency-free crate helix-caps (only serde). Every other crate imports it.

rust
/// The complete authority available to one sandbox for one invocation.
/// Forms a lattice under subset; `is_subset_of` is the only ordering.
pub struct CapabilitySet {
    /// Bitset over a fixed enum of WASI interfaces (stdio, clocks, random,
    /// filesystem, http-outbound, ...). Bit set = interface is linked.
    pub interfaces: u64,
    /// Sorted, deduplicated. Canonical host path resolved at policy time.
    pub files: Vec<FileGrant>,
    /// Sorted, deduplicated. Authority (host:port) plus allowed methods.
    pub hosts: Vec<HostGrant>,
    pub budget: Budget,
}

pub struct FileGrant { pub canonical_path: PathBuf, pub mode: FileMode }
pub struct HostGrant { pub authority: String, pub methods: MethodMask }

pub struct Budget {
    pub epoch_ticks: u32,      // wasm preemption deadline
    pub wall_clock_ms: u32,    // hard deadline including host calls
    pub memory_bytes: u64,     // linear memory ceiling
    pub output_bytes: u32,     // maximum result size returned to caller
}

Operations, all pure:

a.is_subset_of(&b) -> bool: bitwise AND on interfaces, sorted-merge walk on files and hosts, componentwise <= on budget.
attenuate(parent: &CapabilitySet, requested: &CapabilitySet) -> Result<CapabilitySet, AttenuationError>: returns requested if and only if requested.is_subset_of(parent). This is the entire delegation policy.
3.2 Identity
rust
/// SHA-256 of the agent's Ed25519 public key. The single identity of an agent.
pub struct Identity([u8; 32]);

The OAuth subject, audit records, and policy lookups all derive from this value. No other field carries agent identity.

3.3 ToolDigest
rust
/// SHA-256 of the component bytes. The single identity of a tool.
pub struct ToolDigest([u8; 32]);

Human-readable names (read_customer_db) live in an alias table name -> ToolDigest. Policy, the compiled artifact cache, and audit records key on the digest only. Replacing a component changes its digest and therefore loses every grant tied to the old one.

3.4 Policy
rust
pub fn policy(id: Identity, tool: ToolDigest) -> Option<CapabilitySet>

A pure lookup against an immutable, atomically swappable snapshot (arc-swap). Hot reload replaces the whole snapshot; there is no in-place mutation.

3.5 Invocation record

Every state transition (Section 4) appends one record:

rust
pub struct AuditRecord {
    pub request_id: RequestId,
    pub parent_request_id: Option<RequestId>,
    pub identity: Identity,
    pub tool: ToolDigest,
    pub caps: CapabilitySet,          // omitted on transitions that do not change it
    pub transition: Transition,
    pub monotonic_ts: u64,
    pub prev_hash: [u8; 32],           // hash chain
}
4. Invocation State Machine
State	Entered when	Exit transitions	On failure
Received	Bytes parsed as a well-formed request envelope	Authenticated	Failed(Malformed); nothing logged beyond a rate-limited counter
Authenticated	Signature, DPoP proof, and replay check pass; Identity derived	Authorized	Failed(Unauthenticated); audit record written
Authorized	policy(id, digest) returns Some; delegation attenuation passes; payload validates against the tool's WIT signature	Provisioned	Failed(Denied); audit record written with the requested and available sets
Provisioned	Store created with ResourceLimiter, epoch deadline set, Linker built from CapabilitySet, instance created from InstancePre	Running	Failed(Provision); audit record written; Store dropped
Running	invoke export called	Completed, Failed(ToolError), `Killed(Epoch	WallClock

Terminal states: Completed, Failed(_), Killed(_). The Granted audit record (at Provisioned) and the terminal record are written synchronously before the response is sent. All others are buffered.

4.1 Safety properties
S1. A sandbox never holds a capability absent from its CapabilitySet. Enforced structurally: the Linker is built only from the set, and the set is immutable after Authorized. Asserted with debug_assert! at Linker construction.
S2. For every delegation, child.caps.is_subset_of(&parent.caps). Asserted at token mint; a violation is a bug, not an error, and aborts.
S3. No Store outlives the request that created it. Enforced by ownership: the Store is a local of the request future.
S4. No bytes beyond budget.output_bytes are returned to the caller. Enforced by a bounded writer on the result channel.
4.2 Liveness properties
L1. Every invocation reaches a terminal state within budget.wall_clock_ms. Argument: wasm code is preempted within one epoch tick (epoch interruption fires at loop back-edges and function entries, so preemption is bounded, not instantaneous); every host function takes a CancellationToken and is cancel-safe; the wall-clock timer cancels the token; dropping the request future drops the Store.
L2. A dropped parent request cancels all child invocations. Argument: children are spawned into the parent's JoinSet, which aborts on drop.
5. Architecture
5.1 Crate layout
helix-caps      CapabilitySet, Identity, ToolDigest, Budget, lattice ops (no deps beyond serde)
helix-policy    policy snapshot, alias table, attenuate
helix-gateway   axum server, request parsing, DPoP verification, replay cache
helix-runtime   wasmtime engine, artifact cache, InstancePre pool, Linker projection, execution
helix-audit     hash-chained append-only log, OTel exporter
helix-sdk       #[helix_tool] macro, WIT world, component build support

Dependencies flow downward only. helix-caps has no HELIX dependencies.

5.2 Gateway (helix-gateway)
Transport: axum over HTTP/1.1 and HTTP/2, JSON-RPC 2.0 envelopes in the PAP-Hooks structure. One protocol in v1.
Token format: JWT with alg pinned to EdDSA. Any other alg value is rejected before parsing claims. No algorithm negotiation.
DPoP: Every request carries a DPoP proof signed by the agent's Ed25519 key. The access token's cnf.jkt must match the proof key. Proofs carry jti and a server-issued nonce; jti values are held in a sharded expiring set (time-wheel, no global lock) for the proof's validity window.
Identity derivation: Identity = sha256(public_key_bytes). Computed once, carried through the request.
Payload validation: Before instantiation, the request payload is validated against the tool's exported WIT signature (Section 5.4). Malformed input is rejected in the gateway.
Context stripping: Nothing from the HTTP layer crosses into the runtime except Identity, ToolDigest, the validated payload, and the CapabilitySet.

Pure functions in this crate: verify(request) -> Result<Identity>, derive_identity(key) -> Identity, validate_payload(&WitSignature, &[u8]) -> Result<()>.

5.3 Runtime (helix-runtime)

Compilation. A component is compiled once per ToolDigest. The compiled artifact is stored in a local cache keyed on digest and loaded with Module::deserialize. Compilation never happens on the request path.

Instantiation. Each digest has an InstancePre prepared against a Linker template. Per request, the runtime:

Creates a Store with a ResourceLimiter from budget.memory_bytes.
Sets the epoch deadline from budget.epoch_ticks. A single ticker thread advances the engine epoch at a fixed interval.
Projects the CapabilitySet into the linker: link(&CapabilitySet) -> Linker. This is a pure function. Interfaces whose bit is clear are not linked; the component's import resolves to nothing and instantiation fails closed.
Instantiates from the InstancePre using the pooling allocator (PoolingAllocationConfig).
Calls invoke with a bounded output writer.
Drops the Store.

Filesystem grants. At policy time, each FileGrant.canonical_path is resolved with symlinks fully expanded. At request time, the runtime opens the file with openat relative to a root descriptor, O_NOFOLLOW, and the mode in the grant. The sandbox receives the descriptor through wasi:filesystem/preopens. Path strings never cross the boundary.

Network grants. wasi:http/outgoing-handler is linked only when the http bit is set, and the host implementation rejects any request whose authority and method are not in hosts.

Cancellation. Every host function receives a CancellationToken cloned from the request. Blocking host operations use tokio::select! against it.

Concurrency model. tokio only. The request future owns the Store. Child invocations spawn into the parent's JoinSet. There is no actor system.

5.4 Tool interface (helix-sdk)

Tools are WebAssembly components targeting wasm32-wasip2 and export the HELIX world:

wit
package helix:tool@1.0.0;

interface types {
    variant invoke-error {
        invalid-input(string),
        capability-denied(string),
        internal(string),
    }
}

world tool {
    include wasi:cli/imports@0.2.0;
    use types.{invoke-error};
    export invoke: func(input: list<u8>) -> result<list<u8>, invoke-error>;
    export signature: func() -> string;   // JSON Schema of `input`, read at registration
}

The #[helix_tool] macro wraps a typed Rust function, generates the signature export from the argument type via schemars, and generates invoke with deserialization and error mapping:

rust
#[helix_tool]
fn query_db(req: QueryRequest) -> Result<QueryResponse, ToolError> { ... }

The gateway reads signature once at registration and uses it for payload validation (Section 5.2). Tools never parse untrusted bytes themselves.

5.5 Audit (helix-audit)

Two separate concerns:

Store. An append-only local file of AuditRecords. Each record commits to sha256(previous record). Granted and terminal records are written with fdatasync before the response is sent. Others are batched.
Export. A separate task tails the store and emits OpenTelemetry spans (one span per invocation, one event per transition). The exporter may drop under backpressure; the store never does.
6. Requirements
6.1 P0 (MVP)
ID	Requirement
P0-1	helix-caps with CapabilitySet, Identity, ToolDigest, Budget, is_subset_of, attenuate
P0-2	Gateway accepting JSON-RPC 2.0 over HTTP, EdDSA-only JWT validation, identity derivation
P0-3	Policy snapshot keyed on (Identity, ToolDigest), alias table, atomic reload
P0-4	Runtime: precompiled artifact cache, InstancePre per digest, pooling allocator, per-request Store
P0-5	ResourceLimiter, epoch deadline, wall-clock cancellation, output byte cap, all driven from Budget
P0-6	Capability projection for stdio, clocks, random, and scoped filesystem via openat/O_NOFOLLOW
P0-7	Payload validation against the tool's exported signature
P0-8	Hash-chained audit store with synchronous Granted and terminal writes
P0-9	helix-sdk with #[helix_tool] and the helix:tool WIT world
6.2 P1 (Production)
ID	Requirement
P1-1	DPoP enforcement with jti replay cache and server nonces
P1-2	Delegation: child tokens minted via attenuate, parent_request_id in audit records, JoinSet cancellation
P1-3	wasi:http outbound with HostGrant enforcement  **(D-1 / HLX-2 locked 2026-09-03: wasi:http outbound is P0; remains scheduled as M4-07 / HLX-30 in the 14-week plan. This row's P1 label is historical.)**
P1-4	OTel exporter tailing the audit store
P1-5	Operational metrics: instantiation latency, epoch kills, memory kills, policy denials
6.3 P2 (Advanced)
ID	Requirement
P2-1	PAP-CP control-plane adapter (Satellite role), as a separate crate, added only when a second protocol is real
P2-2	Policy authoring UI or CLI
7. Performance

The hot path per request: proof verification, policy lookup, Store creation, linker projection, instantiation, invoke, teardown, two synchronous audit writes.

Rough per-core cost estimates, to be replaced by measurement:

Step	Estimate
Ed25519 verify (JWT + DPoP)	50 to 100 µs
Policy lookup	< 1 µs
Pooled instantiation	5 to 20 µs
Two fdatasync audit writes	dominated by storage; NVMe ~50 to 200 µs
Tool body	tool-dependent

Targets for v1: ≥ 2,000 invocations per second per core for a trivial tool with a 1 KB payload; p99 overhead (excluding tool body) ≤ 2 ms.

Working set: precompiled artifacts (tens of MB for a typical tool catalogue) plus N × memory_bytes for the pooling allocator, where N is the configured concurrent instance limit.

First benchmark to run: instantiate plus trivial invoke with a 1 KB payload, measured at 1, 8, and 64 concurrent requests, with and without the synchronous audit writes.

Nothing outside this path is optimized. The policy loader, artifact compiler, and exporter are written for clarity.

8. Verification

Pure functions (unit and property tested, no I/O): is_subset_of, attenuate, derive_identity, policy, validate_payload, link, AuditRecord::hash.

Property tests (proptest):

attenuate(p, r) never returns a set that is not a subset of p.
Lattice laws on CapabilitySet: reflexive, antisymmetric, transitive, exhaustively over small enumerated sets.
link(caps) binds exactly the interfaces whose bits are set.

Fuzzing (cargo-fuzz): request envelope parser, DPoP proof parser, payload validator, WIT signature parser.

Assertions: S1 at Linker build, S2 at token mint, S4 at the output writer. Preconditions on every helix-caps constructor (sorted, deduplicated vectors).

Static analysis: #![deny(warnings)], clippy::pedantic, #![forbid(unsafe_code)] in every crate except helix-runtime, Miri on helix-caps and helix-audit in CI.

Integration tests: one test per row of the state table in Section 4, including each failure edge. A test suite of adversarial components: infinite loop, memory bomb, output flood, path traversal attempt, unlinked import.

9. Future Work (not in scope)

Bare-metal runtime. A deployment without a host OS would require an interpreter-backed engine (Wasmtime's Pulley), since JIT and AOT-loaded native code both need executable memory mappings that a kernel context does not provide. This is a sibling runtime with a different performance envelope, not a build flag. If pursued, helix-caps carries over unchanged; helix-runtime does not.

Side-channel isolation. Per-core pinning or temporal isolation between sandboxes of different identities.

10. Success Criteria
Every P0 requirement shipped with its Section 8 tests passing in CI.
Adversarial component suite: zero escapes, all terminated within budget.wall_clock_ms.
Benchmark in Section 7 meets targets on the reference hardware.
An external tool author can build, register, and invoke a tool using only helix-sdk documentation.