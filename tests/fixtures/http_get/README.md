# http_get.wasm

Benchmark / RT fixture: GET a local mock HTTP server and return the status.

**HLX-30:** Host-path coverage lives in `helix-runtime` test
`http_get_against_local_mock` (real TCP + `HostGrant` link). A guest
component binary can be built later with `waki` / `wstd` against
`wasi:http/outgoing-handler`; the host handler is what enforces grants.
