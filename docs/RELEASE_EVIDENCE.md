# Production release evidence

**Status:** complete. This evidence covers the private `bpc-tsk-rust` release source, its exact standalone dependencies and its executable `bpc-tsk-service`.

## Immutable composition inputs

| Component | Repository | Exact source revision | Exact package version |
|---|---|---|---|
| BPC | `rblake2320/bpc-rust-protocol` | `f67d00db46a49e8babcaa074fa56ad7adbc1e2ec` | `0.1.0` |
| TSK | `rblake2320/tsk-rust-protocol` | `7ca5644c625dbe0465ce945625b0904b6014aaed` | `0.1.0` |
| Composition | `rblake2320/bpc-tsk-rust` | this checked-in release | `0.1.0` |

The core and service manifests specify both the immutable Git revision and `=0.1.0` package version. `Cargo.lock` resolves one source for each standalone protocol. Neither standalone crate imports the other; composition is confined to this third workspace.

## Locked source and dependency gates

The final source completed all of the following with Rust/Cargo 1.85.0, a locked dependency graph and warnings promoted to failure:

```sh
cargo fmt --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --release -p bpc-tsk-service
cargo-deny check advisories bans licenses sources
cargo audit
semgrep --config auto --error .
git diff --check
```

The workspace test run passed all non-live tests (27 bridge/core, 16 service library and transport/configuration, and 2 executable CLI tests). The explicit PostgreSQL authority, TLS, concurrency, bounded wait, delivery-state, role-separation and migration-upgrade drills were also run against fresh disposable authorities. Security scans found no blocking Semgrep finding and no blocking RustSec/Cargo Deny advisory or source/license policy violation. The standalone BPC and TSK repositories completed their own pinned release suites before the service was repinned to these source revisions.

CycloneDX all-feature dependency inventories are checked in under [`sbom/`](../sbom/), with offline reproduction instructions and SHA-256 digests in [`sbom/README.md`](../sbom/README.md).

## Live private-authority proof

A fresh, disposable validation topology used only loopback listeners and distinct private authority material:

- separate BPC, TSK and bridge PostgreSQL databases, schemas, migrator roles and verifier roles;
- a private PostgreSQL CA with hostname-verified TLS connections;
- governed BPC Redis with a new namespace/epoch, explicit quarantine/reconciliation, private CA and client mutual TLS;
- distinct BPC, TSK, bridge and Redis CA files to exercise the service file-isolation controls;
- runtime verifier grants applied only after public API migrations/provisioning; runtime roles were checked non-superuser, non-role-admin and non-database-admin;
- two optimized `bpc-tsk-service` release binaries started independently on distinct private loopback listeners while sharing only the durable authority systems.

New BPC pair, TSK map and bridge binding records were provisioned through public BPC, TSK and bridge lifecycle APIs. No direct credential-table insert was used. Each successful proof used an independently generated, current 64-character TSK v1 credential.

The final cross-process proof completed this sequence:

1. A valid request with a deliberately corrupted BPC signature received a generic empty `401`.
2. The same untouched TSK HOTP credential, now with a valid BPC request, received empty `204`; this demonstrates the BPC failure caused no TSK consumption.
3. An exact replay of the valid BPC signed request was sent to the second service process and received generic empty `401`; BPC’s shared governed nonce authority rejected it before TSK.
4. A newly BPC-signed request with a fresh nonce but the consumed TSK HOTP credential was sent to the second service process and received generic empty `401`; TSK’s shared PostgreSQL authority rejected the replay.
5. Both release listeners remained `readyz=204` after the proof.

The helper verifies empty bodies, no-store denial headers and absence of factor/error response headers. It does not print request headers, keys, registration secrets, DSNs, maps or database diagnostics. This live proof is in addition to the core regression that exhausts the mandatory TSK limiter and demonstrates that the same HOTP credential remains usable through an unrestricted adapter, proving limiter denial occurs before TSK state mutation.

## Assertions demonstrated

- BPC runs before any bridge binding/TSK access.
- Malformed or rejected BPC results do not look up or consume TSK HOTP state.
- Duplicate/malformed factor input and identity/binding inconsistencies fail closed before TSK by bridge unit and adversarial tests.
- BPC replay state is shared across live service processes.
- TSK HOTP state is shared across live service processes.
- The service runs from its optimized release artifact with private CA TLS and Redis mutual TLS rather than mocked authority transports.
- BPC, TSK, bridge and audit trust domains remain separate; no TSK shared secret is passed to BPC or persisted by the bridge.
