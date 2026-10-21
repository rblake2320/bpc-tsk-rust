# Production-readiness declaration

## Status

**Production ready.** `bpc-tsk-rust` is the deployable private-edge composition of the independently version-pinned `bpc-protocol` and `tsk-rust-protocol` releases. It is a service product, not only a library or GitHub artifact.

The service implements the BPC-first contract: it rejects malformed/duplicate authentication input before either factor; a failed, stale, malformed, exceptional, open-scope, identity-mismatched or unbound BPC result denies before TSK lookup or HOTP consumption; TSK runs exactly once only after a current BPC result and byte-exact server-controlled binding; final BPC/binding fences are rechecked after TSK; all public factor denials are generic. BPC and TSK key material, lifecycle, replay state, PostgreSQL authority, Redis usage, audit authority and operational roles remain independent.

## Completed release controls

- Exact standalone source pins and exact crate versions are recorded in both core and service manifests and locked in `Cargo.lock`.
- The service uses only certificate/hostname-verified BPC PostgreSQL, TSK PostgreSQL, bridge PostgreSQL and private-CA mutual-TLS Redis constructors. It rejects insecure, plaintext, unresolved continuity and ambiguous secret-file configurations before binding a socket.
- BPC Redis continuity is explicitly reconciled, never automatically initialized or recovered by the verifier. BPC nonce replay/fencing remains BPC-owned; TSK HOTP lifecycle remains TSK-owned; bridge PostgreSQL owns only binding and audit/outbox authority.
- Bridge bindings are serializable, expected-revision fenced, uniquely map one active TSK identity, retain revocation tombstones, and write immutable history/outbox state atomically. Runtime access uses separately provisioned verifier credentials; the service neither runs migrations nor exposes lifecycle control-plane endpoints.
- Raw request capture is bounded and byte exact. The Linux transport rejects forwarding headers, ambiguous framing, trailers and unsupported transfer behavior before factors; it uses admission deadlines, non-waiting bounded admission, bounded blocking execution, generic error mapping, no automatic verification retry and private listeners only.
- Every service instance requires a bounded independent TSK pre-lookup verification limiter. Its exhaustion denies without a TSK lookup or HOTP commit; service configuration rejects zero or unbounded values. The authenticated TLS edge additionally supplies source-aware distributed abuse limits.
- The hardened systemd template runs as a fixed non-login identity with no capabilities, no new privileges, protected filesystem/home/devices/kernel interfaces, constrained address families, a private runtime directory, explicit network allow-list placeholders, disabled core dumps and bounded shutdown.
- The release contains version-controlled CycloneDX all-feature SBOMs for the core and service. Locked Rust quality, license/source/duplicate policy, RustSec advisory scan and Semgrep SAST are release gates.

## Verification evidence

The completed release evidence is recorded in [RELEASE_EVIDENCE.md](RELEASE_EVIDENCE.md). It includes:

1. locked all-feature workspace formatting, unit/integration tests, strict Clippy, optimized release build, Cargo Deny, Cargo Audit, Semgrep and clean-diff checks;
2. standalone BPC and TSK final-pinned dependency graphs under the composition service;
3. a fresh private-CA PostgreSQL topology with separate BPC, TSK and bridge databases/schemas/roles; a governed Redis epoch with private-CA mutual TLS; and post-migration verifier-only grants;
4. two independent release binary processes sharing only the durable authorities;
5. live empty-204 two-factor admission of a 64-character secured TSK credential; corrupted BPC signature denial before valid TSK use; exact BPC nonce replay denial; and fresh-nonce consumed-HOTP replay denial across the second service process.

## Deployment contract

Each deployment supplies its own protected private configuration/secret files, independently managed factor and audit key domains, PostgreSQL/Redis endpoints, least-privilege roles, durable database/Redis operating policy, allowed egress addresses, and authenticated TLS edge. The service intentionally has no insecure convenience mode, migration-on-start path or direct public Internet listener. Use the service [operator guide](../crates/bpc-tsk-service/README.md), [configuration template](../crates/bpc-tsk-service/deploy/config.example.toml), [systemd template](../crates/bpc-tsk-service/deploy/bpc-tsk-service.service), [architecture contract](ARCHITECTURE.md) and [SBOM instructions](../sbom/README.md) to deploy the validated product.

This statement does not label the composition an encryption primitive, provide an AAL/FIPS/PQC certification, or remove the need for an organization to operate its chosen TLS edge, keys, databases and incident process correctly.
