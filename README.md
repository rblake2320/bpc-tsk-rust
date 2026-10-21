# BPC + TSK Rust bridge

`bpc-tsk-rust` is a third, private Rust workspace that composes two independently owned protocol crates:

- `bpc-protocol`, pinned by immutable Git revision;
- `tsk-rust-protocol`, pinned by immutable Git revision.

It does not merge either protocol, and neither standalone crate depends on the other. The bridge never stores, derives, concatenates, or transfers TSK shared credentials into BPC. BPC signing/HMAC/private-key material, TSK shared credentials and HOTP state, bridge binding authority, audit keys, and CI/release credentials are separate domains with independent lifecycle and access controls.

## Security invariant

For every protected request, the bridge captures bounded immutable request data and rejects malformed or duplicate BPC/TSK authentication headers before either verifier runs. It then verifies BPC against the exact method, path-and-query, and body bytes. Only a fresh, closed-scope BPC result with a concrete pair identity can resolve a server-controlled active binding. The submitted TSK client ID must byte-equal the binding’s TSK client ID before any TSK store lookup, validation, or HOTP commit. TSK is called exactly once only after those checks.

After a successful TSK verification, the bridge rechecks BPC and binding fences. A changed/revoked factor, authority failure, or audit-finalization failure denies the request. A BPC nonce or TSK HOTP value already consumed before a later denial remains consumed; it is never retried or compensated. The business side effect belongs behind its own idempotency and transaction boundary.

Public callers receive only a generic decision and correlation ID. Protected audit data is secret-free and records a domain-separated HMAC of the request context rather than raw bodies, signatures, JWKs, registration secrets, or TSK keys.

## Status

**Private checkpoint; not production-ready.** The core has unit tests for BPC-first ordering, duplicate-header rejection, identity mismatch, final fences, redacted audit digests, and its optional Axum admission adapter. The adapter captures exact request bytes, preserves duplicate headers, returns generic denial, and overwrites TSK response-control headers with the verified values. It does not yet contain the required PostgreSQL binding/outbox implementation, real PostgreSQL/Redis service drills, TSK durable authority/HA parity, or independent security review. See [the readiness gate](docs/PRODUCTION_READINESS.md), [architecture](docs/ARCHITECTURE.md), and [cryptographic assurance assessment](docs/CRYPTOGRAPHIC_ASSURANCE.md).

The composition strengthens independent authorization and replay resistance. It is not “ultra encryption.” Transport confidentiality requires TLS 1.3, and storage confidentiality requires a separately reviewed standard AEAD/KMS key-management design.
