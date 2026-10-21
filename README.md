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

**Private checkpoint; not production-ready.** The core has unit tests for BPC-first ordering, duplicate-header rejection, identity mismatch, final fences, redacted audit digests, and its optional Axum admission adapter. The adapter captures exact request bytes, preserves duplicate headers, returns generic denial, and overwrites TSK response-control headers with the verified values. The optional `postgres-authority` module now supplies revisioned bindings, append-only lifecycle history, explicit checksummed migrations, and a transactional audit outbox with fenced publisher leases. Local integration tests are opt-in; production PostgreSQL/Redis fault/HA drills, TSK durable authority/HA parity, deployment validation, external audit anchoring, and independent security review remain release gates. See [the readiness gate](docs/PRODUCTION_READINESS.md), [architecture](docs/ARCHITECTURE.md), and [cryptographic assurance assessment](docs/CRYPTOGRAPHIC_ASSURANCE.md).

## Durable bridge authority

Enable `postgres-authority` to use `postgres_authority::PostgresAuthority` as both `BindingStore` and `AuditSink`. Production connections must use **`connect_tls`**, which requires explicit DER trust roots, verifies the certificate chain and configured hostname/IP SAN, and permits only TLS 1.3 with no plaintext fallback. **`connect_insecure_local_test`** is explicitly insecure and rejects non-loopback test endpoints. Neither constructor implicitly applies migrations or creates roles.

The trusted control plane uses expected-revision `activate`/`revoke` calls with a stable operation UUID, bounded actor identity and closed reason code. Mutations use serializable transactions; stale revisions deny, revoked bindings retain tombstones, and history plus outbox intent commits with the new revision. An active TSK client cannot be mapped to two pairs/principals. A separate publisher uses `claim_outbox` and `acknowledge_delivery`; delivery is at-least-once and must deduplicate by event UUID externally. No keys, bodies, signatures, HMAC values or JWKs are persisted: the core's independent audit digest is transformed into a domain-separated SHA-256 commitment before storage.

This is a **synchronous** authority. The optional Axum adapter bounds concurrent admission with a non-waiting permit and runs the entire composition coordinator on Tokio's blocking executor; saturation, task failure, and invalid capacity configuration fail closed. Separately provision migrator/verifier/control-plane/publisher credentials. Statement, lock, idle-transaction, TCP-connect, TCP-user and connection-contention limits are bounded; they are not a complete end-to-end cancellation or failover design. See the [migration and role contract](migrations/README.md) and [operator/API guide](docs/POSTGRES_AUTHORITY.md).

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
```

Normal tests require no live services. The ignored PostgreSQL tests require explicitly set test URL variables; commands and disposable-database caveats are in the operator guide.

The composition strengthens independent authorization and replay resistance. It is not “ultra encryption.” Transport confidentiality requires TLS 1.3, and storage confidentiality requires a separately reviewed standard AEAD/KMS key-management design.

## Runnable private-edge production candidate

[`bpc-tsk-service`](crates/bpc-tsk-service/README.md) constructs independent TLS-backed BPC PostgreSQL, governed Redis, TSK PostgreSQL and bridge PostgreSQL authorities, explicitly reconciles Redis and checks the bridge schema before exposing its private listener. It accepts only `bpc-tsk-service --config /absolute/path`, uses bounded private secret files, serves `/livez`, `/readyz` and the snapshot-only `/v1/protected` route, and supplies a hardened systemd template. It never migrates, exports TSK maps/shared secrets, retries factors, or uses insecure constructors. This candidate does not remove the separate production/HA/security-review gates above.
