# Durable PostgreSQL bridge authority

**Private checkpoint; not production-ready.** Enable `postgres-authority` for `bpc_tsk_core::postgres_authority`. `PostgresAuthority` implements both existing synchronous `BindingStore` and `AuditSink` boundaries without changing the coordinator's BPC-first ordering or generic public denial.

## Connection and migration APIs

```rust,no_run
use bpc_tsk_core::postgres_authority::{AuthorityLimits, PostgresAuthority};
use postgres::Config;

# fn example(config: Config, public_ca_der: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
// Get config credentials from a separate secret manager, not request headers.
// The production constructor never uses NoTls and never accepts a custom
// unsafe certificate verifier. It overrides caller sslmode with Require.
let authority = PostgresAuthority::connect_tls(
    config,
    &[public_ca_der],
    AuthorityLimits::default(),
)?;
// On a separate DDL-owning connection, explicitly call migrate().
// Runtime roles only check compatibility and use granted data operations.
authority.check_schema()?;
# Ok(())
# }
```

`connect_tls` accepts one bounded TCP hostname (or IP SAN identity), at most one explicit hostaddr/port, and 1–64 DER trust roots of at most 64 KiB each. Normal rustls chain and hostname/IP-SAN verification remains enabled. Only TLS 1.3 is offered; servers with no TLS, untrusted/expired certificates, wrong names or older TLS versions cannot fall back to plaintext. No production constructor takes `NoTls` or an arbitrary caller-supplied TLS verifier. Current API supports server-authenticated TLS without client certificate authentication; infrastructure may additionally require its own network/mTLS admission boundary.

`connect_insecure_local_test` is **explicitly insecure** and accepts only `localhost`, literal loopback IPs, and loopback hostaddr values. It pins `localhost` without an explicit hostaddr to `127.0.0.1`, avoiding DNS redirection. It rejects Unix sockets, remote endpoints and multi-host configurations. Loopback is not a security guarantee: never use this API with production credentials.

`migrate()` is explicit, checksummed, version-recorded and idempotent through its metadata ledger. It requires separately authorized DDL ownership. Runtime transactions verify both schema version and checksum. See the [migration/role contract](../migrations/README.md).

### Bounds and synchronous execution

Defaults: statement timeout **5 s**, lock timeout **1 s**, idle-in-transaction timeout **5 s**, TCP connect timeout **5 s**, Linux TCP-user timeout **10 s**, local connection-mutex wait **1 s**. All are validated as nonzero, bounded durations; lock timeout cannot exceed statement timeout. Statement/lock/idle bounds and synchronous_commit=on are installed on the connection and reasserted locally in each transaction. SQL is parameterized and authority object names are fixed/schema-qualified.

This is a **synchronous connection per authority handle**; clones share it. Use separate credentials/connections for verifier, control-plane and publisher and a **bounded blocking executor** for application integration. Calling synchronous postgres on an async reactor is unsupported. The optional Axum admission adapter uses a non-waiting bounded permit and Tokio's blocking executor for the entire composition coordinator; saturated or failed admission fails closed. There is no connection pool, multi-host failover policy or automatic retry. Statement deadlines are per statement, not whole-business-transaction deadlines. TCP-user timeouts bound unacknowledged transport data, not all DNS/TLS/server/application stalls; full cancellation and failure-time guarantees require deployment fault tests and executor/network design.

## Binding lifecycle and reconciliation

- `activate(pair, client, principal, expected_revision, context)` creates only when expected revision is **0 and the pair has never existed**. Replacements/reactivations require the exact current revision, whether active or revoked.
- `revoke(pair, expected_revision, context)` requires a nonzero revision and an active current mapping. It advances the revision and retains the inactive tombstone.
- Every transition advances the revision by exactly one without saturation/overflow, preserves the pair's stable binding UUID and atomically commits immutable history plus lifecycle outbox intent at **SERIALIZABLE** isolation.
- Pair IDs use the pinned BPC canonical 1–64 ASCII alphanumeric/underscore/hyphen contract. Client, principal, actor and publisher IDs are 1–128 ASCII alphanumeric or `_.:@-`; whitespace, control bytes, other punctuation and prototype-reserved names are rejected. This intentionally tightens the development store's identity alphabet. Existing IDs outside this contract need policy-approved migration, not lossy normalization.
- An active TSK client has at most one pair/principal mapping. Reassignment to a different pair requires explicit revocation of its previous binding plus trusted policy approval. No request header creates/selects control-plane authority.
- `MutationContext` contains a non-nil operation UUID, bounded privileged actor identity and a closed `BindingReason` enum; no free-text reason, arbitrary JSON or operator secret field exists. These strings do **not authenticate an operator**: caller authorization and isolated database role credentials must establish privilege.
- Reusing the same operation UUID with identical inputs returns the original historical result without another mutation/outbox event. Changed inputs conflict. A returned historical activation does not imply it is still active; use `BindingStore` lookup/recheck to establish current state.
- `binding_change(operation_id)` supports read-only reconciliation. `SerializationFailure` means the transaction aborted. `CommitUnknown` means the commit response was lost; reconnect, inspect the operation/history or retry only the identical privileged lifecycle operation after reconciliation. The module never automatically retries BPC/TSK requests or compensates consumed replay/HOTP state.

Lookup and final recheck are read-only SERIALIZABLE transactions and validate the full binding UUID/pair/client/principal/revision. They are point-in-time fences, **not an atomic cross-database business-effect lock**. A concurrent revocation after recheck and before application commit remains an application integration/release-gate issue.

## Secret-free transactional audit

The existing core computes an independent domain-separated audit HMAC request-context digest. The PostgreSQL sink requires its canonical 64-byte lowercase hexadecimal shape, then stores only:

> `SHA-256(ASCII("bpc-tsk-persisted-audit-commitment-v1") || 0x00 || ASCII(canonical_digest_hex))`

The original HMAC value is **not persisted**. Neither its key nor any BPC/TSK key, request body, signature, HMAC authenticator, JWK, raw signed data or authentication header enters a database payload. Identifiers, closed phase/failure/reason codes and positive revisions are the only other content. Do not place secrets inside trusted identifier fields.

`record_audit` atomically inserts the immutable verification phase and publisher intent. Attempt creation is required before a matching final phase. Correlation/phase retries are idempotent only for identical payloads; there can be at most one allowed/denied final phase. A changed digest, revision/classification or conflicting final phase fails closed. `AuditSink` maps every detailed authority error to the existing opaque `AuditError`; `BindingStore` similarly exposes only its opaque error. Protected error enums do not retain database error messages, query text or credentials.

An `Allowed` event is **authorization intent**, not proof of a business side effect or of a successfully delivered client response. For example, its commit can succeed while the response is lost and the coordinator still denies generically. Attempt and final audit phases are separate transactions; abandoned attempts and ambiguous outcomes require operator reconciliation. Binding lifecycle state/history/outbox, in contrast, commit in one database transaction.

## Separate at-least-once publisher

1. Call `claim_outbox(worker_id, batch_size, lease)`: **1–100 events**, leases **100 ms–5 min**, database-clock expiry, SERIALIZABLE transaction, `FOR UPDATE ... SKIP LOCKED`, fresh random lease token and monotonically increasing claim count. Do not publish any returned tentative data until this method has successfully committed/returned.
2. Publish the closed `OutboxPayload` externally with its stable event UUID as the deduplication key. Handle backlog and destination failures independently of factor verification. Lifecycle payloads resolve from immutable history, never current binding rows.
3. Call `acknowledge_delivery(event_id, worker_id, lease_token)` only after external durable acceptance. Wrong owner/token and expired/reclaimed leases cannot acknowledge; identical successful acknowledgements are idempotent. Payload/history is never updated/deleted.
4. A crashed/uncertain publisher leaves events pending; they become reclaimable after lease expiry. There is no heartbeat API today: select an adequately bounded lease or allow reclaim/redelivery. Serialization-aborted claims/acks can be retried by publisher policy; unknown claim commits must not trigger publication of an unconfirmed lease.

External deduplication is essential: acceptance followed by a lost acknowledgement causes redelivery. Publisher credentials are trusted to acknowledge their assigned queue; the role template does not enforce per-worker tenancy or verify the external destination's receipt. External anchors, retention/reconciliation, alerting, durable destination and publisher daemon are deployment work, not supplied here.

## Tests

No live services are required for standard checks:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
```

The live suite is ignored by default **and requires explicit URL variables**, never defaults or ambient `PG*` credentials. Use a private, disposable PostgreSQL 16+ database owned solely by the test suite. It applies persistent schema/history, exercises rejection triggers, and claims/acknowledges that database's publisher queue; never point it at production/shared data. Run live tests sequentially.

`binding_lock_timeout_is_fail_closed_and_transactional` uses the same explicit local URL to exercise rollback under a held table lock. `least_privilege_role_template_separates_runtime_boundaries` additionally requires role-administration privileges on a **disposable cluster without the example role names already present**; it creates, exercises and removes those example roles. These tests are also ignored unless explicitly selected.

```sh
# Local plaintext test only; use throwaway credentials and a loopback endpoint.
BPC_TSK_POSTGRES_TEST_URL='host=127.0.0.1 port=55432 user=test_owner dbname=disposable' \
  cargo test --workspace --all-features --locked --test postgres_authority \
  lifecycle_audit_leases_constraints_and_migration_reapplication -- --ignored --test-threads=1

BPC_TSK_POSTGRES_TEST_URL='host=127.0.0.1 port=55432 user=test_owner dbname=disposable' \
  cargo test --workspace --all-features --locked --test postgres_authority \
  concurrent_expected_revision_has_only_one_winner -- --ignored --test-threads=1

# A trusted, unexpired test CA and a TLS 1.3 server certificate for db.test.
# Both URLs reach the SAME server; the second deliberately has the wrong name.
BPC_TSK_POSTGRES_TLS_TEST_URL='host=db.test hostaddr=127.0.0.1 port=55432 user=test_owner dbname=disposable' \
BPC_TSK_POSTGRES_TLS_TEST_CA_DER='/path/to/public-test-ca.der' \
BPC_TSK_POSTGRES_TLS_WRONG_HOST_TEST_URL='host=wrong.test hostaddr=127.0.0.1 port=55432 user=test_owner dbname=disposable' \
  cargo test --workspace --all-features --locked --test postgres_authority \
  verified_tls_connection_and_explicit_hostname_failure -- --ignored --test-threads=1
```

Unit tests cover limits, canonical identifiers/revision overflow, explicit insecure API locality/localhost pinning, empty/malformed trust roots, fixed secret-free audit commitments, closed event shapes/codes, idempotency metadata matching, claim bounds, schema invariants and trait compatibility. Opt-in live tests cover migration reapplication/unknown-version refusal, active-client uniqueness, activate/revoke/reactivate fences, transactional rejection/lock-timeout rollback, append-only enforcement, audit phase idempotency/conflicts, lease expiry/reclaim/old-token rejection, acknowledgement idempotency, concurrent revision mutations, local runtime-role grants and verified TLS hostname failure. These are **local integration checks**, not partition/failover/crash/ambiguous-commit or production least-privilege/HA evidence.
