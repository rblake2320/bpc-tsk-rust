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

Version 2 makes delivery a **database-controlled state machine**:

| Current state | Authorized transition | Result |
| --- | --- | --- |
| Pending, due, no live lease, within budget | Publisher claim | Pending with DB-generated token/owner/expiry; lifetime and cycle claims increase |
| Pending with matching live fence | Publisher acknowledge after acceptance | Delivered; identical successful fence remains idempotent |
| Pending with matching live fence | Publisher record transient failure | Pending with released fence and future DB-clock retry schedule |
| Pending | Permanent failure, exhausted claims or age | Quarantined; no lease or retry schedule |
| Quarantined | Privileged, audited control-plane requeue | Pending with new bounded cycle and at least 1 s delay |
| Delivered | None | Terminal; no requeue or further failure mutation |

1. Call `claim_outbox(worker_id, batch_size, lease)`: **1–100 events**, leases **100 ms–5 min**, database-clock expiry, SERIALIZABLE transaction, `FOR UPDATE ... SKIP LOCKED`, fresh **DB-generated random token per event** and monotonically increasing lifetime claim count. The returned `ClaimedAuditEvent` API is unchanged; tokens are no longer shared by a batch. Claim checks `state`, `next_attempt_at`, lease expiry, and cycle budgets. A batch can quarantine expired work instead of returning claims, so an empty batch is not proof that the entire queue is drained. Do not publish any returned tentative data until this method has successfully committed/returned.
2. Publish the closed `OutboxPayload` externally with its stable event UUID as the deduplication key. Handle backlog and destination failures independently of factor verification. Lifecycle payloads resolve from immutable history, never current binding rows.
3. Call `acknowledge_delivery(event_id, worker_id, lease_token)` only after external durable acceptance. Wrong owner/token, expired/reclaimed/released fences and quarantined events cannot acknowledge; identical successful acknowledgements are idempotent. DB time is evaluated **after acquiring the row lock**, so lock wait cannot preserve an expired fence. Payload/history is never updated/deleted.
4. On destination failure call `record_delivery_failure(event_id, worker_id, lease_token, DeliveryFailureClass, retry_after)`. The result is `Some(Pending)` or `Some(Quarantined)`; `None` means the fence/state did not authorize a mutation. A failure releases the token and owner, so repeat/stale failures cannot reschedule anything. No destination message, URL, payload or credential is accepted. Caller delay must be **1 s–1 h**. The DB uses the greater of that delay and exponential backoff **1, 2, 4, …, 256, 300 s (capped)**. A requested retry crossing the age deadline quarantines instead.
5. A crashed/uncertain publisher leaves events pending, but claim sets `next_attempt_at` to **lease expiry plus the same exponential backoff**. Expiry alone never causes an immediate tight reclaim loop. There is no heartbeat API: select an adequately bounded lease or allow delayed reclaim/redelivery. Serialization-aborted transactions can be retried by a bounded publisher policy; unknown claim commits must not trigger publication of an unconfirmed lease. Unknown failure/ack outcomes do not authorize publishing again; deduplication and later fenced recovery reconcile them.

Closed delivery classes are **Unavailable, Timeout, RateLimited** (retryable within budget), and **Rejected, InvalidEvent** (immediate quarantine). They are distinct from the bridge's verification `FailureClass`. Failure metadata stores only the corresponding fixed code and a DB timestamp.

Budgets are fixed in checksummed SQL, not adjustable by publisher inputs: **12 claims and 7 days per cycle**, counting downtime and abandoned claims. Age starts at the immutable event's `recorded_at`; an audited requeue starts a new cycle at DB time. A claim sweep quarantines due/aged, non-live work in bounded batches. The twelfth claim can still acknowledge a live accepted delivery; a failure or abandoned-expiry sweep quarantines it rather than issuing a thirteenth claim. A live claim may acknowledge after the age boundary while its lease is valid; age bounds **new claims and retries**, not cancellation of already accepted external work. Lifetime attempts never reset or overflow: `i64::MAX` work is quarantined and cannot requeue.

### Controlled database privileges and recovery

The publisher has no INSERT/UPDATE/DELETE/TRUNCATE delivery rights, including **legacy column UPDATE grants**. Only three fixed-search-path `SECURITY DEFINER` entry points are executable by `bridge_publisher`: `claim_audit_deliveries`, `acknowledge_audit_delivery`, and `fail_audit_delivery`. Helpers, triggers and privileged recovery are not exposed; PUBLIC execute is revoked. Initial creation also runs through a controlled enqueue trigger rather than runtime delivery-row INSERT rights. Functions must be owned by the separate trusted DDL owner, with no runtime ownership, schema CREATE, broad function/default grants or dangerous inherited memberships. The [role template](../migrations/ROLE_GRANTS.example.sql) must be reviewed for deployment-specific roles.

Only the control-plane role can call `requeue_delivery(event_id, &DeliveryRequeueContext)`, wrapping `requeue_audit_delivery`. It works **only for quarantine** and atomically appends an immutable `delivery_requeues` record (operation UUID, operator label, closed DestinationRepaired/ReviewedRecovery reason, DB session actor, prior claims/cycle/age/cause, DB time). An identical operation UUID reconciles unknown commits without a new cycle/audit record; changed event, actor or reason conflicts. A historical true result does not imply the event is currently pending. Fresh operations cannot requeue delivered or live pending work. Requeue resets cycle attempts/age but preserves lifetime attempts, stable event identity, payload and prior failure metadata; old fences stay invalid. Operator authorization comes from isolated credentials and reviewed policy, **not the actor label**. The requeue history is a local audit ledger; independently anchoring/exporting it remains deployment work.

External deduplication is essential: acceptance followed by a lost acknowledgement causes redelivery. Publisher credentials are still trusted to acknowledge leases they can observe; worker labels/token fences are **not per-worker tenancy or proof of an external receipt**. Run workers with bounded, delayed empty-poll/error retries and alert on backlog, oldest pending age, attempts and quarantine. Retention/reconciliation, external anchors, alerting, durable destination and publisher daemon remain deployment work.

## Tests

No live services are required for standard checks:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
```

The live suite is ignored by default **and requires explicit URL variables**, never defaults or ambient `PG*` credentials. Use a private, disposable PostgreSQL 16+ database owned solely by the test suite. It applies persistent schema/history, exercises rejection triggers, and claims/acknowledges that database's publisher queue; never point it at production/shared data. Run live tests sequentially. The controlled retry test accelerates schedules with owner-only SQL to test long exponential delays without sleeping for minutes; runtime privilege tests separately prove that publishers cannot do this.

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

`controlled_retry_quarantine_requeue_and_no_tight_loop` uses `BPC_TSK_POSTGRES_TEST_URL` to test retry schedules, failure fence rejection, permanent/attempt/age quarantine, exponential delay, abandoned final claims, immutable requeue audits and terminal delivery. The role test checks direct publisher SQL denials, malformed procedure inputs, PUBLIC execute revocation, temporary-search-path shadowing and control-only recovery. `version_one_upgrade_checksums_legacy_state_and_privilege_revocation` requires a **separate empty DB** via `BPC_TSK_POSTGRES_UPGRADE_TEST_URL` and role-administration privileges. It tests v1 checksum tamper refusal before DDL, legacy state preservation/quarantine, two-entry checksums, idempotent reapplication, and removal of legacy column/broad/default function grants. It deliberately repairs corrupt test metadata using owner privileges; never perform that operation on production metadata.

```sh
BPC_TSK_POSTGRES_TEST_URL='host=127.0.0.1 port=55432 user=test_owner dbname=disposable' \
  cargo test --locked -p bpc-tsk-core --all-features --test postgres_authority \
  controlled_retry_quarantine_requeue_and_no_tight_loop -- --ignored --test-threads=1
BPC_TSK_POSTGRES_UPGRADE_TEST_URL='host=127.0.0.1 port=55432 user=test_owner dbname=empty_upgrade' \
  cargo test --locked -p bpc-tsk-core --all-features --test postgres_authority \
  version_one_upgrade_checksums_legacy_state_and_privilege_revocation -- --ignored --test-threads=1
```

Unit and ignored-live tests are **local integration checks**, not partition/failover/crash/ambiguous-commit or production least-privilege/HA evidence. Existing connection, audit, binding-fence and TLS tests remain in place.
