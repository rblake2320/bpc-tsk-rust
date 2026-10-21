# PostgreSQL migration and role contract

**Implemented checkpoint, not production-ready.** The optional `postgres-authority` feature owns only bounded pair-to-client-to-principal identifiers, binding revisions/history, secret-free verification intent/outbox payloads, delivery metadata and schema compatibility records. It stores **no BPC/TSK key material, bodies, signatures, HMAC values, JWKs, or independent audit key**. The core's audit HMAC digest is transformed into a domain-separated SHA-256 commitment before persistence.

## Version 1

- `0000_bootstrap.sql` idempotently establishes the fixed `bpc_tsk_bridge` schema, singleton `schema_version`, and `schema_migrations` checksum/applied-time ledger.
- `0001_authority.sql` creates `principal_bindings`, append-only `binding_history`, append-only `verification_attempts`, append-only `audit_outbox`, and separately mutable `audit_deliveries`. A partial unique index prohibits one TSK client from belonging to two active pair/principal mappings.
- `PostgresAuthority::migrate()` serializes migrators using a bounded transaction-scoped advisory lock and SERIALIZABLE transaction. It applies missing DDL and records its SHA-256 checksum plus schema version in **one commit**. Reapplication with matching metadata is a no-op. SQL is deliberately not blindly replayed using `IF NOT EXISTS` for authority tables: unknown partial/preexisting layouts fail instead of being silently accepted.
- The runtime checks the exact version and checksum in every operation's transaction. Unknown/newer versions, missing ledger entries and changed migration bytes fail closed. Version 1 is the only supported version today; future upgrades require adding an ordered migration, its code/ledger validation and upgrade tests. Do not edit an already deployed migration.
- Binding insert/update triggers enforce monotonic revisions and nondeletable tombstones. A deferred consistency trigger rejects any binding state change lacking its matching history, outbox and delivery state in that same transaction. Immutable payload/ledger tables reject UPDATE, DELETE and TRUNCATE. Table owners/superusers can bypass database protections; runtime roles must never be owners or superusers.
- Verification outbox events require a matching secret-free attempt commitment. Uniqueness allows one attempt and at most one final allowed/denied event per correlation. Outbox insertion automatically initializes delivery state. Leases/acknowledgements update delivery metadata, never payload/history.

## Separate roles and TLS

Provision a DDL-owning **migrator** separately from verifier, control-plane and publisher LOGIN credentials. The fixed-role [grant template](ROLE_GRANTS.example.sql) is an **operator-reviewed example, not an automatically applied migration**. It assumes separately created NOLOGIN group roles and isolated LOGIN memberships. The schema and its tables/functions revoke PUBLIC privileges. Default/future grants and inherited memberships must also be reviewed by deployment infrastructure.

| Boundary | Allowed authority operations | Not granted |
| --- | --- | --- |
| Verifier | Read active bindings/schema, insert/read verification attempts and verification outbox columns, initialize delivery rows through the enqueue trigger | Binding lifecycle writes, lease/delivery updates, historical payload updates/deletes, DDL |
| Control plane | Expected-revision lifecycle code, binding/history reads/inserts, binding outbox columns, initialization/reads needed by consistency triggers | Verification payload columns, publication acknowledgement, historical payload updates/deletes, DDL |
| Publisher | Read immutable outbox/history/schema, claim and acknowledge delivery metadata | Binding writes, outbox/history payload writes, DDL |
| Migrator | Explicit versioned DDL and approved grant administration | Public request verification or factor secret access |

Production calls must use `connect_tls` with explicit DER trust roots: TLS 1.3, certificate-chain and hostname/IP-SAN verification, and sslmode Require overriding caller downgrade settings. The only plaintext API is explicitly named `connect_insecure_local_test`, validates loopback TCP endpoints, and is forbidden for real deployment credentials. All SQL request/control inputs are parameters; schema/table/function names are fixed constants. See [the operator guide](../docs/POSTGRES_AUTHORITY.md) for limits, idempotency, publisher recovery and opt-in integration commands.

## Remaining release gates

Database role/grant hardening, exact release PostgreSQL versions, migration upgrade/forward-repair and restoration rehearsals, schema-owner/superuser controls, statement/lock/cancellation behavior under network faults, failover durability, serialization and ambiguous-commit reconciliation, queue/backlog retention controls, external audit anchors, and independent security review remain mandatory. There is no automatic destructive rollback, cross-authority final-decision transaction, production connection pool, external publisher service or `audit_anchors` implementation. Local tests do not establish production HA/readiness.
