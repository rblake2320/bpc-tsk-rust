# Planned PostgreSQL migration contract

The bridge database is authoritative only for pair-to-client-to-principal bindings and protected audit/outbox records. It stores no TSK shared secret, BPC registration secret, BPC private key, raw BPC signature, signed payload, JWK, TSK key, or raw request body.

The first reviewed migration must create `principal_bindings`, immutable `binding_history`, `verification_attempts`, `audit_outbox`, `audit_anchors`, and a schema-version/readiness record. Active bindings need unique, bounded canonical BPC pair identities and a policy review before a TSK client may be attached to another principal or pair. Binding lifecycle procedures require an expected revision, privileged actor, and non-empty reason. History/outbox payloads are append-only and secret-free.

The migrator role owns DDL. The verifier runtime role may execute only parameterized binding lookup/final-fence and audit/outbox procedures. The control-plane role may invoke lifecycle procedures. The publisher role may claim and mark deliveries but may not rewrite historical payloads. Database TLS, certificate/hostname verification, and statement/lock/cancellation limits are mandatory.

Each migration requires tested forward upgrade, rollback/forward-repair, least-privilege grant, restoration, and serialization/ambiguous-commit behavior before it is applied to production.
