-- OPERATOR-REVIEWED TEMPLATE, NOT AN AUTOMATIC MIGRATION.
-- Provision these NOLOGIN group roles separately; use isolated LOGIN roles
-- with membership in exactly one group, no superuser/owner/DDL privileges.
-- The DDL migrator must be a separate owner, not a runtime role or membership.
-- Static names below are examples. Do not interpolate request input into DDL.
GRANT USAGE ON SCHEMA bpc_tsk_bridge TO bridge_verifier, bridge_control, bridge_publisher;
GRANT SELECT ON bpc_tsk_bridge.schema_version, bpc_tsk_bridge.schema_migrations
    TO bridge_verifier, bridge_control, bridge_publisher;

GRANT SELECT ON bpc_tsk_bridge.principal_bindings TO bridge_verifier, bridge_control;
GRANT SELECT, INSERT ON bpc_tsk_bridge.verification_attempts TO bridge_verifier;
GRANT SELECT ON bpc_tsk_bridge.audit_outbox TO bridge_verifier, bridge_control, bridge_publisher;
GRANT INSERT (event_id, event_kind, correlation_id, context_commitment, phase, failure_class, binding_revision)
    ON bpc_tsk_bridge.audit_outbox TO bridge_verifier;
-- The invoker-security enqueue trigger creates only initial delivery state.
GRANT INSERT (event_id) ON bpc_tsk_bridge.audit_deliveries TO bridge_verifier, bridge_control;

GRANT INSERT (bpc_pair_id, binding_id, tsk_client_id, principal_id, revision, active),
    UPDATE (tsk_client_id, principal_id, revision, active, changed_at)
    ON bpc_tsk_bridge.principal_bindings TO bridge_control;
GRANT SELECT, INSERT ON bpc_tsk_bridge.binding_history TO bridge_control;
GRANT INSERT (event_id, event_kind, correlation_id, history_operation_id)
    ON bpc_tsk_bridge.audit_outbox TO bridge_control;
-- Deferred lifecycle consistency trigger reads the delivery row.
GRANT SELECT ON bpc_tsk_bridge.audit_deliveries TO bridge_control;

GRANT SELECT ON bpc_tsk_bridge.binding_history, bpc_tsk_bridge.audit_deliveries TO bridge_publisher;
GRANT UPDATE (lease_token, lease_owner, lease_until, attempts, delivered_at)
    ON bpc_tsk_bridge.audit_deliveries TO bridge_publisher;
-- No runtime role has UPDATE/DELETE/TRUNCATE rights on immutable payloads,
-- schema modification rights, or access to factor authority/secret databases.
-- Publishers are trusted to claim/ack their assigned queue. These SQL grants
-- do not enforce per-worker tenancy or prove external acceptance.
