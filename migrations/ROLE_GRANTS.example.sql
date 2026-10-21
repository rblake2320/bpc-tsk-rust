-- OPERATOR-REVIEWED TEMPLATE, NOT AN AUTOMATIC MIGRATION. Apply after v2.
-- Provision these NOLOGIN group roles separately; use isolated LOGIN roles
-- with membership in exactly one group, no superuser/owner/DDL privileges.
-- The DDL migrator must be a separate non-runtime owner. SECURITY DEFINER
-- functions must be owned by that trusted owner, never a runtime role.
-- Static names below are examples. Do not interpolate request input into DDL.
REVOKE CREATE ON SCHEMA bpc_tsk_bridge FROM bridge_verifier, bridge_control, bridge_publisher;
GRANT USAGE ON SCHEMA bpc_tsk_bridge TO bridge_verifier, bridge_control, bridge_publisher;
GRANT SELECT ON bpc_tsk_bridge.schema_version, bpc_tsk_bridge.schema_migrations
    TO bridge_verifier, bridge_control, bridge_publisher;

GRANT SELECT ON bpc_tsk_bridge.principal_bindings TO bridge_verifier, bridge_control;
GRANT SELECT, INSERT ON bpc_tsk_bridge.verification_attempts TO bridge_verifier;
GRANT SELECT ON bpc_tsk_bridge.audit_outbox TO bridge_verifier, bridge_control, bridge_publisher;
GRANT INSERT (event_id, event_kind, correlation_id, context_commitment, phase, failure_class, binding_revision)
    ON bpc_tsk_bridge.audit_outbox TO bridge_verifier;

GRANT INSERT (bpc_pair_id, binding_id, tsk_client_id, principal_id, revision, active),
    UPDATE (tsk_client_id, principal_id, revision, active, changed_at)
    ON bpc_tsk_bridge.principal_bindings TO bridge_control;
GRANT SELECT, INSERT ON bpc_tsk_bridge.binding_history TO bridge_control;
GRANT INSERT (event_id, event_kind, correlation_id, history_operation_id)
    ON bpc_tsk_bridge.audit_outbox TO bridge_control;
-- Deferred lifecycle consistency trigger reads the delivery row.
GRANT SELECT ON bpc_tsk_bridge.audit_deliveries TO bridge_control;
GRANT SELECT ON bpc_tsk_bridge.binding_history, bpc_tsk_bridge.audit_deliveries TO bridge_publisher;

-- Revoke legacy TABLE AND COLUMN privileges: a table revoke alone does not
-- remove the v1 column UPDATE grants. No runtime role initializes state directly.
REVOKE INSERT (event_id) ON bpc_tsk_bridge.audit_deliveries FROM bridge_verifier, bridge_control;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON bpc_tsk_bridge.audit_deliveries FROM bridge_verifier, bridge_control, bridge_publisher;
REVOKE ALL (event_id, lease_token, lease_owner, lease_until, attempts, delivered_at,
    state, next_attempt_at, policy_started_at, cycle_attempts, last_failure_code,
    last_failed_at, quarantined_at, quarantine_reason)
    ON bpc_tsk_bridge.audit_deliveries FROM bridge_verifier, bridge_control, bridge_publisher;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bpc_tsk_bridge FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bpc_tsk_bridge FROM bridge_verifier, bridge_control, bridge_publisher;
REVOKE ALL ON bpc_tsk_bridge.delivery_requeues FROM bridge_verifier, bridge_control, bridge_publisher;
-- Do not grant EXECUTE ON ALL FUNCTIONS: helpers/triggers/requeue stay private.
GRANT EXECUTE ON FUNCTION bpc_tsk_bridge.claim_audit_deliveries(text, bigint, bigint),
    bpc_tsk_bridge.acknowledge_audit_delivery(uuid, text, uuid),
    bpc_tsk_bridge.fail_audit_delivery(uuid, text, uuid, text, bigint) TO bridge_publisher;
GRANT SELECT ON bpc_tsk_bridge.delivery_requeues TO bridge_control;
GRANT EXECUTE ON FUNCTION bpc_tsk_bridge.requeue_audit_delivery(uuid, uuid, text, text) TO bridge_control;

-- No runtime role has UPDATE/DELETE/TRUNCATE rights on immutable payloads,
-- schema modification rights, or access to factor authority/secret databases.
-- Reviewed deployment must also remove conflicting inherited/custom/default
-- grants and EXECUTE rights. Publisher IDs are labels, not per-worker tenancy.
-- A publisher can still acknowledge a lease it owns without external acceptance;
-- the DB boundary enforces transitions/fences, not a destination receipt.
