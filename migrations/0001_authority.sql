-- Version 1. Do not edit after deployment: add a new checksummed migration instead.
-- Reapplication is controlled by schema_migrations, not by ignoring DDL errors.
CREATE TABLE bpc_tsk_bridge.principal_bindings (
    bpc_pair_id varchar(64) COLLATE "C" PRIMARY KEY
        CHECK (bpc_pair_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    binding_id uuid NOT NULL UNIQUE,
    tsk_client_id varchar(128) COLLATE "C" NOT NULL
        CHECK (tsk_client_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'
            AND tsk_client_id NOT IN ('__proto__', 'constructor', 'prototype')),
    principal_id varchar(128) COLLATE "C" NOT NULL
        CHECK (principal_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'
            AND principal_id NOT IN ('__proto__', 'constructor', 'prototype')),
    revision bigint NOT NULL CHECK (revision > 0),
    active boolean NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- A TSK identity cannot be attached to a second active pair/principal.
CREATE UNIQUE INDEX one_active_pair_per_tsk_client
    ON bpc_tsk_bridge.principal_bindings (tsk_client_id) WHERE active;

CREATE TABLE bpc_tsk_bridge.binding_history (
    operation_id uuid PRIMARY KEY,
    binding_id uuid NOT NULL,
    bpc_pair_id varchar(64) COLLATE "C" NOT NULL
        REFERENCES bpc_tsk_bridge.principal_bindings (bpc_pair_id),
    tsk_client_id varchar(128) COLLATE "C" NOT NULL
        CHECK (tsk_client_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'
            AND tsk_client_id NOT IN ('__proto__', 'constructor', 'prototype')),
    principal_id varchar(128) COLLATE "C" NOT NULL
        CHECK (principal_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'
            AND principal_id NOT IN ('__proto__', 'constructor', 'prototype')),
    revision bigint NOT NULL CHECK (revision > 0),
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0 AND revision = expected_revision + 1),
    active boolean NOT NULL,
    actor_id varchar(128) COLLATE "C" NOT NULL
        CHECK (actor_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'
            AND actor_id NOT IN ('__proto__', 'constructor', 'prototype')),
    reason_code text NOT NULL CHECK (reason_code IN ('provision', 'rotation', 'revocation', 'policy_change', 'recovery')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (bpc_pair_id, revision)
);

CREATE TABLE bpc_tsk_bridge.verification_attempts (
    correlation_id uuid PRIMARY KEY,
    context_commitment bytea NOT NULL CHECK (octet_length(context_commitment) = 32),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE bpc_tsk_bridge.audit_outbox (
    event_id uuid PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('verification', 'binding')),
    correlation_id uuid NOT NULL,
    context_commitment bytea CHECK (octet_length(context_commitment) = 32),
    phase text CHECK (phase IN ('attempt', 'allowed', 'denied')),
    failure_class text CHECK (failure_class IN ('input', 'bpc', 'binding', 'identity_mismatch', 'tsk', 'final_fence', 'audit')),
    binding_revision bigint CHECK (binding_revision > 0),
    history_operation_id uuid UNIQUE REFERENCES bpc_tsk_bridge.binding_history (operation_id),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (event_kind = 'binding' AND history_operation_id IS NOT NULL
            AND correlation_id = history_operation_id
            AND context_commitment IS NULL AND phase IS NULL
            AND failure_class IS NULL AND binding_revision IS NULL)
        OR
        (event_kind = 'verification' AND history_operation_id IS NULL
            AND context_commitment IS NOT NULL AND phase IS NOT NULL
            AND ((phase = 'attempt' AND failure_class IS NULL AND binding_revision IS NULL)
                OR (phase = 'allowed' AND failure_class IS NULL AND binding_revision IS NOT NULL)
                OR (phase = 'denied' AND failure_class IS NOT NULL)))
    )
);
CREATE UNIQUE INDEX one_verification_phase_per_correlation
    ON bpc_tsk_bridge.audit_outbox (correlation_id, phase) WHERE event_kind = 'verification';
-- At most one final result, including across concurrent/idempotent writers.
CREATE UNIQUE INDEX one_verification_final_per_correlation
    ON bpc_tsk_bridge.audit_outbox (correlation_id)
    WHERE event_kind = 'verification' AND phase IN ('allowed', 'denied');

CREATE TABLE bpc_tsk_bridge.audit_deliveries (
    event_id uuid PRIMARY KEY REFERENCES bpc_tsk_bridge.audit_outbox (event_id),
    lease_token uuid,
    lease_owner varchar(128) COLLATE "C"
        CHECK (lease_owner ~ '^[A-Za-z0-9_.:@-]{1,128}$'
            AND lease_owner NOT IN ('__proto__', 'constructor', 'prototype')),
    lease_until timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    delivered_at timestamptz,
    CHECK ((lease_token IS NULL AND lease_owner IS NULL AND lease_until IS NULL AND attempts = 0 AND delivered_at IS NULL)
        OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND attempts > 0
            AND ((delivered_at IS NULL AND lease_until IS NOT NULL)
                OR (delivered_at IS NOT NULL AND lease_until IS NULL))))
);
CREATE INDEX pending_audit_deliveries
    ON bpc_tsk_bridge.audit_deliveries (lease_until, event_id) WHERE delivered_at IS NULL;

CREATE FUNCTION bpc_tsk_bridge.reject_history_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'append-only authority record' USING ERRCODE = '42501';
END;
$$;
CREATE TRIGGER immutable_binding_history BEFORE UPDATE OR DELETE ON bpc_tsk_bridge.binding_history
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_binding_history_truncate BEFORE TRUNCATE ON bpc_tsk_bridge.binding_history
    FOR EACH STATEMENT EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_verification_attempts BEFORE UPDATE OR DELETE ON bpc_tsk_bridge.verification_attempts
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_verification_attempts_truncate BEFORE TRUNCATE ON bpc_tsk_bridge.verification_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_outbox BEFORE UPDATE OR DELETE ON bpc_tsk_bridge.audit_outbox
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_outbox_truncate BEFORE TRUNCATE ON bpc_tsk_bridge.audit_outbox
    FOR EACH STATEMENT EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_migrations BEFORE UPDATE OR DELETE ON bpc_tsk_bridge.schema_migrations
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_migrations_truncate BEFORE TRUNCATE ON bpc_tsk_bridge.schema_migrations
    FOR EACH STATEMENT EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();

CREATE FUNCTION bpc_tsk_bridge.guard_binding_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'binding tombstones cannot be deleted' USING ERRCODE = '42501';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NOT NEW.active THEN
            RAISE EXCEPTION 'invalid initial binding revision' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.bpc_pair_id <> OLD.bpc_pair_id OR NEW.binding_id <> OLD.binding_id
        OR NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'invalid binding revision transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER revisioned_bindings BEFORE INSERT OR UPDATE OR DELETE ON bpc_tsk_bridge.principal_bindings
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.guard_binding_revision();
CREATE TRIGGER immutable_bindings_truncate BEFORE TRUNCATE ON bpc_tsk_bridge.principal_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();

-- Every lifecycle state transition must commit together with matching history,
-- an immutable outbox intent, and delivery state; no partial lifecycle commit.
CREATE FUNCTION bpc_tsk_bridge.require_binding_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM bpc_tsk_bridge.binding_history h
        JOIN bpc_tsk_bridge.audit_outbox o ON o.history_operation_id = h.operation_id
        JOIN bpc_tsk_bridge.audit_deliveries d ON d.event_id = o.event_id
        WHERE h.binding_id = NEW.binding_id AND h.bpc_pair_id = NEW.bpc_pair_id
            AND h.tsk_client_id = NEW.tsk_client_id AND h.principal_id = NEW.principal_id
            AND h.revision = NEW.revision AND h.active = NEW.active
    ) THEN
        RAISE EXCEPTION 'binding transition missing audit intent' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER binding_audit_required AFTER INSERT OR UPDATE ON bpc_tsk_bridge.principal_bindings
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.require_binding_audit();

CREATE FUNCTION bpc_tsk_bridge.enqueue_delivery() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO bpc_tsk_bridge.audit_deliveries (event_id) VALUES (NEW.event_id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER outbox_delivery AFTER INSERT ON bpc_tsk_bridge.audit_outbox
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.enqueue_delivery();

CREATE FUNCTION bpc_tsk_bridge.require_verification_attempt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.event_kind = 'verification' AND NOT EXISTS (
        SELECT 1 FROM bpc_tsk_bridge.verification_attempts a
        WHERE a.correlation_id = NEW.correlation_id AND a.context_commitment = NEW.context_commitment
    ) THEN
        RAISE EXCEPTION 'audit event missing matching attempt' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER outbox_attempt BEFORE INSERT ON bpc_tsk_bridge.audit_outbox
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.require_verification_attempt();

REVOKE ALL ON ALL TABLES IN SCHEMA bpc_tsk_bridge FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bpc_tsk_bridge FROM PUBLIC;
