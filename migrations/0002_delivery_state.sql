-- Version 2. Do not edit after deployment; add an ordered checksummed migration.
-- Stop v1 publishers before upgrading. All times and retry budgets use DB time.
ALTER TABLE bpc_tsk_bridge.audit_deliveries DROP CONSTRAINT audit_deliveries_check;
DROP INDEX bpc_tsk_bridge.pending_audit_deliveries;
ALTER TABLE bpc_tsk_bridge.audit_deliveries
    ADD COLUMN state text NOT NULL DEFAULT 'pending',
    ADD COLUMN next_attempt_at timestamptz DEFAULT clock_timestamp(),
    ADD COLUMN policy_started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN cycle_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN last_failure_code text,
    ADD COLUMN last_failed_at timestamptz,
    ADD COLUMN quarantined_at timestamptz,
    ADD COLUMN quarantine_reason text;

-- Preserve lifetime claims and immutable payloads, conservatively delay legacy
-- leases, and quarantine legacy work that already exhausted the fixed budget.
UPDATE bpc_tsk_bridge.audit_deliveries d SET
    policy_started_at = o.recorded_at,
    cycle_attempts = least(d.attempts, 12)::integer,
    state = CASE WHEN d.delivered_at IS NOT NULL THEN 'delivered'
        WHEN d.attempts >= 12 OR o.recorded_at + interval '7 days' <= clock_timestamp()
            THEN 'quarantined' ELSE 'pending' END,
    next_attempt_at = CASE WHEN d.delivered_at IS NOT NULL OR d.attempts >= 12
        OR o.recorded_at + interval '7 days' <= clock_timestamp() THEN NULL
        ELSE greatest(o.recorded_at, coalesce(d.lease_until, o.recorded_at) + interval '1 second') END,
    quarantined_at = CASE WHEN d.delivered_at IS NULL AND (d.attempts >= 12
        OR o.recorded_at + interval '7 days' <= clock_timestamp()) THEN clock_timestamp() END,
    quarantine_reason = CASE WHEN d.delivered_at IS NULL THEN
        CASE WHEN o.recorded_at + interval '7 days' <= clock_timestamp() THEN 'age_limit'
            WHEN d.attempts >= 12 THEN 'attempt_limit' END END
FROM bpc_tsk_bridge.audit_outbox o WHERE d.event_id = o.event_id;
UPDATE bpc_tsk_bridge.audit_deliveries SET lease_token = NULL, lease_owner = NULL,
    lease_until = NULL WHERE state = 'quarantined';
ALTER TABLE bpc_tsk_bridge.audit_deliveries
    ADD CONSTRAINT delivery_state_closed CHECK (state IN ('pending', 'delivered', 'quarantined')),
    ADD CONSTRAINT delivery_cycle_bound CHECK (cycle_attempts BETWEEN 0 AND 12 AND attempts >= cycle_attempts),
    ADD CONSTRAINT delivery_failure_closed CHECK (
        last_failure_code IN ('unavailable', 'timeout', 'rate_limited', 'rejected', 'invalid_event')
        AND (last_failure_code IS NULL) = (last_failed_at IS NULL)),
    ADD CONSTRAINT delivery_quarantine_closed CHECK (
        quarantine_reason IN ('attempt_limit', 'age_limit', 'permanent_failure', 'attempt_overflow')),
    ADD CONSTRAINT delivery_state_shape CHECK (
        (state = 'pending' AND delivered_at IS NULL AND next_attempt_at IS NOT NULL
            AND quarantined_at IS NULL AND quarantine_reason IS NULL
            AND ((lease_token IS NULL AND lease_owner IS NULL AND lease_until IS NULL)
                OR (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_until IS NOT NULL
                    AND cycle_attempts > 0)))
        OR (state = 'delivered' AND delivered_at IS NOT NULL AND next_attempt_at IS NULL
            AND quarantined_at IS NULL AND quarantine_reason IS NULL
            AND lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_until IS NULL AND attempts > 0)
        OR (state = 'quarantined' AND delivered_at IS NULL AND next_attempt_at IS NULL
            AND quarantined_at IS NOT NULL AND quarantine_reason IS NOT NULL
            AND lease_token IS NULL AND lease_owner IS NULL AND lease_until IS NULL)
    );
CREATE INDEX pending_audit_deliveries ON bpc_tsk_bridge.audit_deliveries
    (next_attempt_at, event_id) WHERE state = 'pending';
CREATE INDEX aging_audit_deliveries ON bpc_tsk_bridge.audit_deliveries
    (policy_started_at, event_id) WHERE state = 'pending';

CREATE TABLE bpc_tsk_bridge.delivery_requeues (
    operation_id uuid PRIMARY KEY CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'),
    event_id uuid NOT NULL REFERENCES bpc_tsk_bridge.audit_outbox (event_id),
    actor_id varchar(128) COLLATE "C" NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'
        AND actor_id NOT IN ('__proto__', 'constructor', 'prototype')),
    reason_code text NOT NULL CHECK (reason_code IN ('destination_repaired', 'reviewed_recovery')),
    database_actor name NOT NULL,
    prior_attempts bigint NOT NULL CHECK (prior_attempts >= 0),
    prior_cycle_attempts integer NOT NULL CHECK (prior_cycle_attempts BETWEEN 0 AND 12),
    prior_policy_started_at timestamptz NOT NULL,
    prior_quarantine_reason text NOT NULL CHECK (
        prior_quarantine_reason IN ('attempt_limit', 'age_limit', 'permanent_failure', 'attempt_overflow')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable_delivery_requeues BEFORE UPDATE OR DELETE ON bpc_tsk_bridge.delivery_requeues
    FOR EACH ROW EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();
CREATE TRIGGER immutable_delivery_requeues_truncate BEFORE TRUNCATE ON bpc_tsk_bridge.delivery_requeues
    FOR EACH STATEMENT EXECUTE FUNCTION bpc_tsk_bridge.reject_history_change();

-- Private helpers; callers never select policy limits or supply a clock/token.
CREATE FUNCTION bpc_tsk_bridge.delivery_identifier_valid(p_id text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_id IS NOT NULL AND p_id COLLATE "C" ~ '^[A-Za-z0-9_.:@-]{1,128}$'
        AND p_id NOT IN ('__proto__', 'constructor', 'prototype');
$$;
CREATE FUNCTION bpc_tsk_bridge.delivery_backoff(p_attempt integer) RETURNS interval
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT least(300, (1::bigint << greatest(0, least(p_attempt - 1, 9)))::integer) * interval '1 second';
$$;

-- Initial delivery creation cannot be abused to insert arbitrary delivery state.
CREATE OR REPLACE FUNCTION bpc_tsk_bridge.enqueue_delivery() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO bpc_tsk_bridge.audit_deliveries (event_id, policy_started_at, next_attempt_at)
        VALUES (NEW.event_id, NEW.recorded_at, NEW.recorded_at);
    RETURN NEW;
END;
$$;

CREATE FUNCTION bpc_tsk_bridge.claim_audit_deliveries(p_worker text, p_batch bigint, p_lease_ms bigint)
RETURNS TABLE (event_id uuid, lease_token uuid, attempts bigint, expiry_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r bpc_tsk_bridge.audit_deliveries%ROWTYPE;
    v_now timestamptz;
    v_reason text;
BEGIN
    IF NOT bpc_tsk_bridge.delivery_identifier_valid(p_worker)
        OR p_batch IS NULL OR p_batch NOT BETWEEN 1 AND 100
        OR p_lease_ms IS NULL OR p_lease_ms NOT BETWEEN 100 AND 300000 THEN
        RAISE EXCEPTION 'invalid delivery input' USING ERRCODE = '22023';
    END IF;
    FOR r IN SELECT d.* FROM bpc_tsk_bridge.audit_deliveries d
        WHERE d.state = 'pending'
            AND (d.next_attempt_at <= clock_timestamp()
                OR d.policy_started_at + interval '7 days' <= clock_timestamp())
            AND (d.lease_until IS NULL OR d.lease_until <= clock_timestamp())
        ORDER BY d.next_attempt_at, d.event_id LIMIT p_batch FOR UPDATE SKIP LOCKED
    LOOP
        v_now := clock_timestamp();
        v_reason := CASE WHEN r.policy_started_at + interval '7 days' <= v_now THEN 'age_limit'
            WHEN r.attempts = 9223372036854775807 THEN 'attempt_overflow'
            WHEN r.cycle_attempts >= 12 THEN 'attempt_limit' END;
        IF v_reason IS NOT NULL THEN
            UPDATE bpc_tsk_bridge.audit_deliveries d SET state = 'quarantined',
                quarantined_at = v_now, quarantine_reason = v_reason, next_attempt_at = NULL,
                lease_token = NULL, lease_owner = NULL, lease_until = NULL WHERE d.event_id = r.event_id;
        ELSE
            RETURN QUERY UPDATE bpc_tsk_bridge.audit_deliveries d
                SET lease_token = pg_catalog.gen_random_uuid(), lease_owner = p_worker,
                    lease_until = v_now + (p_lease_ms * interval '1 millisecond'),
                    -- An abandoned/expired claim must not cause a tight retry loop.
                    next_attempt_at = v_now + (p_lease_ms * interval '1 millisecond')
                        + bpc_tsk_bridge.delivery_backoff(d.cycle_attempts + 1),
                    attempts = d.attempts + 1, cycle_attempts = d.cycle_attempts + 1
                WHERE d.event_id = r.event_id
                RETURNING d.event_id, d.lease_token, d.attempts,
                    floor(extract(epoch FROM d.lease_until) * 1000)::bigint;
        END IF;
    END LOOP;
END;
$$;

CREATE FUNCTION bpc_tsk_bridge.acknowledge_audit_delivery(p_event uuid, p_worker text, p_token uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r bpc_tsk_bridge.audit_deliveries%ROWTYPE;
BEGIN
    IF p_event IS NULL OR p_event = '00000000-0000-0000-0000-000000000000'
        OR p_token IS NULL OR p_token = '00000000-0000-0000-0000-000000000000'
        OR NOT bpc_tsk_bridge.delivery_identifier_valid(p_worker) THEN
        RAISE EXCEPTION 'invalid delivery input' USING ERRCODE = '22023';
    END IF;
    SELECT d.* INTO r FROM bpc_tsk_bridge.audit_deliveries d WHERE d.event_id = p_event FOR UPDATE;
    -- Evaluate DB time AFTER acquiring the row lock, never a stale statement timestamp.
    IF NOT FOUND OR r.lease_owner IS DISTINCT FROM p_worker OR r.lease_token IS DISTINCT FROM p_token
        OR r.state = 'quarantined' THEN RETURN false; END IF;
    IF r.state = 'delivered' THEN RETURN true; END IF;
    IF r.lease_until IS NULL OR r.lease_until <= clock_timestamp() THEN RETURN false; END IF;
    UPDATE bpc_tsk_bridge.audit_deliveries SET state = 'delivered', delivered_at = clock_timestamp(),
        lease_until = NULL, next_attempt_at = NULL WHERE event_id = p_event;
    RETURN true;
END;
$$;

CREATE FUNCTION bpc_tsk_bridge.fail_audit_delivery(
    p_event uuid, p_worker text, p_token uuid, p_failure text, p_retry_ms bigint)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r bpc_tsk_bridge.audit_deliveries%ROWTYPE;
    v_now timestamptz;
    v_next timestamptz;
    v_reason text;
BEGIN
    IF p_event IS NULL OR p_event = '00000000-0000-0000-0000-000000000000'
        OR p_token IS NULL OR p_token = '00000000-0000-0000-0000-000000000000'
        OR NOT bpc_tsk_bridge.delivery_identifier_valid(p_worker)
        OR p_failure IS NULL OR p_failure NOT IN ('unavailable', 'timeout', 'rate_limited', 'rejected', 'invalid_event')
        OR p_retry_ms IS NULL OR p_retry_ms NOT BETWEEN 1000 AND 3600000 THEN
        RAISE EXCEPTION 'invalid delivery input' USING ERRCODE = '22023';
    END IF;
    SELECT d.* INTO r FROM bpc_tsk_bridge.audit_deliveries d WHERE d.event_id = p_event FOR UPDATE;
    v_now := clock_timestamp();
    IF NOT FOUND OR r.state <> 'pending' OR r.lease_owner IS DISTINCT FROM p_worker
        OR r.lease_token IS DISTINCT FROM p_token OR r.lease_until IS NULL OR r.lease_until <= v_now THEN
        RETURN NULL;
    END IF;
    v_next := v_now + greatest(p_retry_ms * interval '1 millisecond',
        bpc_tsk_bridge.delivery_backoff(r.cycle_attempts));
    v_reason := CASE WHEN p_failure IN ('rejected', 'invalid_event') THEN 'permanent_failure'
        WHEN r.policy_started_at + interval '7 days' <= v_next THEN 'age_limit'
        WHEN r.attempts = 9223372036854775807 THEN 'attempt_overflow'
        WHEN r.cycle_attempts >= 12 THEN 'attempt_limit' END;
    UPDATE bpc_tsk_bridge.audit_deliveries SET
        state = CASE WHEN v_reason IS NULL THEN 'pending' ELSE 'quarantined' END,
        next_attempt_at = CASE WHEN v_reason IS NULL THEN v_next END,
        last_failure_code = p_failure, last_failed_at = v_now,
        quarantined_at = CASE WHEN v_reason IS NOT NULL THEN v_now END, quarantine_reason = v_reason,
        lease_token = NULL, lease_owner = NULL, lease_until = NULL WHERE event_id = p_event;
    RETURN CASE WHEN v_reason IS NULL THEN 'pending' ELSE 'quarantined' END;
END;
$$;

CREATE FUNCTION bpc_tsk_bridge.requeue_audit_delivery(p_event uuid, p_operation uuid, p_actor text, p_reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r bpc_tsk_bridge.audit_deliveries%ROWTYPE;
    h bpc_tsk_bridge.delivery_requeues%ROWTYPE;
    v_now timestamptz;
BEGIN
    IF p_event IS NULL OR p_event = '00000000-0000-0000-0000-000000000000'
        OR p_operation IS NULL OR p_operation = '00000000-0000-0000-0000-000000000000'
        OR NOT bpc_tsk_bridge.delivery_identifier_valid(p_actor)
        OR p_reason IS NULL OR p_reason NOT IN ('destination_repaired', 'reviewed_recovery') THEN
        RAISE EXCEPTION 'invalid delivery input' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO h FROM bpc_tsk_bridge.delivery_requeues WHERE operation_id = p_operation;
    IF FOUND THEN
        IF h.event_id = p_event AND h.actor_id = p_actor AND h.reason_code = p_reason THEN RETURN true; END IF;
        RAISE EXCEPTION 'requeue operation conflict' USING ERRCODE = 'BP001';
    END IF;
    SELECT d.* INTO r FROM bpc_tsk_bridge.audit_deliveries d WHERE d.event_id = p_event FOR UPDATE;
    IF NOT FOUND OR r.state <> 'quarantined' OR r.attempts = 9223372036854775807 THEN RETURN false; END IF;
    v_now := clock_timestamp();
    INSERT INTO bpc_tsk_bridge.delivery_requeues (operation_id, event_id, actor_id, reason_code,
        database_actor, prior_attempts, prior_cycle_attempts, prior_policy_started_at, prior_quarantine_reason, recorded_at)
        VALUES (p_operation, p_event, p_actor, p_reason, session_user, r.attempts,
            r.cycle_attempts, r.policy_started_at, r.quarantine_reason, v_now);
    UPDATE bpc_tsk_bridge.audit_deliveries SET state = 'pending', cycle_attempts = 0,
        policy_started_at = v_now, next_attempt_at = v_now + interval '1 second',
        quarantined_at = NULL, quarantine_reason = NULL,
        lease_token = NULL, lease_owner = NULL, lease_until = NULL WHERE event_id = p_event;
    RETURN true;
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'requeue operation conflict' USING ERRCODE = 'BP001';
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA bpc_tsk_bridge FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bpc_tsk_bridge FROM PUBLIC;
-- Upgrade the standard example roles too, if already provisioned. Custom roles
-- require the same explicit column-level revocations in the deployment runbook.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'bridge_publisher') THEN
        REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bpc_tsk_bridge FROM bridge_publisher;
        REVOKE ALL ON bpc_tsk_bridge.delivery_requeues FROM bridge_publisher;
        REVOKE ALL ON bpc_tsk_bridge.audit_deliveries FROM bridge_publisher;
        REVOKE ALL (event_id, lease_token, lease_owner, lease_until, attempts, delivered_at,
            state, next_attempt_at, policy_started_at, cycle_attempts, last_failure_code,
            last_failed_at, quarantined_at, quarantine_reason)
            ON bpc_tsk_bridge.audit_deliveries FROM bridge_publisher;
        GRANT SELECT ON bpc_tsk_bridge.audit_deliveries TO bridge_publisher;
        GRANT EXECUTE ON FUNCTION bpc_tsk_bridge.claim_audit_deliveries(text, bigint, bigint),
            bpc_tsk_bridge.acknowledge_audit_delivery(uuid, text, uuid),
            bpc_tsk_bridge.fail_audit_delivery(uuid, text, uuid, text, bigint) TO bridge_publisher;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'bridge_verifier') THEN
        REVOKE INSERT (event_id) ON bpc_tsk_bridge.audit_deliveries FROM bridge_verifier;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'bridge_control') THEN
        REVOKE INSERT (event_id) ON bpc_tsk_bridge.audit_deliveries FROM bridge_control;
        GRANT SELECT ON bpc_tsk_bridge.delivery_requeues TO bridge_control;
        GRANT EXECUTE ON FUNCTION bpc_tsk_bridge.requeue_audit_delivery(uuid, uuid, text, text) TO bridge_control;
    END IF;
END;
$$;
