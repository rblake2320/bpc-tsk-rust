#![cfg(feature = "postgres-authority")]
//! Opt-in tests for disposable local PostgreSQL databases. Normal test runs
//! compile these tests but never connect. Ignored execution requires explicit
//! environment variables; none default to localhost or ambient PG* variables.

use std::{thread, time::Duration};

use bpc_tsk_core::{
    AuditPhase, BindingStore, BridgeAuditRecord, FailureClass,
    postgres_authority::{
        AuthorityError, AuthorityLimits, BindingReason, DeliveryFailureClass,
        DeliveryRequeueContext, DeliveryRequeueReason, DeliveryState, MutationContext,
        OutboxPayload, PostgresAuthority, SCHEMA_VERSION,
    },
};
use postgres::{Config, NoTls};
use uuid::Uuid;

fn explicit_test_config() -> Config {
    std::env::var("BPC_TSK_POSTGRES_TEST_URL")
        .expect("explicit BPC_TSK_POSTGRES_TEST_URL for a disposable local database is required")
        .parse()
        .expect("valid explicit test URL")
}

fn context(reason: BindingReason) -> MutationContext {
    MutationContext {
        operation_id: Uuid::new_v4(),
        actor_id: "test:privileged-operator".into(),
        reason,
    }
}

fn local_authority(config: Config) -> PostgresAuthority {
    PostgresAuthority::connect_insecure_local_test(config, AuthorityLimits::default())
        .expect("explicit local test connection")
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_TEST_URL and a disposable local PostgreSQL database"]
fn lifecycle_audit_leases_constraints_and_migration_reapplication() {
    let config = explicit_test_config();
    // Validate locality through the public test-only constructor BEFORE raw test
    // inspection opens a connection. Raw NoTls is confined to this opt-in test.
    let authority = local_authority(config.clone());
    authority.migrate().unwrap();
    authority.migrate().unwrap();
    authority.check_schema().unwrap();
    let mut inspect = config.connect(NoTls).unwrap();
    inspect
        .execute(
            "UPDATE bpc_tsk_bridge.schema_version SET version = $1 WHERE singleton",
            &[&(SCHEMA_VERSION + 1)],
        )
        .unwrap();
    assert_eq!(
        authority.check_schema(),
        Err(AuthorityError::SchemaMismatch)
    );
    assert_eq!(authority.migrate(), Err(AuthorityError::SchemaMismatch));
    inspect
        .execute(
            "UPDATE bpc_tsk_bridge.schema_version SET version = $1 WHERE singleton",
            &[&SCHEMA_VERSION],
        )
        .unwrap();
    authority.check_schema().unwrap();
    // Drain only this explicitly disposable database's old test queue so
    // re-running the suite does not assume there are fewer than 100 events.
    loop {
        let old = authority
            .claim_outbox("test:cleanup", 100, Duration::from_secs(10))
            .unwrap();
        if old.is_empty() {
            break;
        }
        for event in old {
            authority
                .acknowledge_delivery(event.event_id, "test:cleanup", event.lease_token)
                .unwrap();
        }
    }
    let suffix = Uuid::new_v4().simple().to_string();
    let pair = format!("pair_{suffix}");
    let client = format!("client_{suffix}");
    let principal = format!("principal_{suffix}");
    let activate = context(BindingReason::Provision);
    let initial = authority
        .activate(&pair, &client, &principal, 0, &activate)
        .unwrap();
    assert_eq!(initial.binding.revision(), 1);
    assert_eq!(
        authority
            .activate(&pair, &client, &principal, 0, &activate)
            .unwrap(),
        initial
    );
    assert_eq!(
        authority.binding_change(activate.operation_id).unwrap(),
        Some(initial.clone())
    );
    assert!(authority.recheck_active(&initial.binding).unwrap());
    assert_eq!(
        authority.activate(&pair, &client, "changed_principal", 0, &activate),
        Err(AuthorityError::OperationConflict)
    );
    assert_eq!(
        authority.activate(
            &pair,
            &client,
            &principal,
            0,
            &context(BindingReason::Provision)
        ),
        Err(AuthorityError::RevisionConflict)
    );
    let other_pair = format!("other_{suffix}");
    assert_eq!(
        authority.activate(
            &other_pair,
            &client,
            &principal,
            0,
            &context(BindingReason::Provision)
        ),
        Err(AuthorityError::IdentityConflict)
    );
    assert!(authority.lookup_active(&other_pair).unwrap().is_none());
    let count: i64 = inspect
        .query_one(
            "SELECT count(*) FROM bpc_tsk_bridge.binding_history WHERE bpc_pair_id = $1",
            &[&other_pair],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        count, 0,
        "failed activation must roll back history/outbox as well"
    );

    let revoke = context(BindingReason::Revocation);
    assert_eq!(
        authority.revoke(&pair, 99, &revoke),
        Err(AuthorityError::RevisionConflict)
    );
    let revoked = authority.revoke(&pair, 1, &revoke).unwrap();
    assert_eq!(revoked.binding.revision(), 2);
    assert!(!revoked.active);
    assert!(authority.lookup_active(&pair).unwrap().is_none());
    assert!(!authority.recheck_active(&initial.binding).unwrap());
    assert_eq!(authority.revoke(&pair, 1, &revoke).unwrap(), revoked);
    assert_eq!(
        authority.revoke(&pair, 2, &context(BindingReason::Revocation)),
        Err(AuthorityError::RevisionConflict)
    );
    let reactivated = authority
        .activate(
            &pair,
            &client,
            &principal,
            2,
            &context(BindingReason::Recovery),
        )
        .unwrap();
    assert_eq!(reactivated.binding.revision(), 3);
    assert_eq!(
        reactivated.binding.binding_id(),
        initial.binding.binding_id()
    );
    assert!(!authority.recheck_active(&initial.binding).unwrap());
    assert_eq!(
        authority
            .activate(&pair, &client, &principal, 0, &activate)
            .unwrap(),
        initial,
        "idempotent replay is historical reconciliation, not a new activation"
    );

    for table in [
        "binding_history",
        "audit_outbox",
        "verification_attempts",
        "schema_migrations",
    ] {
        // Identifiers are constants from this test, never API/request input.
        let error = inspect.batch_execute(&format!("DELETE FROM bpc_tsk_bridge.{table}"));
        // verification_attempts can be empty before the audit test; statement
        // TRUNCATE triggers must still protect an empty append-only table.
        if table != "verification_attempts" {
            assert!(error.is_err());
        }
        assert!(
            inspect
                .batch_execute(&format!("TRUNCATE bpc_tsk_bridge.{table} CASCADE"))
                .is_err()
        );
    }
    assert!(inspect.execute(
        "UPDATE bpc_tsk_bridge.principal_bindings SET active = false, revision = revision + 1 WHERE bpc_pair_id = $1",
        &[&pair],
    ).is_err(), "binding mutation without transactional history/outbox must fail at commit");
    assert!(authority.recheck_active(&reactivated.binding).unwrap());

    let correlation = Uuid::new_v4();
    let attempt = BridgeAuditRecord {
        correlation_id: correlation,
        request_context_digest: "ab".repeat(32),
        phase: AuditPhase::Attempt,
        failure_class: None,
        binding_revision: None,
    };
    authority.record_audit(attempt.clone()).unwrap();
    authority.record_audit(attempt.clone()).unwrap();
    let mut mismatched = attempt.clone();
    mismatched.request_context_digest = "cd".repeat(32);
    assert_eq!(
        authority.record_audit(mismatched),
        Err(AuthorityError::OperationConflict)
    );
    let allowed = BridgeAuditRecord {
        phase: AuditPhase::Allowed,
        binding_revision: Some(3),
        ..attempt.clone()
    };
    authority.record_audit(allowed.clone()).unwrap();
    authority.record_audit(allowed).unwrap();
    let denied = BridgeAuditRecord {
        phase: AuditPhase::Denied,
        failure_class: Some(FailureClass::FinalFence),
        ..attempt
    };
    assert_eq!(
        authority.record_audit(denied),
        Err(AuthorityError::OperationConflict)
    );
    let audit_count: i64 = inspect
        .query_one(
            "SELECT count(*) FROM bpc_tsk_bridge.audit_outbox WHERE correlation_id = $1",
            &[&correlation],
        )
        .unwrap()
        .get(0);
    assert_eq!(audit_count, 2);
    let persisted: Vec<u8> = inspect.query_one(
        "SELECT context_commitment FROM bpc_tsk_bridge.verification_attempts WHERE correlation_id = $1", &[&correlation],
    ).unwrap().get(0);
    assert_eq!(persisted.len(), 32);
    assert_ne!(persisted, vec![0xab; 32]);

    // This test must own the disposable database's publisher queue. It preserves
    // all records rather than truncating immutable authority data between runs.
    let first = authority
        .claim_outbox("publisher:old", 100, Duration::from_millis(100))
        .unwrap();
    assert!(!first.is_empty());
    assert!(
        authority
            .claim_outbox("publisher:other", 100, Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );
    let old = first
        .iter()
        .find(|event| event.event_id == activate.operation_id)
        .unwrap();
    assert!(
        !authority
            .acknowledge_delivery(old.event_id, "publisher:wrong", old.lease_token)
            .unwrap()
    );
    thread::sleep(Duration::from_millis(150));
    assert!(
        !authority
            .acknowledge_delivery(old.event_id, "publisher:old", old.lease_token)
            .unwrap()
    );
    assert!(
        authority
            .claim_outbox("publisher:no-tight-loop", 100, Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );
    thread::sleep(Duration::from_millis(1100));
    let second = authority
        .claim_outbox("publisher:new", 100, Duration::from_secs(10))
        .unwrap();
    let new = second
        .iter()
        .find(|event| event.event_id == old.event_id)
        .unwrap();
    assert_ne!(new.lease_token, old.lease_token);
    assert_eq!(new.delivery_attempt, old.delivery_attempt + 1);
    assert!(
        !authority
            .acknowledge_delivery(old.event_id, "publisher:old", old.lease_token)
            .unwrap()
    );
    assert!(matches!(&new.payload, OutboxPayload::Binding(change) if change == &initial));
    assert!(second.iter().any(|event| matches!(&event.payload,
        OutboxPayload::Verification(record) if record.correlation_id == correlation)));
    for event in &second {
        assert!(
            authority
                .acknowledge_delivery(event.event_id, "publisher:new", event.lease_token)
                .unwrap()
        );
        assert!(
            authority
                .acknowledge_delivery(event.event_id, "publisher:new", event.lease_token)
                .unwrap()
        );
    }
    assert!(
        authority
            .claim_outbox("publisher:finished", 100, Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_TEST_URL; two independent local database connections"]
fn concurrent_expected_revision_has_only_one_winner() {
    let config = explicit_test_config();
    let authority = local_authority(config.clone());
    authority.migrate().unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let pair = format!("race_{suffix}");
    let client = format!("client_{suffix}");
    authority
        .activate(
            &pair,
            &client,
            "principal",
            0,
            &context(BindingReason::Provision),
        )
        .unwrap();
    let first = local_authority(config.clone());
    let second = local_authority(config);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let pair1 = pair.clone();
    let pair2 = pair.clone();
    let barrier1 = barrier.clone();
    let one = thread::spawn(move || {
        barrier1.wait();
        first.revoke(&pair1, 1, &context(BindingReason::Revocation))
    });
    let two = thread::spawn(move || {
        barrier.wait();
        second.revoke(&pair2, 1, &context(BindingReason::Revocation))
    });
    let results = [one.join().unwrap(), two.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().any(|result| matches!(
        result,
        Err(AuthorityError::RevisionConflict | AuthorityError::SerializationFailure)
    )));
    assert!(authority.lookup_active(&pair).unwrap().is_none());
}

#[test]
#[ignore = "requires explicit TLS test URL and DER trust-root path; never uses NoTls"]
fn verified_tls_connection_and_explicit_hostname_failure() {
    let url = std::env::var("BPC_TSK_POSTGRES_TLS_TEST_URL")
        .expect("explicit BPC_TSK_POSTGRES_TLS_TEST_URL is required");
    let root_path = std::env::var("BPC_TSK_POSTGRES_TLS_TEST_CA_DER")
        .expect("explicit BPC_TSK_POSTGRES_TLS_TEST_CA_DER is required");
    let wrong_name_url = std::env::var("BPC_TSK_POSTGRES_TLS_WRONG_HOST_TEST_URL")
        .expect("explicit URL to same server with wrong host and fixed hostaddr is required");
    let root = std::fs::read(root_path).expect("DER public trust-root certificate");
    let authority = PostgresAuthority::connect_tls(
        url.parse().unwrap(),
        &[root.clone()],
        AuthorityLimits::default(),
    )
    .unwrap();
    authority.migrate().unwrap();
    authority.check_schema().unwrap();
    assert_eq!(
        PostgresAuthority::connect_tls(
            wrong_name_url.parse().unwrap(),
            &[root],
            AuthorityLimits::default()
        )
        .unwrap_err(),
        AuthorityError::Unavailable
    );
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_TEST_URL and a disposable local database"]
fn binding_lock_timeout_is_fail_closed_and_transactional() {
    let config = explicit_test_config();
    let limits = AuthorityLimits {
        statement_timeout: Duration::from_millis(200),
        lock_timeout: Duration::from_millis(50),
        ..AuthorityLimits::default()
    };
    let authority = PostgresAuthority::connect_insecure_local_test(config.clone(), limits).unwrap();
    // Migrate with normal DDL limits, not intentionally short mutation limits.
    local_authority(config.clone()).migrate().unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let pair = format!("locked_{suffix}");
    let client = format!("client_{suffix}");
    let original = authority
        .activate(
            &pair,
            &client,
            "principal",
            0,
            &context(BindingReason::Provision),
        )
        .unwrap();
    let mut inspect = config.connect(NoTls).unwrap();
    let mut blocker = inspect.transaction().unwrap();
    blocker
        .batch_execute("LOCK TABLE bpc_tsk_bridge.principal_bindings IN ACCESS EXCLUSIVE MODE")
        .unwrap();
    assert!(authority.lookup_active(&pair).is_err());
    let revoke = context(BindingReason::Revocation);
    assert_eq!(
        authority.revoke(&pair, 1, &revoke),
        Err(AuthorityError::Unavailable)
    );
    blocker.rollback().unwrap();
    assert!(authority.recheck_active(&original.binding).unwrap());
    assert!(
        authority
            .binding_change(revoke.operation_id)
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_TEST_URL, disposable cluster and role-admin privileges"]
fn least_privilege_role_template_separates_runtime_boundaries() {
    let config = explicit_test_config();
    let admin = local_authority(config.clone());
    admin.migrate().unwrap();
    let mut inspect = config.connect(NoTls).unwrap();
    for role in ["bridge_verifier", "bridge_control", "bridge_publisher"] {
        assert!(
            inspect
                .query_opt(
                    "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1",
                    &[&role]
                )
                .unwrap()
                .is_none(),
            "role template test requires a disposable cluster without pre-existing example roles"
        );
    }
    inspect.batch_execute("CREATE ROLE bridge_verifier NOLOGIN; CREATE ROLE bridge_control NOLOGIN; CREATE ROLE bridge_publisher NOLOGIN;").unwrap();
    inspect
        .batch_execute(include_str!("../../../migrations/ROLE_GRANTS.example.sql"))
        .unwrap();
    let mut control_config = config.clone();
    control_config.options("-c role=bridge_control");
    let control = local_authority(control_config);
    let mut verifier_config = config.clone();
    verifier_config.options("-c role=bridge_verifier");
    let verifier = local_authority(verifier_config);
    let mut publisher_config = config;
    publisher_config.options("-c role=bridge_publisher");
    let publisher = local_authority(publisher_config);
    control.check_schema().unwrap();
    verifier.check_schema().unwrap();
    publisher.check_schema().unwrap();
    assert!(control.migrate().is_err());
    assert!(verifier.migrate().is_err());
    assert!(publisher.migrate().is_err());
    let suffix = Uuid::new_v4().simple().to_string();
    let pair = format!("roles_{suffix}");
    let client = format!("client_{suffix}");
    let activation = context(BindingReason::Provision);
    let binding = control
        .activate(&pair, &client, "principal", 0, &activation)
        .unwrap();
    assert_eq!(
        verifier.lookup_active(&pair).unwrap(),
        Some(binding.binding.clone())
    );
    assert!(verifier.recheck_active(&binding.binding).unwrap());
    assert!(publisher.lookup_active(&pair).is_err());
    assert!(
        verifier
            .activate(
                &pair,
                &client,
                "principal",
                1,
                &context(BindingReason::Rotation)
            )
            .is_err()
    );
    assert!(
        publisher
            .activate(
                &pair,
                &client,
                "principal",
                1,
                &context(BindingReason::Rotation)
            )
            .is_err()
    );
    let attempt = BridgeAuditRecord {
        correlation_id: Uuid::new_v4(),
        request_context_digest: "ab".repeat(32),
        phase: AuditPhase::Attempt,
        failure_class: None,
        binding_revision: None,
    };
    verifier.record_audit(attempt.clone()).unwrap();
    assert!(control.record_audit(attempt.clone()).is_err());
    assert!(publisher.record_audit(attempt).is_err());
    assert!(
        verifier
            .claim_outbox("publisher:denied", 1, Duration::from_secs(10))
            .is_err()
    );
    assert!(
        control
            .claim_outbox("publisher:denied", 1, Duration::from_secs(10))
            .is_err()
    );
    let claimed = publisher
        .claim_outbox("publisher:granted", 100, Duration::from_secs(10))
        .unwrap();
    assert!(
        claimed
            .iter()
            .any(|event| event.event_id == activation.operation_id)
    );
    for event in claimed {
        assert!(
            verifier
                .acknowledge_delivery(event.event_id, "publisher:granted", event.lease_token)
                .is_err()
        );
        assert!(
            control
                .acknowledge_delivery(event.event_id, "publisher:granted", event.lease_token)
                .is_err()
        );
        assert!(
            publisher
                .acknowledge_delivery(event.event_id, "publisher:granted", event.lease_token)
                .unwrap()
        );
    }
    let public_execute: bool = inspect
        .query_one(
            "SELECT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace,
        LATERAL pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
        WHERE n.nspname = 'bpc_tsk_bridge' AND a.grantee = 0 AND a.privilege_type = 'EXECUTE')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        !public_execute,
        "no bridge function is executable by PUBLIC"
    );
    inspect
        .batch_execute(
            "SET ROLE bridge_publisher; SET search_path = pg_temp, public;
        CREATE TEMP TABLE audit_deliveries (event_id uuid, state text);
        INSERT INTO audit_deliveries VALUES ('00000000-0000-0000-0000-000000000001', 'delivered');",
        )
        .unwrap();
    for sql in [
        "UPDATE bpc_tsk_bridge.audit_deliveries SET attempts = 0",
        "UPDATE bpc_tsk_bridge.audit_deliveries SET delivered_at = clock_timestamp()",
        "UPDATE bpc_tsk_bridge.audit_deliveries SET next_attempt_at = clock_timestamp()",
        "UPDATE bpc_tsk_bridge.audit_deliveries SET state = 'pending'",
        "UPDATE bpc_tsk_bridge.audit_deliveries SET lease_token = gen_random_uuid()",
        "UPDATE bpc_tsk_bridge.audit_deliveries SET lease_owner = 'stolen'",
        "UPDATE bpc_tsk_bridge.audit_deliveries SET lease_until = clock_timestamp() + interval '1 hour'",
        "INSERT INTO bpc_tsk_bridge.audit_deliveries(event_id) VALUES (gen_random_uuid())",
        "DELETE FROM bpc_tsk_bridge.audit_deliveries",
        "TRUNCATE bpc_tsk_bridge.audit_deliveries",
        "INSERT INTO bpc_tsk_bridge.delivery_requeues(operation_id) VALUES (gen_random_uuid())",
        "SELECT bpc_tsk_bridge.delivery_backoff(1)",
        "SELECT bpc_tsk_bridge.requeue_audit_delivery(gen_random_uuid(), gen_random_uuid(), 'operator', 'reviewed_recovery')",
    ] {
        let error = inspect.batch_execute(sql).unwrap_err();
        assert_eq!(
            error.code(),
            Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "{sql}"
        );
    }
    for sql in [
        "SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries('worker', 0, 1000)",
        "SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries('worker', 101, 1000)",
        "SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries('worker', 1, 1)",
        "SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries('worker', 1, 300001)",
        "SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries(NULL, 1, 1000)",
        "SELECT bpc_tsk_bridge.fail_audit_delivery(gen_random_uuid(), 'worker', gen_random_uuid(), 'raw destination body', 1000)",
        "SELECT bpc_tsk_bridge.fail_audit_delivery(gen_random_uuid(), 'worker', gen_random_uuid(), 'timeout', 0)",
        "SELECT bpc_tsk_bridge.fail_audit_delivery(gen_random_uuid(), 'worker', gen_random_uuid(), 'timeout', 3600001)",
    ] {
        assert_eq!(
            inspect.batch_execute(sql).unwrap_err().code(),
            Some(&postgres::error::SqlState::INVALID_PARAMETER_VALUE),
            "{sql}"
        );
    }
    // Qualified objects + fixed function paths ignore attacker-writable temps.
    assert!(
        inspect
            .query(
                "SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries('publisher:raw', 1, 1000)",
                &[]
            )
            .unwrap()
            .is_empty()
    );
    inspect
        .batch_execute("RESET ROLE; RESET search_path")
        .unwrap();
    let event_id = new_delivery(&verifier, &mut inspect);
    let recovery_claim = publisher
        .claim_outbox("publisher:recovery", 100, Duration::from_secs(10))
        .unwrap()
        .into_iter()
        .find(|event| event.event_id == event_id)
        .unwrap();
    assert_eq!(
        publisher
            .record_delivery_failure(
                event_id,
                "publisher:recovery",
                recovery_claim.lease_token,
                DeliveryFailureClass::InvalidEvent,
                Duration::from_secs(1)
            )
            .unwrap(),
        Some(DeliveryState::Quarantined)
    );
    let recovery = requeue_context();
    assert!(publisher.requeue_delivery(event_id, &recovery).is_err());
    assert!(verifier.requeue_delivery(event_id, &recovery).is_err());
    assert!(control.requeue_delivery(event_id, &recovery).unwrap());
    assert!(control.requeue_delivery(event_id, &recovery).unwrap());
    assert!(
        !publisher
            .acknowledge_delivery(event_id, "publisher:recovery", recovery_claim.lease_token)
            .unwrap()
    );
    assert_eq!(
        publisher
            .record_delivery_failure(
                event_id,
                "publisher:recovery",
                recovery_claim.lease_token,
                DeliveryFailureClass::Timeout,
                Duration::from_secs(1)
            )
            .unwrap(),
        None
    );
    control
        .revoke(&pair, 1, &context(BindingReason::Revocation))
        .unwrap();
    inspect.batch_execute("SET ROLE bridge_verifier").unwrap();
    assert!(inspect.execute("UPDATE bpc_tsk_bridge.principal_bindings SET active = false WHERE bpc_pair_id = $1", &[&pair]).is_err());
    assert!(
        inspect
            .batch_execute("UPDATE bpc_tsk_bridge.audit_outbox SET phase = 'denied'")
            .is_err()
    );
    assert!(
        inspect
            .batch_execute("CREATE TABLE bpc_tsk_bridge.unauthorized (id bigint)")
            .is_err()
    );
    inspect.batch_execute("RESET ROLE; DROP OWNED BY bridge_verifier, bridge_control, bridge_publisher; DROP ROLE bridge_verifier, bridge_control, bridge_publisher;").unwrap();
}

fn requeue_context() -> DeliveryRequeueContext {
    DeliveryRequeueContext {
        operation_id: Uuid::new_v4(),
        actor_id: "test:recovery-operator".into(),
        reason: DeliveryRequeueReason::ReviewedRecovery,
    }
}

fn new_delivery(authority: &PostgresAuthority, inspect: &mut postgres::Client) -> Uuid {
    let correlation_id = Uuid::new_v4();
    authority
        .record_audit(BridgeAuditRecord {
            correlation_id,
            request_context_digest: "ab".repeat(32),
            phase: AuditPhase::Attempt,
            failure_class: None,
            binding_revision: None,
        })
        .unwrap();
    inspect
        .query_one(
            "SELECT event_id FROM bpc_tsk_bridge.audit_outbox WHERE correlation_id = $1",
            &[&correlation_id],
        )
        .unwrap()
        .get(0)
}

fn claim_only(
    authority: &PostgresAuthority,
    event_id: Uuid,
) -> bpc_tsk_core::postgres_authority::ClaimedAuditEvent {
    let claimed = authority
        .claim_outbox("publisher:retry", 100, Duration::from_secs(10))
        .unwrap();
    let mut target = None;
    for event in claimed {
        if event.event_id == event_id {
            target = Some(event);
        } else {
            assert!(
                authority
                    .acknowledge_delivery(event.event_id, "publisher:retry", event.lease_token)
                    .unwrap()
            );
        }
    }
    target.expect("target delivery was due")
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_TEST_URL and sole ownership of a disposable queue"]
fn controlled_retry_quarantine_requeue_and_no_tight_loop() {
    let config = explicit_test_config();
    let authority = local_authority(config.clone());
    authority.migrate().unwrap();
    let mut inspect = config.connect(NoTls).unwrap();
    // Drain old due work; immutable history and quarantined work remain intact.
    loop {
        let old = authority
            .claim_outbox("publisher:cleanup", 100, Duration::from_secs(10))
            .unwrap();
        if old.is_empty() {
            break;
        }
        for event in old {
            assert!(
                authority
                    .acknowledge_delivery(event.event_id, "publisher:cleanup", event.lease_token)
                    .unwrap()
            );
        }
    }
    let event_id = new_delivery(&authority, &mut inspect);
    let first = claim_only(&authority, event_id);
    assert_eq!(first.delivery_attempt, 1);
    for (worker, token) in [
        ("publisher:wrong", first.lease_token),
        ("publisher:retry", Uuid::new_v4()),
    ] {
        assert_eq!(
            authority
                .record_delivery_failure(
                    event_id,
                    worker,
                    token,
                    DeliveryFailureClass::Timeout,
                    Duration::from_secs(1)
                )
                .unwrap(),
            None
        );
    }
    assert_eq!(
        authority
            .record_delivery_failure(
                event_id,
                "publisher:retry",
                first.lease_token,
                DeliveryFailureClass::RateLimited,
                Duration::from_secs(1)
            )
            .unwrap(),
        Some(DeliveryState::Pending)
    );
    let row = inspect
        .query_one(
            "SELECT state, attempts, cycle_attempts, lease_token IS NULL AS released,
        next_attempt_at > clock_timestamp() AS delayed, last_failure_code,
        next_attempt_at >= last_failed_at + interval '1 second' AS minimum_delay
        FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1",
            &[&event_id],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>("state"), "pending");
    assert_eq!(row.get::<_, i64>("attempts"), 1);
    assert!(
        row.get::<_, bool>("released")
            && row.get::<_, bool>("delayed")
            && row.get::<_, bool>("minimum_delay")
    );
    assert_eq!(row.get::<_, String>("last_failure_code"), "rate_limited");
    assert!(
        !authority
            .acknowledge_delivery(event_id, "publisher:retry", first.lease_token)
            .unwrap()
    );
    assert_eq!(
        authority
            .record_delivery_failure(
                event_id,
                "publisher:retry",
                first.lease_token,
                DeliveryFailureClass::Timeout,
                Duration::from_secs(1)
            )
            .unwrap(),
        None
    );
    for _ in 0..10 {
        assert!(
            authority
                .claim_outbox("publisher:retry", 100, Duration::from_secs(10))
                .unwrap()
                .is_empty()
        );
    }
    thread::sleep(Duration::from_millis(1100));
    let second = claim_only(&authority, event_id);
    assert_eq!(second.delivery_attempt, 2);
    assert_ne!(first.lease_token, second.lease_token);
    // Permanent classes never retry, even with a long caller-requested delay.
    assert_eq!(
        authority
            .record_delivery_failure(
                event_id,
                "publisher:retry",
                second.lease_token,
                DeliveryFailureClass::Rejected,
                Duration::from_secs(3600)
            )
            .unwrap(),
        Some(DeliveryState::Quarantined)
    );
    assert!(
        authority
            .claim_outbox("publisher:retry", 100, Duration::from_secs(10))
            .unwrap()
            .is_empty()
    );
    assert!(
        !authority
            .acknowledge_delivery(event_id, "publisher:retry", second.lease_token)
            .unwrap()
    );
    let context = requeue_context();
    assert!(authority.requeue_delivery(event_id, &context).unwrap());
    assert!(authority.requeue_delivery(event_id, &context).unwrap());
    let mut changed = context.clone();
    changed.reason = DeliveryRequeueReason::DestinationRepaired;
    assert_eq!(
        authority.requeue_delivery(event_id, &changed),
        Err(AuthorityError::OperationConflict)
    );
    assert_eq!(
        authority.requeue_delivery(Uuid::new_v4(), &context),
        Err(AuthorityError::OperationConflict)
    );
    let audit = inspect
        .query_one(
            "SELECT count(*) AS count, min(prior_attempts) AS prior_attempts,
        min(prior_cycle_attempts) AS prior_cycle, min(prior_quarantine_reason) AS cause
        FROM bpc_tsk_bridge.delivery_requeues WHERE operation_id = $1",
            &[&context.operation_id],
        )
        .unwrap();
    assert_eq!(audit.get::<_, i64>("count"), 1);
    assert_eq!(audit.get::<_, i64>("prior_attempts"), 2);
    assert_eq!(audit.get::<_, i32>("prior_cycle"), 2);
    assert_eq!(audit.get::<_, String>("cause"), "permanent_failure");
    assert!(
        inspect
            .batch_execute("UPDATE bpc_tsk_bridge.delivery_requeues SET actor_id = 'changed'")
            .is_err()
    );
    assert!(
        inspect
            .batch_execute("TRUNCATE bpc_tsk_bridge.delivery_requeues")
            .is_err()
    );
    assert!(
        authority
            .claim_outbox("publisher:retry", 100, Duration::from_secs(10))
            .unwrap()
            .is_empty()
    );
    // Test-owner time acceleration only; runtime roles cannot reschedule by SQL.
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET next_attempt_at = clock_timestamp() WHERE event_id = $1", &[&event_id]).unwrap();
    let third = claim_only(&authority, event_id);
    assert_eq!(
        third.delivery_attempt, 3,
        "requeue never resets lifetime attempts"
    );
    assert_eq!(
        inspect
            .query_one(
                "SELECT cycle_attempts FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1",
                &[&event_id]
            )
            .unwrap()
            .get::<_, i32>(0),
        1
    );
    assert_eq!(
        authority
            .record_delivery_failure(
                event_id,
                "publisher:retry",
                first.lease_token,
                DeliveryFailureClass::Unavailable,
                Duration::from_secs(1)
            )
            .unwrap(),
        None
    );
    assert!(
        authority
            .acknowledge_delivery(event_id, "publisher:retry", third.lease_token)
            .unwrap()
    );
    assert!(
        authority
            .acknowledge_delivery(event_id, "publisher:retry", third.lease_token)
            .unwrap()
    );
    assert!(
        !authority
            .requeue_delivery(event_id, &requeue_context())
            .unwrap()
    );
    assert_eq!(
        authority
            .record_delivery_failure(
                event_id,
                "publisher:retry",
                third.lease_token,
                DeliveryFailureClass::InvalidEvent,
                Duration::from_secs(1)
            )
            .unwrap(),
        None
    );

    // Twelve total claims per cycle, exponential delay capped at five minutes.
    let exhausted = new_delivery(&authority, &mut inspect);
    for attempt in 1..=12 {
        inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET next_attempt_at = clock_timestamp() WHERE event_id = $1", &[&exhausted]).unwrap();
        let claimed = claim_only(&authority, exhausted);
        assert_eq!(claimed.delivery_attempt, attempt);
        let state = authority
            .record_delivery_failure(
                exhausted,
                "publisher:retry",
                claimed.lease_token,
                DeliveryFailureClass::Unavailable,
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            state,
            Some(if attempt == 12 {
                DeliveryState::Quarantined
            } else {
                DeliveryState::Pending
            })
        );
        if attempt < 12 {
            let delay: i64 = inspect.query_one("SELECT extract(epoch FROM next_attempt_at - last_failed_at)::bigint FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1", &[&exhausted]).unwrap().get(0);
            assert_eq!(delay, (1_i64 << (attempt - 1)).min(300));
            assert!(
                authority
                    .claim_outbox("publisher:retry", 100, Duration::from_secs(1))
                    .unwrap()
                    .is_empty()
            );
        }
    }
    assert_eq!(
        inspect
            .query_one(
                "SELECT quarantine_reason FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1",
                &[&exhausted]
            )
            .unwrap()
            .get::<_, String>(0),
        "attempt_limit"
    );

    // Age sweeps quarantine unclaimed work, even if next_attempt_at is future.
    let aged = new_delivery(&authority, &mut inspect);
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET policy_started_at = clock_timestamp() - interval '8 days', next_attempt_at = clock_timestamp() + interval '1 hour' WHERE event_id = $1", &[&aged]).unwrap();
    assert!(
        authority
            .claim_outbox("publisher:retry", 100, Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inspect
            .query_one(
                "SELECT quarantine_reason FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1",
                &[&aged]
            )
            .unwrap()
            .get::<_, String>(0),
        "age_limit"
    );
    let aging_lease = new_delivery(&authority, &mut inspect);
    let lease = claim_only(&authority, aging_lease);
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET policy_started_at = clock_timestamp() - interval '7 days' + interval '500 milliseconds' WHERE event_id = $1", &[&aging_lease]).unwrap();
    assert_eq!(
        authority
            .record_delivery_failure(
                aging_lease,
                "publisher:retry",
                lease.lease_token,
                DeliveryFailureClass::Timeout,
                Duration::from_secs(1)
            )
            .unwrap(),
        Some(DeliveryState::Quarantined)
    );

    // Abandoned last attempt is swept, not reclaimed as a thirteenth attempt.
    let abandoned = new_delivery(&authority, &mut inspect);
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET attempts = 11, cycle_attempts = 11 WHERE event_id = $1", &[&abandoned]).unwrap();
    let final_claim = claim_only(&authority, abandoned);
    assert_eq!(final_claim.delivery_attempt, 12);
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET lease_until = clock_timestamp() - interval '1 second', next_attempt_at = clock_timestamp() WHERE event_id = $1", &[&abandoned]).unwrap();
    assert_eq!(
        authority
            .record_delivery_failure(
                abandoned,
                "publisher:retry",
                final_claim.lease_token,
                DeliveryFailureClass::Timeout,
                Duration::from_secs(1)
            )
            .unwrap(),
        None
    );
    assert!(
        !authority
            .acknowledge_delivery(abandoned, "publisher:retry", final_claim.lease_token)
            .unwrap()
    );
    assert!(
        authority
            .claim_outbox("publisher:retry", 100, Duration::from_secs(1))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inspect
            .query_one(
                "SELECT state FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1",
                &[&abandoned]
            )
            .unwrap()
            .get::<_, String>(0),
        "quarantined"
    );
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_UPGRADE_TEST_URL to an EMPTY disposable DB and role-admin cluster"]
fn version_one_upgrade_checksums_legacy_state_and_privilege_revocation() {
    use sha2::{Digest, Sha256};
    let config: Config = std::env::var("BPC_TSK_POSTGRES_UPGRADE_TEST_URL")
        .expect("explicit EMPTY disposable upgrade database URL required")
        .parse()
        .unwrap();
    let authority = local_authority(config.clone());
    let mut inspect = config.connect(NoTls).unwrap();
    assert!(
        inspect
            .query_one(
                "SELECT pg_catalog.to_regnamespace('bpc_tsk_bridge') IS NULL",
                &[]
            )
            .unwrap()
            .get::<_, bool>(0),
        "upgrade test requires an empty database"
    );
    assert!(
        inspect
            .query_opt(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'bridge_publisher'",
                &[]
            )
            .unwrap()
            .is_none()
    );
    inspect
        .batch_execute(include_str!("../../../migrations/0000_bootstrap.sql"))
        .unwrap();
    inspect
        .batch_execute(include_str!("../../../migrations/0001_authority.sql"))
        .unwrap();
    inspect
        .execute(
            "INSERT INTO bpc_tsk_bridge.schema_migrations(version, checksum) VALUES (1, $1)",
            &[&vec![0_u8; 32]],
        )
        .unwrap();
    inspect
        .batch_execute("UPDATE bpc_tsk_bridge.schema_version SET version = 1 WHERE singleton")
        .unwrap();
    assert_eq!(authority.migrate(), Err(AuthorityError::SchemaMismatch));
    assert!(inspect.query_one("SELECT NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'bpc_tsk_bridge' AND table_name = 'audit_deliveries' AND column_name = 'state')", &[]).unwrap().get::<_, bool>(0));
    // Test-only owner repair of intentionally corrupt immutable metadata.
    inspect
        .batch_execute(
            "ALTER TABLE bpc_tsk_bridge.schema_migrations DISABLE TRIGGER immutable_migrations",
        )
        .unwrap();
    let checksum =
        Sha256::digest(include_str!("../../../migrations/0001_authority.sql").as_bytes()).to_vec();
    inspect
        .execute(
            "UPDATE bpc_tsk_bridge.schema_migrations SET checksum = $1 WHERE version = 1",
            &[&checksum],
        )
        .unwrap();
    inspect
        .batch_execute(
            "ALTER TABLE bpc_tsk_bridge.schema_migrations ENABLE TRIGGER immutable_migrations",
        )
        .unwrap();
    let events = [
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    ];
    for event_id in events {
        inspect.execute("INSERT INTO bpc_tsk_bridge.verification_attempts(correlation_id, context_commitment) VALUES ($1, $2)", &[&event_id, &vec![0_u8; 32]]).unwrap();
        inspect.execute("INSERT INTO bpc_tsk_bridge.audit_outbox(event_id, event_kind, correlation_id, context_commitment, phase) VALUES ($1, 'verification', $1, $2, 'attempt')", &[&event_id, &vec![0_u8; 32]]).unwrap();
    }
    let old_token = Uuid::new_v4();
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET attempts = 1, lease_token = $2, lease_owner = 'publisher:legacy', lease_until = clock_timestamp() + interval '60 seconds' WHERE event_id = $1", &[&events[0], &old_token]).unwrap();
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET attempts = 12, lease_token = $2, lease_owner = 'publisher:legacy', lease_until = clock_timestamp() - interval '1 second' WHERE event_id = $1", &[&events[1], &Uuid::new_v4()]).unwrap();
    // Simulate downtime using only mutable v1 delivery metadata; age comes from
    // immutable outbox time, inserted old in a separately prepared event below.
    let aged = Uuid::new_v4();
    inspect.execute("INSERT INTO bpc_tsk_bridge.verification_attempts(correlation_id, context_commitment) VALUES ($1, $2)", &[&aged, &vec![0_u8; 32]]).unwrap();
    inspect.execute("INSERT INTO bpc_tsk_bridge.audit_outbox(event_id, event_kind, correlation_id, context_commitment, phase, recorded_at) VALUES ($1, 'verification', $1, $2, 'attempt', clock_timestamp() - interval '8 days')", &[&aged, &vec![0_u8; 32]]).unwrap();
    inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET attempts = 1, lease_token = $2, lease_owner = 'publisher:legacy', delivered_at = clock_timestamp() WHERE event_id = $1", &[&events[2], &old_token]).unwrap();
    inspect.batch_execute("CREATE ROLE bridge_publisher NOLOGIN;
        GRANT USAGE ON SCHEMA bpc_tsk_bridge TO bridge_publisher;
        GRANT SELECT ON ALL TABLES IN SCHEMA bpc_tsk_bridge TO bridge_publisher;
        GRANT UPDATE (lease_token, lease_owner, lease_until, attempts, delivered_at) ON bpc_tsk_bridge.audit_deliveries TO bridge_publisher;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA bpc_tsk_bridge TO bridge_publisher;
        ALTER DEFAULT PRIVILEGES IN SCHEMA bpc_tsk_bridge GRANT EXECUTE ON FUNCTIONS TO bridge_publisher;").unwrap();
    authority.migrate().unwrap();
    authority.migrate().unwrap();
    authority.check_schema().unwrap();
    let rows = inspect
        .query(
            "SELECT version, checksum FROM bpc_tsk_bridge.schema_migrations ORDER BY version",
            &[],
        )
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, Vec<u8>>("checksum"), checksum);
    assert_eq!(
        rows[1].get::<_, Vec<u8>>("checksum"),
        Sha256::digest(include_str!("../../../migrations/0002_delivery_state.sql").as_bytes())
            .to_vec()
    );
    let legacy = inspect.query_one("SELECT state, attempts, next_attempt_at >= lease_until + interval '1 second' AS delayed FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1", &[&events[0]]).unwrap();
    assert_eq!(legacy.get::<_, String>("state"), "pending");
    assert_eq!(legacy.get::<_, i64>("attempts"), 1);
    assert!(legacy.get::<_, bool>("delayed"));
    for (event, expected) in [(events[1], "attempt_limit"), (aged, "age_limit")] {
        let row = inspect.query_one("SELECT state, quarantine_reason, lease_token IS NULL AS fenced FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1", &[&event]).unwrap();
        assert_eq!(row.get::<_, String>("state"), "quarantined");
        assert_eq!(row.get::<_, String>("quarantine_reason"), expected);
        assert!(row.get::<_, bool>("fenced"));
    }
    assert!(
        authority
            .acknowledge_delivery(events[2], "publisher:legacy", old_token)
            .unwrap(),
        "legacy delivered acknowledgements remain idempotent"
    );
    inspect.batch_execute("SET ROLE bridge_publisher").unwrap();
    for sql in [
        "UPDATE bpc_tsk_bridge.audit_deliveries SET attempts = 0",
        "SELECT bpc_tsk_bridge.delivery_backoff(1)",
        "SELECT bpc_tsk_bridge.requeue_audit_delivery(gen_random_uuid(), gen_random_uuid(), 'actor', 'reviewed_recovery')",
    ] {
        assert_eq!(
            inspect.batch_execute(sql).unwrap_err().code(),
            Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE)
        );
    }
    assert!(inspect.query("SELECT * FROM bpc_tsk_bridge.claim_audit_deliveries('publisher:upgraded', 1, 1000)", &[]).unwrap().is_empty(), "legacy work must not become an immediate retry");
    inspect.batch_execute("RESET ROLE;
        ALTER DEFAULT PRIVILEGES IN SCHEMA bpc_tsk_bridge REVOKE EXECUTE ON FUNCTIONS FROM bridge_publisher;
        DROP OWNED BY bridge_publisher; DROP ROLE bridge_publisher;").unwrap();
}

#[test]
#[ignore = "requires explicit BPC_TSK_POSTGRES_TEST_URL and disposable local DB"]
fn delivery_fences_expire_during_row_lock_wait() {
    let config = explicit_test_config();
    let authority = local_authority(config.clone());
    authority.migrate().unwrap();
    let mut inspect = config.connect(NoTls).unwrap();
    let mut observer = config.connect(NoTls).unwrap();
    for fail in [false, true] {
        let event_id = new_delivery(&authority, &mut inspect);
        let event = claim_only(&authority, event_id);
        let application_name = format!("delivery_fence_wait_{}", Uuid::new_v4().simple());
        let mut worker_config = config.clone();
        worker_config.application_name(&application_name);
        let worker = local_authority(worker_config);
        // Owner-only acceleration gives a long setup lease a short known expiry.
        inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET lease_until = clock_timestamp() + interval '500 milliseconds' WHERE event_id = $1", &[&event_id]).unwrap();
        let mut blocker = inspect.transaction().unwrap();
        blocker.query_one("SELECT event_id FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1 FOR UPDATE", &[&event_id]).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            if fail {
                assert_eq!(
                    worker
                        .record_delivery_failure(
                            event_id,
                            "publisher:retry",
                            event.lease_token,
                            DeliveryFailureClass::Timeout,
                            Duration::from_secs(1)
                        )
                        .unwrap(),
                    None
                );
            } else {
                assert!(
                    !worker
                        .acknowledge_delivery(event_id, "publisher:retry", event.lease_token)
                        .unwrap()
                );
            }
        });
        ready_rx.recv().unwrap();
        let start = std::time::Instant::now();
        loop {
            let waiting: bool = observer
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity
                WHERE application_name = $1 AND wait_event_type = 'Lock')",
                    &[&application_name],
                )
                .unwrap()
                .get(0);
            if waiting {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_millis(200),
                "worker must reach the row lock before lease expiry"
            );
            thread::sleep(Duration::from_millis(1));
        }
        thread::sleep(Duration::from_millis(550));
        blocker.rollback().unwrap();
        waiter.join().unwrap();
        let row = inspect.query_one("SELECT state, last_failure_code IS NULL AS no_failure,
            delivered_at IS NULL AS no_ack FROM bpc_tsk_bridge.audit_deliveries WHERE event_id = $1", &[&event_id]).unwrap();
        assert_eq!(row.get::<_, String>("state"), "pending");
        assert!(row.get::<_, bool>("no_failure") && row.get::<_, bool>("no_ack"));
        // Leave no scheduled work for subsequent tests on this disposable queue.
        inspect.execute("UPDATE bpc_tsk_bridge.audit_deliveries SET lease_until = clock_timestamp() - interval '1 second',
            next_attempt_at = clock_timestamp() WHERE event_id = $1", &[&event_id]).unwrap();
        let recovered = claim_only(&authority, event_id);
        assert!(
            authority
                .acknowledge_delivery(event_id, "publisher:retry", recovered.lease_token)
                .unwrap()
        );
    }
}
