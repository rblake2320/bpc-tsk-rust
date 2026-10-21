#![cfg(feature = "postgres-authority")]
//! Opt-in tests for disposable local PostgreSQL databases. Normal test runs
//! compile these tests but never connect. Ignored execution requires explicit
//! environment variables; none default to localhost or ambient PG* variables.

use std::{thread, time::Duration};

use bpc_tsk_core::{
    AuditPhase, BindingStore, BridgeAuditRecord, FailureClass,
    postgres_authority::{
        AuthorityError, AuthorityLimits, BindingReason, MutationContext, OutboxPayload,
        PostgresAuthority,
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
            "UPDATE bpc_tsk_bridge.schema_version SET version = 2 WHERE singleton",
            &[],
        )
        .unwrap();
    assert_eq!(
        authority.check_schema(),
        Err(AuthorityError::SchemaMismatch)
    );
    assert_eq!(authority.migrate(), Err(AuthorityError::SchemaMismatch));
    inspect
        .execute(
            "UPDATE bpc_tsk_bridge.schema_version SET version = 1 WHERE singleton",
            &[],
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
