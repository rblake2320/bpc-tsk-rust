//! Durable bridge authority, enabled by `postgres-authority`.
//!
//! Use [`PostgresAuthority::connect_tls`] for certificate/hostname-verified
//! TLS 1.3. No production constructor uses `NoTls`. Migrations are explicit and
//! require a separate DDL-owning connection. This synchronous implementation
//! must run on a bounded blocking executor, not an async reactor thread.
//!
//! Binding mutations atomically commit state, immutable history and outbox
//! intent at SERIALIZABLE isolation. Unknown commits are never retried here.
//! A publisher claims renewable-by-reclaim leases and acknowledges only after
//! external durable acceptance; publication is at-least-once, not exactly-once.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};

use postgres::{
    Client, Config, IsolationLevel, Row, Transaction,
    config::{Host, SslMode},
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres_rustls::MakeRustlsConnect;
use uuid::Uuid;

use crate::{
    AuditError, AuditPhase, AuditSink, BindingSnapshot, BindingStore, BindingStoreError,
    BridgeAuditRecord, FailureClass,
};

const BOOTSTRAP: &str = include_str!("../../../migrations/0000_bootstrap.sql");
const MIGRATION_V1: &str = include_str!("../../../migrations/0001_authority.sql");
/// Schema version understood by this authority. Unknown/newer versions fail closed.
pub const SCHEMA_VERSION: i32 = 1;
const MIGRATION_LOCK: i64 = 0x4250_4354_534b_0001;
const MAX_BATCH: u32 = 100;
const MAX_LEASE: Duration = Duration::from_secs(300);
const AUDIT_COMMITMENT_DOMAIN: &[u8] = b"bpc-tsk-persisted-audit-commitment-v1\0";

/// Bounded database and local connection-contention limits; zero is forbidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityLimits {
    /// Server-side statement deadline (at most 60 seconds).
    pub statement_timeout: Duration,
    /// Server-side lock wait deadline, no larger than the statement deadline.
    pub lock_timeout: Duration,
    /// Server-side idle-in-transaction deadline (at most 60 seconds).
    pub idle_transaction_timeout: Duration,
    /// TCP connect deadline (at most 30 seconds).
    pub connect_timeout: Duration,
    /// Linux TCP unacknowledged-data deadline (at most 60 seconds).
    pub tcp_user_timeout: Duration,
    /// Maximum wait for this handle's synchronous connection mutex.
    pub connection_lock_timeout: Duration,
}

impl Default for AuthorityLimits {
    fn default() -> Self {
        Self {
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(1),
            idle_transaction_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            tcp_user_timeout: Duration::from_secs(10),
            connection_lock_timeout: Duration::from_secs(1),
        }
    }
}

impl AuthorityLimits {
    fn validate(self) -> Result<(), AuthorityError> {
        for (value, maximum) in [
            (self.statement_timeout, Duration::from_secs(60)),
            (self.lock_timeout, self.statement_timeout),
            (self.idle_transaction_timeout, Duration::from_secs(60)),
            (self.connect_timeout, Duration::from_secs(30)),
            (self.tcp_user_timeout, Duration::from_secs(60)),
            (self.connection_lock_timeout, Duration::from_secs(30)),
        ] {
            if value < Duration::from_millis(1) || value > maximum {
                return Err(AuthorityError::InvalidInput);
            }
        }
        Ok(())
    }
}

/// Sanitized operator-facing errors. No query text, identifiers, credentials,
/// server messages, raw payloads or authentication artifacts are retained.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    /// An identifier, revision, digest, timeout or lease was out of bounds.
    #[error("invalid authority input")]
    InvalidInput,
    /// The expected revision did not match the durable active/tombstone state.
    #[error("binding revision conflict")]
    RevisionConflict,
    /// An active TSK identity is already attached to another binding.
    #[error("active identity conflict")]
    IdentityConflict,
    /// An idempotency identifier was reused with a different operation/payload.
    #[error("authority operation conflict")]
    OperationConflict,
    /// Schema version/checksum does not match this binary.
    #[error("authority schema mismatch")]
    SchemaMismatch,
    /// Transaction aborted due to serialization failure or deadlock.
    #[error("authority transaction aborted")]
    SerializationFailure,
    /// A commit response was lost; reconcile the operation ID before retrying.
    #[error("authority commit outcome unknown")]
    CommitUnknown,
    /// Database, TLS, local contention, permission or decoding uncertainty.
    #[error("authority unavailable")]
    Unavailable,
}

/// Closed, secret-free reason codes; do not use free-form operator text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingReason {
    /// Initial policy-approved provisioning.
    Provision,
    /// Credential identity rotation.
    Rotation,
    /// Explicit revocation.
    Revocation,
    /// Privileged mapping-policy change.
    PolicyChange,
    /// Reviewed recovery operation.
    Recovery,
}

impl BindingReason {
    fn code(self) -> &'static str {
        match self {
            Self::Provision => "provision",
            Self::Rotation => "rotation",
            Self::Revocation => "revocation",
            Self::PolicyChange => "policy_change",
            Self::Recovery => "recovery",
        }
    }

    fn parse(code: &str) -> Result<Self, AuthorityError> {
        match code {
            "provision" => Ok(Self::Provision),
            "rotation" => Ok(Self::Rotation),
            "revocation" => Ok(Self::Revocation),
            "policy_change" => Ok(Self::PolicyChange),
            "recovery" => Ok(Self::Recovery),
            _ => Err(AuthorityError::Unavailable),
        }
    }
}

/// Trusted control-plane metadata, not an authentication mechanism.
/// Database credentials/roles and operator authorization must establish privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationContext {
    /// Stable, non-nil idempotency ID. Reuse only for the identical operation.
    pub operation_id: Uuid,
    /// Bounded privileged actor identity; no secrets or free-form annotations.
    pub actor_id: String,
    /// Closed, non-empty lifecycle reason.
    pub reason: BindingReason,
}

impl MutationContext {
    fn validate(&self) -> Result<(), AuthorityError> {
        if self.operation_id.is_nil() || !valid_identifier(&self.actor_id) {
            return Err(AuthorityError::InvalidInput);
        }
        Ok(())
    }
}

/// Immutable lifecycle result. Revocation advances the revision and preserves
/// a tombstone; reactivation cannot reuse an old authorization fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingChange {
    /// Durable mapping at the revision resulting from this operation.
    pub binding: BindingSnapshot,
    /// Whether the resulting mapping is active.
    pub active: bool,
    /// Revision supplied by the caller (zero means no prior binding).
    pub expected_revision: u64,
    /// Trusted actor, reason code and idempotency ID.
    pub context: MutationContext,
}

/// Persisted verification payload. This is a SHA-256 commitment to the core's
/// independent audit digest, NOT a stored BPC/TSK or audit HMAC value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationAuditEvent {
    /// Generic public/protected correlation identifier.
    pub correlation_id: Uuid,
    /// Fixed-length domain-separated commitment; no raw request data or HMAC.
    pub context_commitment: [u8; 32],
    /// Attempt, allowed, or denied lifecycle phase.
    pub phase: AuditPhase,
    /// Closed internal denial classification, never public response detail.
    pub failure_class: Option<FailureClass>,
    /// Trusted binding revision, when known.
    pub binding_revision: Option<u64>,
}

/// Closed outbox payload types. No arbitrary JSON, headers or secret blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxPayload {
    /// Secret-free bridge verification event.
    Verification(VerificationAuditEvent),
    /// Privileged binding lifecycle event.
    Binding(BindingChange),
}

/// An event claimed for a separate at-least-once publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedAuditEvent {
    /// Stable external deduplication identifier.
    pub event_id: Uuid,
    /// Unpredictable lease token; acknowledgements must match it and the owner.
    pub lease_token: Uuid,
    /// Database-clock lease expiry in Unix milliseconds.
    pub lease_expires_at_unix_ms: i64,
    /// Monotonic number of delivery claims, including this one.
    pub delivery_attempt: u64,
    /// Immutable, closed, secret-free event payload.
    pub payload: OutboxPayload,
}

struct Inner {
    client: Mutex<Client>,
    limits: AuthorityLimits,
}

/// Cloneable synchronous bridge authority implementing both [`BindingStore`]
/// and [`AuditSink`]. Clones share one bounded-contention connection. For role
/// separation use distinct connections/credentials, not just clones.
#[derive(Clone)]
pub struct PostgresAuthority {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for PostgresAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PostgresAuthority([REDACTED CONNECTION])")
    }
}

impl PostgresAuthority {
    /// Connect using TLS 1.3 with normal certificate-chain AND hostname/IP-SAN
    /// verification against explicitly supplied DER trust roots. Empty roots,
    /// Unix sockets, and multi-host configurations are rejected. Caller sslmode
    /// is overwritten with Require; downgrade/plaintext fallback is impossible.
    /// This constructor does not migrate or create database roles.
    pub fn connect_tls(
        mut config: Config,
        trusted_roots_der: &[Vec<u8>],
        limits: AuthorityLimits,
    ) -> Result<Self, AuthorityError> {
        validate_connection(&config, false)?;
        limits.validate()?;
        let tls = verified_tls_config(trusted_roots_der)?;
        configure_connection(&mut config, limits);
        config.ssl_mode(SslMode::Require);
        let client = config
            .connect(MakeRustlsConnect::new(tls))
            .map_err(database_error)?;
        Self::initialize(client, limits)
    }

    /// **INSECURE LOCAL TEST ONLY.** Explicitly disables TLS and accepts only
    /// localhost or literal loopback TCP addresses (including hostaddr). Never
    /// use this API for production, remote services or real credentials.
    /// This constructor does not implicitly migrate.
    pub fn connect_insecure_local_test(
        mut config: Config,
        limits: AuthorityLimits,
    ) -> Result<Self, AuthorityError> {
        validate_connection(&config, true)?;
        limits.validate()?;
        pin_local_test_address(&mut config);
        configure_connection(&mut config, limits);
        config.ssl_mode(SslMode::Disable);
        let client = config.connect(postgres::NoTls).map_err(database_error)?;
        Self::initialize(client, limits)
    }

    fn initialize(mut client: Client, limits: AuthorityLimits) -> Result<Self, AuthorityError> {
        client
            .query_one(
                "SELECT pg_catalog.set_config('statement_timeout', $1, false),
                pg_catalog.set_config('lock_timeout', $2, false),
                pg_catalog.set_config('idle_in_transaction_session_timeout', $3, false),
                pg_catalog.set_config('synchronous_commit', 'on', false),
                pg_catalog.set_config('search_path', 'pg_catalog', false)",
                &[
                    &milliseconds(limits.statement_timeout),
                    &milliseconds(limits.lock_timeout),
                    &milliseconds(limits.idle_transaction_timeout),
                ],
            )
            .map_err(database_error)?;
        Ok(Self {
            inner: Arc::new(Inner {
                client: Mutex::new(client),
                limits,
            }),
        })
    }

    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, AuthorityError> {
        let start = Instant::now();
        loop {
            match self.inner.client.try_lock() {
                Ok(client) => return Ok(client),
                Err(TryLockError::Poisoned(_)) => return Err(AuthorityError::Unavailable),
                Err(TryLockError::WouldBlock) => {
                    if start.elapsed() >= self.inner.limits.connection_lock_timeout {
                        return Err(AuthorityError::Unavailable);
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn transaction<T>(
        &self,
        read_only: bool,
        operation: impl FnOnce(&mut Transaction<'_>) -> Result<T, AuthorityError>,
    ) -> Result<T, AuthorityError> {
        let mut client = self.lock_client()?;
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(read_only)
            .start()
            .map_err(database_error)?;
        set_transaction_limits(&mut tx, self.inner.limits)?;
        verify_schema(&mut tx)?;
        let value = operation(&mut tx)?;
        tx.commit().map_err(commit_error)?;
        Ok(value)
    }

    /// Apply missing migrations under a transaction-scoped advisory lock.
    /// The entire version/history/schema change commits atomically; successful
    /// reapplication is a no-op. Unknown versions or changed SQL checksums fail
    /// closed. Use only a DDL-owning migrator connection, never verifier roles.
    /// On CommitUnknown, reconnect and run this method to reconcile metadata.
    pub fn migrate(&self) -> Result<(), AuthorityError> {
        let mut client = self.lock_client()?;
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        set_transaction_limits(&mut tx, self.inner.limits)?;
        tx.query_one(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&MIGRATION_LOCK],
        )
        .map_err(database_error)?;
        tx.batch_execute(BOOTSTRAP).map_err(database_error)?;
        let row = tx
            .query_one(
                "SELECT version FROM bpc_tsk_bridge.schema_version WHERE singleton FOR UPDATE",
                &[],
            )
            .map_err(database_error)?;
        let version: i32 = get(&row, "version")?;
        if version == 0 {
            let count: i64 = get(
                &tx.query_one(
                    "SELECT count(*) AS count FROM bpc_tsk_bridge.schema_migrations",
                    &[],
                )
                .map_err(database_error)?,
                "count",
            )?;
            if count != 0 {
                return Err(AuthorityError::SchemaMismatch);
            }
            tx.batch_execute(MIGRATION_V1).map_err(database_error)?;
            tx.execute(
                "INSERT INTO bpc_tsk_bridge.schema_migrations (version, checksum) VALUES ($1, $2)",
                &[&SCHEMA_VERSION, &migration_checksum()],
            )
            .map_err(database_error)?;
            tx.execute(
                "UPDATE bpc_tsk_bridge.schema_version SET version = $1 WHERE singleton AND version = 0",
                &[&SCHEMA_VERSION],
            ).map_err(database_error)?;
        }
        verify_schema(&mut tx)?;
        tx.commit().map_err(commit_error)
    }

    /// Check exact schema version/checksum in a read-only serializable transaction.
    /// This is a schema compatibility check, not a production-readiness claim.
    pub fn check_schema(&self) -> Result<(), AuthorityError> {
        self.transaction(true, |_| Ok(()))
    }

    /// Activate/create/replace a trusted mapping only at `expected_revision`.
    /// Zero requires absence; nonzero must match the active or revoked record.
    /// All successful transitions advance the revision; a stable operation ID
    /// returns its original result if and only if every input matches history.
    pub fn activate(
        &self,
        bpc_pair_id: &str,
        tsk_client_id: &str,
        principal_id: &str,
        expected_revision: u64,
        context: &MutationContext,
    ) -> Result<BindingChange, AuthorityError> {
        validate_pair(bpc_pair_id)?;
        if !valid_identifier(tsk_client_id) || !valid_identifier(principal_id) {
            return Err(AuthorityError::InvalidInput);
        }
        context.validate()?;
        let expected = revision_i64(expected_revision, true)?;
        let next = next_revision(expected_revision)?;
        self.transaction(false, |tx| {
            if let Some(prior) = history_by_operation(tx, context.operation_id)? {
                if same_operation(&prior, bpc_pair_id, expected_revision, true, context)
                    && prior.binding.tsk_client_id() == tsk_client_id
                    && prior.binding.principal_id() == principal_id
                {
                    return Ok(prior);
                }
                return Err(AuthorityError::OperationConflict);
            }
            let current = tx
                .query_opt(
                    "SELECT binding_id, bpc_pair_id, tsk_client_id, principal_id, revision, active
                 FROM bpc_tsk_bridge.principal_bindings WHERE bpc_pair_id = $1 FOR UPDATE",
                    &[&bpc_pair_id],
                )
                .map_err(database_error)?;
            let (binding_id, exists) = match current {
                Some(row) => {
                    let binding = binding_from_row(&row)?;
                    if binding.revision() != expected_revision {
                        return Err(AuthorityError::RevisionConflict);
                    }
                    (binding.binding_id(), true)
                }
                None if expected_revision == 0 => (Uuid::new_v4(), false),
                None => return Err(AuthorityError::RevisionConflict),
            };
            // The partial unique index is the final authority for TSK ownership.
            let mutation = if exists {
                tx.execute(
                    "UPDATE bpc_tsk_bridge.principal_bindings
                     SET tsk_client_id = $2, principal_id = $3, revision = $4,
                        active = true, changed_at = clock_timestamp()
                     WHERE bpc_pair_id = $1 AND revision = $5",
                    &[
                        &bpc_pair_id,
                        &tsk_client_id,
                        &principal_id,
                        &next,
                        &expected,
                    ],
                )
            } else {
                tx.execute(
                    "INSERT INTO bpc_tsk_bridge.principal_bindings
                    (binding_id, bpc_pair_id, tsk_client_id, principal_id, revision, active)
                 VALUES ($1, $2, $3, $4, $5, true)",
                    &[
                        &binding_id,
                        &bpc_pair_id,
                        &tsk_client_id,
                        &principal_id,
                        &next,
                    ],
                )
            };
            mutation
                .map_err(|error| {
                    if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                        match error
                            .as_db_error()
                            .and_then(postgres::error::DbError::constraint)
                        {
                            Some("one_active_pair_per_tsk_client") => {
                                AuthorityError::IdentityConflict
                            }
                            Some("principal_bindings_pkey") => AuthorityError::RevisionConflict,
                            _ => AuthorityError::Unavailable,
                        }
                    } else {
                        database_error(error)
                    }
                })
                .and_then(|rows| {
                    if rows == 1 {
                        Ok(())
                    } else {
                        Err(AuthorityError::RevisionConflict)
                    }
                })?;
            let change = BindingChange {
                binding: BindingSnapshot {
                    binding_id,
                    bpc_pair_id: bpc_pair_id.to_owned(),
                    tsk_client_id: tsk_client_id.to_owned(),
                    principal_id: principal_id.to_owned(),
                    revision: next as u64,
                },
                active: true,
                expected_revision,
                context: context.clone(),
            };
            append_binding_change(tx, &change)?;
            Ok(change)
        })
    }

    /// Revoke only an active mapping at the exact nonzero expected revision.
    /// Revocation advances the revision and leaves its tombstone/history intact.
    /// An identical operation ID is idempotent even after later reactivation.
    pub fn revoke(
        &self,
        bpc_pair_id: &str,
        expected_revision: u64,
        context: &MutationContext,
    ) -> Result<BindingChange, AuthorityError> {
        validate_pair(bpc_pair_id)?;
        context.validate()?;
        let expected = revision_i64(expected_revision, false)?;
        let next = next_revision(expected_revision)?;
        self.transaction(false, |tx| {
            if let Some(prior) = history_by_operation(tx, context.operation_id)? {
                return if same_operation(&prior, bpc_pair_id, expected_revision, false, context) {
                    Ok(prior)
                } else {
                    Err(AuthorityError::OperationConflict)
                };
            }
            let row = tx
                .query_opt(
                    "UPDATE bpc_tsk_bridge.principal_bindings
                 SET active = false, revision = $3, changed_at = clock_timestamp()
                 WHERE bpc_pair_id = $1 AND revision = $2 AND active
                 RETURNING binding_id, bpc_pair_id, tsk_client_id, principal_id, revision, active",
                    &[&bpc_pair_id, &expected, &next],
                )
                .map_err(database_error)?
                .ok_or(AuthorityError::RevisionConflict)?;
            let change = BindingChange {
                binding: binding_from_row(&row)?,
                active: false,
                expected_revision,
                context: context.clone(),
            };
            append_binding_change(tx, &change)?;
            Ok(change)
        })
    }

    /// Reconcile a lifecycle operation after an unknown commit, without changing
    /// authority or repeating BPC/TSK verification. Requires history read access.
    pub fn binding_change(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<BindingChange>, AuthorityError> {
        if operation_id.is_nil() {
            return Err(AuthorityError::InvalidInput);
        }
        self.transaction(true, |tx| history_by_operation(tx, operation_id))
    }

    /// Persist an audit phase and its outbox intent atomically. Repeating an
    /// identical correlation/phase is idempotent; changed payloads or competing
    /// final phases conflict. A final phase requires its matching prior attempt.
    /// HMAC digests are validated then irreversibly committed with SHA-256;
    /// neither the original digest nor any factor secret is stored.
    pub fn record_audit(&self, record: BridgeAuditRecord) -> Result<(), AuthorityError> {
        let event = verification_event(&record)?;
        let phase = phase_code(event.phase);
        let failure = event.failure_class.map(failure_code);
        let revision = event
            .binding_revision
            .map(|revision| revision_i64(revision, false))
            .transpose()?;
        let commitment = event.context_commitment.as_slice();
        self.transaction(false, |tx| {
            if event.phase == AuditPhase::Attempt {
                tx.execute(
                    "INSERT INTO bpc_tsk_bridge.verification_attempts (correlation_id, context_commitment)
                     VALUES ($1, $2) ON CONFLICT (correlation_id) DO NOTHING",
                    &[&event.correlation_id, &commitment],
                ).map_err(database_error)?;
            }
            let row = tx.query_opt(
                "SELECT context_commitment FROM bpc_tsk_bridge.verification_attempts WHERE correlation_id = $1",
                &[&event.correlation_id],
            ).map_err(database_error)?.ok_or(AuthorityError::OperationConflict)?;
            let stored: Vec<u8> = get(&row, "context_commitment")?;
            if stored != commitment { return Err(AuthorityError::OperationConflict); }
            tx.execute(
                "INSERT INTO bpc_tsk_bridge.audit_outbox
                    (event_id, event_kind, correlation_id, context_commitment, phase, failure_class, binding_revision)
                 VALUES ($1, 'verification', $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[&Uuid::new_v4(), &event.correlation_id, &commitment, &phase, &failure, &revision],
            ).map_err(database_error)?;
            let row = tx.query_opt(
                "SELECT correlation_id, context_commitment, phase, failure_class, binding_revision
                 FROM bpc_tsk_bridge.audit_outbox WHERE event_kind = 'verification' AND correlation_id = $1 AND phase = $2",
                &[&event.correlation_id, &phase],
            ).map_err(database_error)?.ok_or(AuthorityError::OperationConflict)?;
            if verification_from_row(&row)? != event { return Err(AuthorityError::OperationConflict); }
            Ok(())
        })
    }

    /// Claim at most 100 pending/expired events using SKIP LOCKED and the database
    /// clock. A fresh UUID lease token fences every claim batch. Unacknowledged
    /// events become claimable again after expiry; there is no implicit publish.
    /// A serialization error is an aborted claim, not permission to publish.
    pub fn claim_outbox(
        &self,
        worker_id: &str,
        batch_size: u32,
        lease: Duration,
    ) -> Result<Vec<ClaimedAuditEvent>, AuthorityError> {
        validate_claim(worker_id, batch_size, lease)?;
        let batch_size = i64::from(batch_size);
        let lease_ms = lease.as_millis() as i64;
        let lease_token = Uuid::new_v4();
        self.transaction(false, |tx| {
            let rows = tx.query(
                "WITH candidates AS (
                    SELECT d.event_id FROM bpc_tsk_bridge.audit_deliveries d
                    JOIN bpc_tsk_bridge.audit_outbox o USING (event_id)
                    WHERE d.delivered_at IS NULL AND (d.lease_until IS NULL OR d.lease_until <= clock_timestamp())
                    ORDER BY o.recorded_at, d.event_id FOR UPDATE OF d SKIP LOCKED LIMIT $1
                 ) UPDATE bpc_tsk_bridge.audit_deliveries d
                 SET lease_token = $2, lease_owner = $3,
                    lease_until = clock_timestamp() + ($4::bigint * interval '1 millisecond'), attempts = d.attempts + 1
                 FROM candidates c WHERE d.event_id = c.event_id
                 RETURNING d.event_id, d.attempts, floor(extract(epoch FROM d.lease_until) * 1000)::bigint AS expiry_ms",
                &[&batch_size, &lease_token, &worker_id, &lease_ms],
            ).map_err(database_error)?;
            let mut claimed = Vec::with_capacity(rows.len());
            for row in rows {
                let event_id = get(&row, "event_id")?;
                let attempts: i64 = get(&row, "attempts")?;
                let payload = outbox_payload(tx, event_id)?;
                claimed.push(ClaimedAuditEvent { event_id, lease_token,
                    lease_expires_at_unix_ms: get(&row, "expiry_ms")?,
                    delivery_attempt: u64::try_from(attempts).map_err(|_| AuthorityError::Unavailable)?, payload });
            }
            Ok(claimed)
        })
    }

    /// Acknowledge ONLY after external durable acceptance, using event ID for
    /// external deduplication. Wrong owner/token and expired/reclaimed leases
    /// return false. Repeating a successful acknowledgement with the same fence
    /// is idempotent. Payload/history is never rewritten or removed.
    pub fn acknowledge_delivery(
        &self,
        event_id: Uuid,
        worker_id: &str,
        lease_token: Uuid,
    ) -> Result<bool, AuthorityError> {
        if event_id.is_nil() || lease_token.is_nil() || !valid_identifier(worker_id) {
            return Err(AuthorityError::InvalidInput);
        }
        self.transaction(false, |tx| {
            let rows = tx
                .execute(
                    "UPDATE bpc_tsk_bridge.audit_deliveries
                 SET delivered_at = coalesce(delivered_at, clock_timestamp()), lease_until = NULL
                 WHERE event_id = $1 AND lease_owner = $2 AND lease_token = $3
                    AND (delivered_at IS NOT NULL OR lease_until > clock_timestamp())",
                    &[&event_id, &worker_id, &lease_token],
                )
                .map_err(database_error)?;
            Ok(rows == 1)
        })
    }

    fn lookup(&self, bpc_pair_id: &str) -> Result<Option<BindingSnapshot>, AuthorityError> {
        validate_pair(bpc_pair_id)?;
        self.transaction(true, |tx| {
            tx.query_opt(
                "SELECT binding_id, bpc_pair_id, tsk_client_id, principal_id, revision
                 FROM bpc_tsk_bridge.principal_bindings WHERE bpc_pair_id = $1 AND active",
                &[&bpc_pair_id],
            )
            .map_err(database_error)?
            .map(|row| binding_from_row(&row))
            .transpose()
        })
    }

    fn recheck(&self, binding: &BindingSnapshot) -> Result<bool, AuthorityError> {
        validate_pair(binding.bpc_pair_id())?;
        let revision = revision_i64(binding.revision(), false)?;
        if !valid_identifier(binding.tsk_client_id()) || !valid_identifier(binding.principal_id()) {
            return Err(AuthorityError::InvalidInput);
        }
        self.transaction(true, |tx| {
            let row = tx
                .query_opt(
                    "SELECT binding_id FROM bpc_tsk_bridge.principal_bindings
                 WHERE bpc_pair_id = $1 AND binding_id = $2 AND tsk_client_id = $3
                    AND principal_id = $4 AND revision = $5 AND active",
                    &[
                        &binding.bpc_pair_id(),
                        &binding.binding_id(),
                        &binding.tsk_client_id(),
                        &binding.principal_id(),
                        &revision,
                    ],
                )
                .map_err(database_error)?;
            Ok(row.is_some())
        })
    }
}

impl BindingStore for PostgresAuthority {
    fn lookup_active(
        &self,
        bpc_pair_id: &str,
    ) -> Result<Option<BindingSnapshot>, BindingStoreError> {
        self.lookup(bpc_pair_id).map_err(|_| BindingStoreError)
    }

    fn recheck_active(&self, binding: &BindingSnapshot) -> Result<bool, BindingStoreError> {
        self.recheck(binding).map_err(|_| BindingStoreError)
    }
}

impl AuditSink for PostgresAuthority {
    fn record(&self, record: BridgeAuditRecord) -> Result<(), AuditError> {
        self.record_audit(record).map_err(|_| AuditError)
    }
}

fn pin_local_test_address(config: &mut Config) {
    if config.get_hostaddrs().is_empty()
        && matches!(&config.get_hosts()[0], Host::Tcp(host) if host == "localhost")
    {
        config.hostaddr(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
}

fn configure_connection(config: &mut Config, limits: AuthorityLimits) {
    config
        .connect_timeout(limits.connect_timeout)
        .tcp_user_timeout(limits.tcp_user_timeout)
        .keepalives(true)
        .keepalives_idle(Duration::from_secs(10))
        .keepalives_interval(Duration::from_secs(5))
        .keepalives_retries(2);
}

fn validate_connection(config: &Config, insecure: bool) -> Result<(), AuthorityError> {
    if config.get_hosts().len() != 1
        || config.get_hostaddrs().len() > 1
        || config.get_ports().len() > 1
    {
        return Err(AuthorityError::InvalidInput);
    }
    let Host::Tcp(host) = &config.get_hosts()[0] else {
        return Err(AuthorityError::InvalidInput);
    };
    if host.is_empty() || host.len() > 253 || ServerName::try_from(host.as_str()).is_err() {
        return Err(AuthorityError::InvalidInput);
    }
    if insecure
        && ((host != "localhost" && !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
            || config.get_hostaddrs().iter().any(|ip| !ip.is_loopback()))
    {
        return Err(AuthorityError::InvalidInput);
    }
    Ok(())
}

fn verified_tls_config(certificates: &[Vec<u8>]) -> Result<ClientConfig, AuthorityError> {
    if certificates.is_empty() || certificates.len() > 64 {
        return Err(AuthorityError::InvalidInput);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        if certificate.is_empty() || certificate.len() > 64 * 1024 {
            return Err(AuthorityError::InvalidInput);
        }
        roots
            .add(CertificateDer::from(certificate.clone()))
            .map_err(|_| AuthorityError::InvalidInput)?;
    }
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| AuthorityError::Unavailable)
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

fn milliseconds(duration: Duration) -> String {
    format!("{}ms", duration.as_millis())
}

fn set_transaction_limits(
    tx: &mut Transaction<'_>,
    limits: AuthorityLimits,
) -> Result<(), AuthorityError> {
    tx.query_one(
        "SELECT pg_catalog.set_config('statement_timeout', $1, true),
            pg_catalog.set_config('lock_timeout', $2, true),
            pg_catalog.set_config('idle_in_transaction_session_timeout', $3, true),
            pg_catalog.set_config('synchronous_commit', 'on', true)",
        &[
            &milliseconds(limits.statement_timeout),
            &milliseconds(limits.lock_timeout),
            &milliseconds(limits.idle_transaction_timeout),
        ],
    )
    .map_err(database_error)?;
    Ok(())
}

fn migration_checksum() -> Vec<u8> {
    Sha256::digest(MIGRATION_V1.as_bytes()).to_vec()
}

fn verify_schema(tx: &mut Transaction<'_>) -> Result<(), AuthorityError> {
    let row = tx
        .query_opt(
            "SELECT version FROM bpc_tsk_bridge.schema_version WHERE singleton",
            &[],
        )
        .map_err(database_error)?
        .ok_or(AuthorityError::SchemaMismatch)?;
    let version: i32 = get(&row, "version")?;
    if version != SCHEMA_VERSION {
        return Err(AuthorityError::SchemaMismatch);
    }
    let rows = tx
        .query(
            "SELECT version, checksum FROM bpc_tsk_bridge.schema_migrations ORDER BY version",
            &[],
        )
        .map_err(database_error)?;
    if rows.len() != 1 {
        return Err(AuthorityError::SchemaMismatch);
    }
    let recorded_version: i32 = get(&rows[0], "version")?;
    let checksum: Vec<u8> = get(&rows[0], "checksum")?;
    if recorded_version != SCHEMA_VERSION || checksum != migration_checksum() {
        return Err(AuthorityError::SchemaMismatch);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@')
        })
        && !matches!(value, "__proto__" | "constructor" | "prototype")
}

fn validate_pair(pair: &str) -> Result<(), AuthorityError> {
    if bpc_protocol::is_valid_pair_id(pair) {
        Ok(())
    } else {
        Err(AuthorityError::InvalidInput)
    }
}

fn revision_i64(revision: u64, allow_zero: bool) -> Result<i64, AuthorityError> {
    if !allow_zero && revision == 0 {
        return Err(AuthorityError::InvalidInput);
    }
    i64::try_from(revision).map_err(|_| AuthorityError::InvalidInput)
}

fn next_revision(expected: u64) -> Result<i64, AuthorityError> {
    revision_i64(expected, true)?
        .checked_add(1)
        .ok_or(AuthorityError::InvalidInput)
}

fn validate_claim(worker: &str, batch: u32, lease: Duration) -> Result<(), AuthorityError> {
    if !valid_identifier(worker)
        || batch == 0
        || batch > MAX_BATCH
        || lease < Duration::from_millis(100)
        || lease > MAX_LEASE
    {
        return Err(AuthorityError::InvalidInput);
    }
    Ok(())
}

fn get<'a, T: postgres::types::FromSql<'a>>(
    row: &'a Row,
    column: &str,
) -> Result<T, AuthorityError> {
    row.try_get(column).map_err(|_| AuthorityError::Unavailable)
}

fn binding_from_row(row: &Row) -> Result<BindingSnapshot, AuthorityError> {
    let revision: i64 = get(row, "revision")?;
    let snapshot = BindingSnapshot {
        binding_id: get(row, "binding_id")?,
        bpc_pair_id: get(row, "bpc_pair_id")?,
        tsk_client_id: get(row, "tsk_client_id")?,
        principal_id: get(row, "principal_id")?,
        revision: u64::try_from(revision).map_err(|_| AuthorityError::Unavailable)?,
    };
    if snapshot.revision() == 0
        || snapshot.binding_id().is_nil()
        || validate_pair(snapshot.bpc_pair_id()).is_err()
        || !valid_identifier(snapshot.tsk_client_id())
        || !valid_identifier(snapshot.principal_id())
    {
        return Err(AuthorityError::Unavailable);
    }
    Ok(snapshot)
}

fn history_from_row(row: &Row) -> Result<BindingChange, AuthorityError> {
    let expected: i64 = get(row, "expected_revision")?;
    let change = BindingChange {
        binding: binding_from_row(row)?,
        active: get(row, "active")?,
        expected_revision: u64::try_from(expected).map_err(|_| AuthorityError::Unavailable)?,
        context: MutationContext {
            operation_id: get(row, "operation_id")?,
            actor_id: get(row, "actor_id")?,
            reason: BindingReason::parse(get(row, "reason_code")?)?,
        },
    };
    if change.context.validate().is_err()
        || change.expected_revision.checked_add(1) != Some(change.binding.revision())
    {
        return Err(AuthorityError::Unavailable);
    }
    Ok(change)
}

fn history_by_operation(
    tx: &mut Transaction<'_>,
    operation_id: Uuid,
) -> Result<Option<BindingChange>, AuthorityError> {
    tx.query_opt(
        "SELECT operation_id, binding_id, bpc_pair_id, tsk_client_id, principal_id,
            revision, expected_revision, active, actor_id, reason_code
         FROM bpc_tsk_bridge.binding_history WHERE operation_id = $1",
        &[&operation_id],
    )
    .map_err(database_error)?
    .map(|row| history_from_row(&row))
    .transpose()
}

fn same_operation(
    prior: &BindingChange,
    pair: &str,
    expected: u64,
    active: bool,
    context: &MutationContext,
) -> bool {
    prior.binding.bpc_pair_id() == pair
        && prior.expected_revision == expected
        && prior.active == active
        && prior.context == *context
}

fn append_binding_change(
    tx: &mut Transaction<'_>,
    change: &BindingChange,
) -> Result<(), AuthorityError> {
    let revision = revision_i64(change.binding.revision(), false)?;
    let expected = revision_i64(change.expected_revision, true)?;
    tx.execute(
        "INSERT INTO bpc_tsk_bridge.binding_history
            (operation_id, binding_id, bpc_pair_id, tsk_client_id, principal_id, revision,
                expected_revision, active, actor_id, reason_code)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &change.context.operation_id,
            &change.binding.binding_id(),
            &change.binding.bpc_pair_id(),
            &change.binding.tsk_client_id(),
            &change.binding.principal_id(),
            &revision,
            &expected,
            &change.active,
            &change.context.actor_id,
            &change.context.reason.code(),
        ],
    )
    .map_err(database_error)?;
    tx.execute(
        "INSERT INTO bpc_tsk_bridge.audit_outbox (event_id, event_kind, correlation_id, history_operation_id)
         VALUES ($1, 'binding', $1, $1)", &[&change.context.operation_id],
    ).map_err(database_error)?;
    Ok(())
}

fn phase_code(phase: AuditPhase) -> &'static str {
    match phase {
        AuditPhase::Attempt => "attempt",
        AuditPhase::Allowed => "allowed",
        AuditPhase::Denied => "denied",
    }
}

fn parse_phase(value: &str) -> Result<AuditPhase, AuthorityError> {
    match value {
        "attempt" => Ok(AuditPhase::Attempt),
        "allowed" => Ok(AuditPhase::Allowed),
        "denied" => Ok(AuditPhase::Denied),
        _ => Err(AuthorityError::Unavailable),
    }
}

fn failure_code(failure: FailureClass) -> &'static str {
    match failure {
        FailureClass::Input => "input",
        FailureClass::Bpc => "bpc",
        FailureClass::Binding => "binding",
        FailureClass::IdentityMismatch => "identity_mismatch",
        FailureClass::Tsk => "tsk",
        FailureClass::FinalFence => "final_fence",
        FailureClass::Audit => "audit",
    }
}

fn parse_failure(value: &str) -> Result<FailureClass, AuthorityError> {
    match value {
        "input" => Ok(FailureClass::Input),
        "bpc" => Ok(FailureClass::Bpc),
        "binding" => Ok(FailureClass::Binding),
        "identity_mismatch" => Ok(FailureClass::IdentityMismatch),
        "tsk" => Ok(FailureClass::Tsk),
        "final_fence" => Ok(FailureClass::FinalFence),
        "audit" => Ok(FailureClass::Audit),
        _ => Err(AuthorityError::Unavailable),
    }
}

fn verification_event(
    record: &BridgeAuditRecord,
) -> Result<VerificationAuditEvent, AuthorityError> {
    if record.request_context_digest.len() != 64
        || !record
            .request_context_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthorityError::InvalidInput);
    }
    if let Some(revision) = record.binding_revision {
        revision_i64(revision, false)?;
    }
    match record.phase {
        AuditPhase::Attempt
            if record.failure_class.is_some() || record.binding_revision.is_some() =>
        {
            return Err(AuthorityError::InvalidInput);
        }
        AuditPhase::Allowed
            if record.failure_class.is_some() || record.binding_revision.is_none() =>
        {
            return Err(AuthorityError::InvalidInput);
        }
        AuditPhase::Denied if record.failure_class.is_none() => {
            return Err(AuthorityError::InvalidInput);
        }
        _ => {}
    }
    let mut hash = Sha256::new();
    hash.update(AUDIT_COMMITMENT_DOMAIN);
    // Hash fixed, canonical hex bytes; never persist the incoming HMAC value.
    hash.update(record.request_context_digest.as_bytes());
    Ok(VerificationAuditEvent {
        correlation_id: record.correlation_id,
        context_commitment: hash.finalize().into(),
        phase: record.phase,
        failure_class: record.failure_class,
        binding_revision: record.binding_revision,
    })
}

fn verification_from_row(row: &Row) -> Result<VerificationAuditEvent, AuthorityError> {
    let commitment: Vec<u8> = get(row, "context_commitment")?;
    let revision: Option<i64> = get(row, "binding_revision")?;
    let failure: Option<&str> = get(row, "failure_class")?;
    Ok(VerificationAuditEvent {
        correlation_id: get(row, "correlation_id")?,
        context_commitment: commitment
            .try_into()
            .map_err(|_| AuthorityError::Unavailable)?,
        phase: parse_phase(get(row, "phase")?)?,
        failure_class: failure.map(parse_failure).transpose()?,
        binding_revision: revision
            .map(|revision| u64::try_from(revision).map_err(|_| AuthorityError::Unavailable))
            .transpose()?,
    })
}

fn outbox_payload(
    tx: &mut Transaction<'_>,
    event_id: Uuid,
) -> Result<OutboxPayload, AuthorityError> {
    let row = tx.query_one(
        "SELECT event_kind, correlation_id, context_commitment, phase, failure_class,
            binding_revision, history_operation_id FROM bpc_tsk_bridge.audit_outbox WHERE event_id = $1", &[&event_id],
    ).map_err(database_error)?;
    match get::<&str>(&row, "event_kind")? {
        "verification" => Ok(OutboxPayload::Verification(verification_from_row(&row)?)),
        "binding" => {
            let operation_id = get(&row, "history_operation_id")?;
            Ok(OutboxPayload::Binding(
                history_by_operation(tx, operation_id)?.ok_or(AuthorityError::Unavailable)?,
            ))
        }
        _ => Err(AuthorityError::Unavailable),
    }
}

fn database_error(error: postgres::Error) -> AuthorityError {
    match error.code() {
        Some(code)
            if *code == postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
                || *code == postgres::error::SqlState::T_R_DEADLOCK_DETECTED =>
        {
            AuthorityError::SerializationFailure
        }
        _ => AuthorityError::Unavailable,
    }
}

fn commit_error(error: postgres::Error) -> AuthorityError {
    if error.as_db_error().is_some() {
        database_error(error)
    } else {
        AuthorityError::CommitUnknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> MutationContext {
        MutationContext {
            operation_id: Uuid::new_v4(),
            actor_id: "operator:control-plane".into(),
            reason: BindingReason::Provision,
        }
    }

    fn attempt() -> BridgeAuditRecord {
        BridgeAuditRecord {
            correlation_id: Uuid::new_v4(),
            request_context_digest: "ab".repeat(32),
            phase: AuditPhase::Attempt,
            failure_class: None,
            binding_revision: None,
        }
    }

    #[test]
    fn limits_are_finite_and_zero_or_inverted_timeouts_are_rejected() {
        assert_eq!(AuthorityLimits::default().validate(), Ok(()));
        let invalid = AuthorityLimits {
            statement_timeout: Duration::ZERO,
            ..AuthorityLimits::default()
        };
        assert_eq!(invalid.validate(), Err(AuthorityError::InvalidInput));
        let invalid = AuthorityLimits {
            lock_timeout: Duration::from_secs(10),
            ..AuthorityLimits::default()
        };
        assert!(invalid.validate().is_err());
        let invalid = AuthorityLimits {
            connect_timeout: Duration::from_secs(31),
            ..AuthorityLimits::default()
        };
        assert!(invalid.validate().is_err());
        let invalid = AuthorityLimits {
            statement_timeout: Duration::from_nanos(1),
            ..AuthorityLimits::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn identifiers_and_revisions_are_bounded_and_never_saturate() {
        for identifier in [
            "",
            " bad",
            "bad\n",
            "bad' OR 1=1",
            "jwk:{}",
            "é",
            "__proto__",
            "constructor",
            "prototype",
        ] {
            assert!(!valid_identifier(identifier), "{identifier:?}");
        }
        assert!(valid_identifier(&"x".repeat(128)));
        assert!(!valid_identifier(&"x".repeat(129)));
        assert!(validate_pair(&"x".repeat(64)).is_ok());
        assert!(validate_pair(&"x".repeat(65)).is_err());
        assert_eq!(next_revision(0), Ok(1));
        assert_eq!(
            next_revision(i64::MAX as u64),
            Err(AuthorityError::InvalidInput)
        );
        assert_eq!(
            revision_i64(u64::MAX, true),
            Err(AuthorityError::InvalidInput)
        );
        assert_eq!(revision_i64(0, false), Err(AuthorityError::InvalidInput));
        let mut invalid = context();
        invalid.operation_id = Uuid::nil();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn only_explicit_loopback_test_connections_can_disable_tls() {
        for url in ["host=127.0.0.1", "host=::1", "host=localhost"] {
            let config: Config = url.parse().unwrap();
            assert!(validate_connection(&config, true).is_ok());
        }
        for url in [
            "host=db.example.com",
            "host=192.0.2.1",
            "host=localhost hostaddr=192.0.2.1",
            "host=localhost,remote.example.com",
            "host=/tmp",
            "user=test",
        ] {
            let config: Config = url.parse().unwrap();
            assert!(validate_connection(&config, true).is_err(), "{url}");
        }
        let config: Config = "host=db.example.com sslmode=disable".parse().unwrap();
        assert!(validate_connection(&config, false).is_ok());
        assert_eq!(
            PostgresAuthority::connect_tls(config, &[], AuthorityLimits::default()).unwrap_err(),
            AuthorityError::InvalidInput
        );
        assert!(verified_tls_config(&[vec![1, 2, 3]]).is_err());
        let config: Config = "host=192.0.2.1".parse().unwrap();
        assert_eq!(
            PostgresAuthority::connect_insecure_local_test(config, AuthorityLimits::default())
                .unwrap_err(),
            AuthorityError::InvalidInput
        );
    }

    #[test]
    fn audit_payload_is_a_fixed_commitment_not_a_persisted_hmac_or_arbitrary_blob() {
        let record = attempt();
        let event = verification_event(&record).unwrap();
        assert_eq!(event, verification_event(&record).unwrap());
        assert_ne!(event.context_commitment.as_slice(), &[0xab; 32]);
        let mut changed = record.clone();
        changed.request_context_digest = "cd".repeat(32);
        assert_ne!(
            event.context_commitment,
            verification_event(&changed).unwrap().context_commitment
        );
        for digest in [
            "body",
            "JWK",
            "TSK-KEY",
            "",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(65),
        ] {
            let mut invalid = record.clone();
            invalid.request_context_digest = digest.into();
            assert_eq!(
                verification_event(&invalid),
                Err(AuthorityError::InvalidInput)
            );
        }
        assert!(!format!("{event:?}").contains(&record.request_context_digest));
    }

    #[test]
    fn audit_phase_shapes_and_closed_codes_are_validated() {
        let mut record = attempt();
        record.phase = AuditPhase::Allowed;
        assert!(verification_event(&record).is_err());
        record.binding_revision = Some(1);
        assert!(verification_event(&record).is_ok());
        record.failure_class = Some(FailureClass::Bpc);
        assert!(verification_event(&record).is_err());
        record.phase = AuditPhase::Denied;
        assert!(verification_event(&record).is_ok());
        record.failure_class = None;
        assert!(verification_event(&record).is_err());
        assert!(parse_phase("key").is_err());
        assert!(parse_failure("raw body").is_err());
        assert!(BindingReason::parse("secret reason").is_err());
        for phase in [AuditPhase::Attempt, AuditPhase::Allowed, AuditPhase::Denied] {
            assert_eq!(parse_phase(phase_code(phase)), Ok(phase));
        }
        for failure in [
            FailureClass::Input,
            FailureClass::Bpc,
            FailureClass::Binding,
            FailureClass::IdentityMismatch,
            FailureClass::Tsk,
            FailureClass::FinalFence,
            FailureClass::Audit,
        ] {
            assert_eq!(parse_failure(failure_code(failure)), Ok(failure));
        }
    }

    #[test]
    fn idempotency_matches_all_control_plane_metadata_and_action() {
        let context = context();
        let change = BindingChange {
            binding: BindingSnapshot {
                binding_id: Uuid::new_v4(),
                bpc_pair_id: "pair_test".into(),
                tsk_client_id: "tsk_test".into(),
                principal_id: "principal_test".into(),
                revision: 1,
            },
            active: true,
            expected_revision: 0,
            context: context.clone(),
        };
        assert!(same_operation(&change, "pair_test", 0, true, &context));
        assert!(!same_operation(&change, "pair_other", 0, true, &context));
        assert!(!same_operation(&change, "pair_test", 1, true, &context));
        assert!(!same_operation(&change, "pair_test", 0, false, &context));
        let mut changed = context.clone();
        changed.actor_id = "another_actor".into();
        assert!(!same_operation(&change, "pair_test", 0, true, &changed));
        changed = context.clone();
        changed.reason = BindingReason::Recovery;
        assert!(!same_operation(&change, "pair_test", 0, true, &changed));
    }

    #[test]
    fn claims_are_bounded_and_require_a_valid_worker() {
        assert!(validate_claim("publisher:1", 100, MAX_LEASE).is_ok());
        for batch in [0, 101, u32::MAX] {
            assert!(validate_claim("worker", batch, Duration::from_secs(1)).is_err());
        }
        for lease in [
            Duration::ZERO,
            Duration::from_millis(99),
            Duration::from_secs(301),
        ] {
            assert!(validate_claim("worker", 1, lease).is_err());
        }
        assert!(validate_claim("secret\nworker", 1, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn schema_has_version_fences_append_only_payloads_and_no_secret_columns() {
        assert!(BOOTSTRAP.contains("schema_version"));
        assert!(BOOTSTRAP.contains("schema_migrations"));
        assert_eq!(migration_checksum().len(), 32);
        for required in [
            "binding_history",
            "verification_attempts",
            "audit_outbox",
            "audit_deliveries",
            "DEFERRABLE INITIALLY DEFERRED",
            "BEFORE TRUNCATE",
            "one_active_pair_per_tsk_client",
            "one_verification_final_per_correlation",
            "SET search_path = pg_catalog",
        ] {
            assert!(MIGRATION_V1.contains(required));
        }
        for forbidden in [
            "request_context_digest",
            "signature",
            "jwk",
            "hmac",
            "shared_secret",
            "request_body",
            "tsk_key",
        ] {
            assert!(!MIGRATION_V1.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn authority_implements_both_send_sync_boundaries() {
        fn assert_traits<T: BindingStore + AuditSink + Send + Sync + Clone>() {}
        assert_traits::<PostgresAuthority>();
    }

    #[test]
    fn insecure_localhost_is_pinned_to_loopback_without_dns() {
        let mut config: Config = "host=localhost".parse().unwrap();
        validate_connection(&config, true).unwrap();
        pin_local_test_address(&mut config);
        assert_eq!(
            config.get_hostaddrs(),
            &[IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
        );
        let mut explicit: Config = "host=localhost hostaddr=::1".parse().unwrap();
        validate_connection(&explicit, true).unwrap();
        pin_local_test_address(&mut explicit);
        assert_eq!(
            explicit.get_hostaddrs(),
            &[IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]
        );
    }
}
