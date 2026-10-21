//! Runnable production-candidate admission service for a separately authenticated TLS edge.
//! No provisioning, migrations, secret-map access, factor retries, or insecure constructors.

mod config;
mod http;
mod transport;

use std::{
    ffi::OsString,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bpc_tsk_core::{
    AuditContextKey, CombinedVerifier, ProtocolBpcGate, ProtocolTskVerifier,
    axum_adapter::BridgeAxumState,
    postgres_authority::{AuthorityLimits, PostgresAuthority},
};
use config::{Config, Secrets, postgres_config};

/// A static configuration field, never a driver error, path, value or secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceError(&'static str);

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ServiceError {}

fn unix_millis() -> Result<i64, ServiceError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError("tsk_verification_per_minute"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| ServiceError("tsk_verification_per_minute"))
}

fn construct(config: &Config, secrets: Secrets) -> Result<axum::Router, ServiceError> {
    let bounded_dsn = config::bounded_bpc_dsn(&secrets.bpc_dsn)?;
    let bpc = bpc_protocol::PostgresPairAuthority::connect_tls(
        &bounded_dsn,
        bpc_protocol::PostgresAuthorityConfig {
            schema: config.bpc.schema.clone(),
            ..Default::default()
        },
        bpc_protocol::PostgresTlsConfig {
            additional_root_certificates_pem: vec![secrets.bpc_ca],
        },
    )
    .map_err(|_| ServiceError("bpc.dsn_file"))?;
    let mut redis_config = bpc_protocol::GovernedRedisNonceConfig::new(
        &config.redis.namespace,
        &config.redis.epoch,
        config.redis.signature_window_ms,
    )
    .map_err(|_| ServiceError("redis.namespace"))?;
    redis_config.command_timeout = Duration::from_millis(config.redis.command_timeout_ms);
    let mut redis_tls = bpc_protocol::RedisTlsConfig::default()
        .with_system_roots(false)
        .with_additional_root_certificate_pem(secrets.redis_ca);
    if let (Some(cert), Some(key)) = (secrets.client_certificate, secrets.client_key) {
        redis_tls = redis_tls.with_client_auth_pem(cert, key.to_vec());
    }
    let nonces = bpc_protocol::GovernedRedisNonceStore::connect_tls_with_config(
        &secrets.redis_endpoint,
        redis_config,
        redis_tls,
    )
    .map_err(|_| ServiceError("redis.endpoint_file"))?;
    nonces
        .reconcile()
        .map_err(|_| ServiceError("redis.epoch"))?;
    let tsk = tsk_rust_protocol::PostgresTumblerStore::connect_tls(
        postgres_config(&secrets.tsk_dsn, "tsk.dsn_file")?,
        tsk_rust_protocol::PostgresStoreConfig {
            schema: config.tsk.schema.clone(),
            max_serialization_retries: 0,
            idle_in_transaction_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        tsk_rust_protocol::PostgresTlsConfig {
            use_system_roots: false,
            root_certificates_pem: vec![secrets.tsk_ca],
        },
    )
    .map_err(|_| ServiceError("tsk.dsn_file"))?;
    let tsk_limiter = Arc::new(
        tsk_rust_protocol::MemoryVerificationRateLimiter::new(
            config.tsk_verification_per_minute,
            unix_millis()?,
        )
        .map_err(|_| ServiceError("tsk_verification_per_minute"))?,
    );
    let authority = PostgresAuthority::connect_tls(
        postgres_config(&secrets.bridge_dsn, "bridge.dsn_file")?,
        &[secrets.bridge_ca_der],
        AuthorityLimits::default(),
    )
    .map_err(|_| ServiceError("bridge.dsn_file"))?;
    authority
        .check_schema()
        .map_err(|_| ServiceError("bridge.schema"))?;
    let state = BridgeAxumState::try_new(
        CombinedVerifier::new(
            ProtocolBpcGate::new(
                bpc_protocol::BpcVerifier::new(bpc_protocol::BpcVerifierConfig {
                    lockout_after: 0,
                    signature_window_ms: config.redis.signature_window_ms,
                }),
                bpc,
                nonces,
            ),
            authority.clone(),
            ProtocolTskVerifier::new(tsk, tsk_rust_protocol::TskServerConfig::default())
                .with_verification_rate_limiter(tsk_limiter),
            authority,
            AuditContextKey::new(*secrets.audit_key),
        ),
        config.request_limits(),
        config.blocking_admission,
    )
    .map_err(|_| ServiceError("blocking_admission"))?;
    Ok(http::protected_router(state))
}

/// Accept exactly `--config /absolute/path`, validate every file before sockets,
/// and run a bounded multi-thread Tokio runtime. No environment config fallback.
pub fn run_from_args(args: impl IntoIterator<Item = OsString>) -> Result<(), ServiceError> {
    let path = config::command(args)?;
    let (config, secrets) = Config::load(&path)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads)
        .max_blocking_threads(config.max_blocking_threads)
        .enable_all()
        .build()
        .map_err(|_| ServiceError("worker_threads"))?;
    let result = runtime.block_on(async move {
        let ready = Arc::new(http::Readiness::default());
        // Register both signals before authorities open sockets.
        let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).map_err(|_| ServiceError("listener"))?;
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|_| ServiceError("listener"))?;
        let signal_ready = Arc::clone(&ready);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
            signal_ready.shutdown();
            let _ = shutdown_tx.send(true);
        });
        let construction_config = config.clone();
        let protected = tokio::select! {
            result = tokio::time::timeout(
                Duration::from_millis(config.startup_timeout_ms),
                tokio::task::spawn_blocking(move || construct(&construction_config, secrets)),
            ) => result.map_err(|_| ServiceError("startup_timeout_ms"))?.map_err(|_| ServiceError("config"))??,
            _ = shutdown_rx.changed() => return Ok(()),
        };
        if !ready.complete() { return Ok(()); }
        let app = http::router(protected, Arc::clone(&ready), &config);
        transport::serve(app, &config, ready, shutdown_rx).await
    });
    // Started verification cannot be canceled/compensated or replayed. On drain
    // expiry, shutdown_timeout bounds waiting for the blocking executor itself.
    runtime.shutdown_timeout(Duration::ZERO);
    result
}
