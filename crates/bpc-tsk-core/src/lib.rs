//! BPC-first, TSK-second authorization composition.
//!
//! This crate composes independently verified BPC and TSK results. It never
//! derives, copies, or exposes their secret material. The public result is
//! either a generic denial with a correlation ID or an immutable authorization
//! snapshot. It is deliberately not a production-readiness claim: durable
//! authority deployment/fault validation and the full TSK HA authority remain
//! separate required deployment gates.

#![forbid(unsafe_code)]

/// Axum middleware that performs bounded byte-exact capture and generic
/// BPC-first/TSK-second route admission. Enable with `axum-adapter`.
#[cfg(feature = "axum-adapter")]
pub mod axum_adapter;

/// Revisioned PostgreSQL bindings and a secret-free transactional audit outbox.
/// Enable with `postgres-authority`; deployment review remains mandatory.
#[cfg(feature = "postgres-authority")]
pub mod postgres_authority;

use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
};

use bpc_protocol as bpc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use tsk_rust_protocol as tsk;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const BPC_HEADERS: [&str; 4] = [
    "x-bpc-pair-id",
    "x-bpc-signature",
    "x-bpc-signed-data",
    "x-bpc-version",
];
const TSK_HEADERS: [&str; 3] = ["x-tsk-client-id", "x-tsk-key", "x-tsk-version"];
const AUDIT_DOMAIN: &[u8] = b"bpc-tsk-audit-v1";

/// Limits applied when an HTTP adapter captures a request for composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    /// Maximum raw header fields before parsing or verification.
    pub max_header_count: usize,
    /// Maximum sum of raw header name and value bytes.
    pub max_header_bytes: usize,
    /// Maximum exact body bytes retained for BPC verification.
    pub max_body_bytes: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_header_count: 128,
            max_header_bytes: 32 * 1024,
            max_body_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Capture failures that are safe to turn into the bridge's generic public denial.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CaptureError {
    /// The method is empty or contains an HTTP control character.
    #[error("invalid method")]
    InvalidMethod,
    /// The raw target is not a control-character-free origin-form target.
    #[error("invalid path and query")]
    InvalidPathAndQuery,
    /// The adapter submitted a malformed header name or value.
    #[error("invalid header")]
    InvalidHeader,
    /// The request exceeded a configured capture bound.
    #[error("request exceeds configured bounds")]
    RequestTooLarge,
}

/// Immutable HTTP data captured exactly once before either factor is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableRequest {
    correlation_id: Uuid,
    method: String,
    path_and_query: String,
    headers: BTreeMap<String, Vec<String>>,
    body: Vec<u8>,
}

impl ImmutableRequest {
    /// Capture a bounded, multi-valued HTTP request snapshot.
    ///
    /// Header names are ASCII-lowercased for lookup only. Header values and the
    /// raw method, target, and body are retained unchanged. HTTP adapters must
    /// reject non-UTF-8 values before calling this API rather than lossy-decoding
    /// them.
    pub fn capture(
        correlation_id: Uuid,
        method: impl Into<String>,
        path_and_query: impl Into<String>,
        headers: impl IntoIterator<Item = (String, String)>,
        body: impl Into<Vec<u8>>,
        limits: RequestLimits,
    ) -> Result<Self, CaptureError> {
        let method = method.into();
        let path_and_query = path_and_query.into();
        let body = body.into();
        if method.is_empty() || !method.bytes().all(is_visible_http_byte) {
            return Err(CaptureError::InvalidMethod);
        }
        if !path_and_query.starts_with('/')
            || path_and_query.bytes().any(is_http_control)
            || path_and_query.contains('#')
        {
            return Err(CaptureError::InvalidPathAndQuery);
        }
        if body.len() > limits.max_body_bytes {
            return Err(CaptureError::RequestTooLarge);
        }
        let mut total_header_bytes = 0_usize;
        let mut captured = BTreeMap::<String, Vec<String>>::new();
        for (index, (name, value)) in headers.into_iter().enumerate() {
            if index >= limits.max_header_count {
                return Err(CaptureError::RequestTooLarge);
            }
            if name.is_empty()
                || !name.bytes().all(is_header_name_byte)
                || value.bytes().any(is_http_control)
            {
                return Err(CaptureError::InvalidHeader);
            }
            total_header_bytes = total_header_bytes
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or(CaptureError::RequestTooLarge)?;
            if total_header_bytes > limits.max_header_bytes {
                return Err(CaptureError::RequestTooLarge);
            }
            captured
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value);
        }
        Ok(Self {
            correlation_id,
            method,
            path_and_query,
            headers: captured,
            body,
        })
    }

    /// Correlates generic public failures with protected internal audit data.
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Exact method bytes after adapter UTF-8 validation.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Exact path and query bytes after adapter UTF-8 validation.
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    /// Exact raw body bytes signed by BPC.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Return one header value only when its cardinality is exactly one.
    pub fn exactly_one_header(&self, name: &str) -> Option<&str> {
        let values = self.headers.get(&name.to_ascii_lowercase())?;
        (values.len() == 1).then(|| values[0].as_str())
    }

    fn tsk_request_data(&self) -> tsk::RequestData {
        tsk::RequestData::from_headers(self.headers.iter().flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.clone(), value.clone()))
        }))
    }
}

fn is_visible_http_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_lowercase() || byte == b'-'
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_http_control(byte: u8) -> bool {
    byte == b'\r' || byte == b'\n' || byte == 0 || byte < 0x20 || byte == 0x7f
}

/// A BPC verification outcome accepted by the bridge only after its own facade
/// validates a fresh, closed-scope, concrete BPC pair identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpcVerification {
    pair_id: String,
    authorization_version: u64,
    verified_at_ms: u64,
    fresh_and_closed_scope: bool,
}

impl BpcVerification {
    /// Construct a verified BPC result in a BPC facade implementation.
    pub fn new(
        pair_id: impl Into<String>,
        authorization_version: u64,
        verified_at_ms: u64,
        fresh_and_closed_scope: bool,
    ) -> Self {
        Self {
            pair_id: pair_id.into(),
            authorization_version,
            verified_at_ms,
            fresh_and_closed_scope,
        }
    }

    /// Authenticated BPC pair identity.
    pub fn pair_id(&self) -> &str {
        &self.pair_id
    }

    /// BPC authorization version captured after the successful BPC claim.
    pub const fn authorization_version(&self) -> u64 {
        self.authorization_version
    }

    /// BPC verification timestamp.
    pub const fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    /// Whether the facade has established freshness and a closed authorization scope.
    pub const fn is_fresh_and_closed_scope(&self) -> bool {
        self.fresh_and_closed_scope
    }
}

/// Opaque BPC-facade failure. Its string representation is not public output.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("BPC verification unavailable or denied")]
pub struct BpcGateError;

/// Narrow BPC boundary. It provides no BPC private keys, HMAC material, or raw
/// signed payloads to the bridge application.
pub trait BpcGate: Send + Sync {
    /// Verify exact immutable request data and consume any BPC replay artifact.
    fn verify(&self, request: &ImmutableRequest) -> Result<BpcVerification, BpcGateError>;
    /// Recheck BPC authorization after TSK has been consumed. A false or error
    /// result is fail-closed and is never compensated by replay-state rollback.
    fn recheck_current(&self, verification: &BpcVerification) -> Result<bool, BpcGateError>;
}

/// Adapter for the pinned standalone BPC crate. It retains BPC stores in the
/// BPC domain and exposes only a narrow verified pair/fence result.
pub struct ProtocolBpcGate<R, N> {
    verifier: bpc::BpcVerifier,
    registry: R,
    nonce_store: N,
}

impl<R, N> ProtocolBpcGate<R, N> {
    /// Construct a BPC adapter from independently owned BPC stores.
    pub fn new(verifier: bpc::BpcVerifier, registry: R, nonce_store: N) -> Self {
        Self {
            verifier,
            registry,
            nonce_store,
        }
    }
}

impl<R, N> BpcGate for ProtocolBpcGate<R, N>
where
    R: bpc::PairRegistry + Send + Sync,
    N: bpc::NonceStore + Send + Sync,
{
    fn verify(&self, request: &ImmutableRequest) -> Result<BpcVerification, BpcGateError> {
        let pair_id = request
            .exactly_one_header("x-bpc-pair-id")
            .ok_or(BpcGateError)?;
        let signature = request
            .exactly_one_header("x-bpc-signature")
            .ok_or(BpcGateError)?;
        let signed_data = request
            .exactly_one_header("x-bpc-signed-data")
            .ok_or(BpcGateError)?;
        let version = request
            .exactly_one_header("x-bpc-version")
            .ok_or(BpcGateError)?;
        let result = self.verifier.verify(
            bpc::BpcRequest {
                pair_id,
                signature,
                signed_data,
                version,
                method: request.method(),
                path: request.path_and_query(),
                body: request.body(),
            },
            &self.registry,
            &self.nonce_store,
        );
        if !result.ok || result.error.is_some() || result.pair_id.as_deref() != Some(pair_id) {
            return Err(BpcGateError);
        }
        let snapshot = result.snapshot.ok_or(BpcGateError)?;
        if snapshot.pair_id != pair_id || snapshot.kind != bpc::PairKind::Legitimate {
            return Err(BpcGateError);
        }
        let pair = self
            .registry
            .get(pair_id)
            .map_err(|_| BpcGateError)?
            .ok_or(BpcGateError)?;
        if pair.status != bpc::PairStatus::Active {
            return Err(BpcGateError);
        }
        Ok(BpcVerification::new(
            pair_id,
            pair.authorization_version,
            snapshot.verified_at_ms,
            true,
        ))
    }

    fn recheck_current(&self, verification: &BpcVerification) -> Result<bool, BpcGateError> {
        let Some(pair) = self
            .registry
            .get(verification.pair_id())
            .map_err(|_| BpcGateError)?
        else {
            return Ok(false);
        };
        Ok(pair.status == bpc::PairStatus::Active
            && pair.authorization_version == verification.authorization_version())
    }
}

/// Snapshot of the server-controlled mapping between a verified BPC pair and a
/// TSK client/principal. It contains no factor secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingSnapshot {
    binding_id: Uuid,
    bpc_pair_id: String,
    tsk_client_id: String,
    principal_id: String,
    revision: u64,
}

impl BindingSnapshot {
    /// Stable binding identifier for protected audit records.
    pub const fn binding_id(&self) -> Uuid {
        self.binding_id
    }

    /// Authenticated BPC pair identity.
    pub fn bpc_pair_id(&self) -> &str {
        &self.bpc_pair_id
    }

    /// TSK credential identity mapped by trusted bridge control-plane policy.
    pub fn tsk_client_id(&self) -> &str {
        &self.tsk_client_id
    }

    /// Application principal selected by trusted bridge control-plane policy.
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Monotonic binding revision used for final authorization fencing.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Opaque binding-authority failure. It must deny rather than fall back to a
/// client assertion or cache.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("binding authority unavailable or denied")]
pub struct BindingStoreError;

/// Durable bridge binding boundary. Production implementations must use a
/// revisioned PostgreSQL authority; this trait intentionally excludes BPC and
/// TSK secret material.
pub trait BindingStore: Send + Sync {
    /// Resolve exactly one current active binding for an authenticated BPC pair.
    fn lookup_active(
        &self,
        bpc_pair_id: &str,
    ) -> Result<Option<BindingSnapshot>, BindingStoreError>;
    /// Recheck the exact binding revision after TSK verification and before an
    /// application side effect is admitted.
    fn recheck_active(&self, binding: &BindingSnapshot) -> Result<bool, BindingStoreError>;
}

#[derive(Debug, Clone)]
struct BindingRecord {
    snapshot: BindingSnapshot,
    active: bool,
}

/// Process-local binding store for unit tests and deliberate development only.
/// It is not a production authority and must never be used for clustered
/// deployments.
#[derive(Default)]
pub struct MemoryBindingStore {
    records: Mutex<BTreeMap<String, BindingRecord>>,
}

impl MemoryBindingStore {
    /// Create or replace an active binding through a trusted control-plane call.
    pub fn activate(
        &self,
        bpc_pair_id: impl Into<String>,
        tsk_client_id: impl Into<String>,
        principal_id: impl Into<String>,
    ) -> Result<BindingSnapshot, BindingStoreError> {
        let bpc_pair_id = bpc_pair_id.into();
        let tsk_client_id = tsk_client_id.into();
        let principal_id = principal_id.into();
        if !bpc::is_valid_pair_id(&bpc_pair_id)
            || !is_valid_identity(&tsk_client_id)
            || !is_valid_identity(&principal_id)
        {
            return Err(BindingStoreError);
        }
        let mut records = self.records.lock().map_err(|_| BindingStoreError)?;
        let revision = records
            .get(&bpc_pair_id)
            .map_or(1, |record| record.snapshot.revision.saturating_add(1));
        let snapshot = BindingSnapshot {
            binding_id: Uuid::new_v4(),
            bpc_pair_id: bpc_pair_id.clone(),
            tsk_client_id,
            principal_id,
            revision,
        };
        records.insert(
            bpc_pair_id,
            BindingRecord {
                snapshot: snapshot.clone(),
                active: true,
            },
        );
        Ok(snapshot)
    }

    /// Revoke an active binding only when its expected revision matches.
    pub fn revoke(
        &self,
        bpc_pair_id: &str,
        expected_revision: u64,
    ) -> Result<bool, BindingStoreError> {
        let mut records = self.records.lock().map_err(|_| BindingStoreError)?;
        let Some(record) = records.get_mut(bpc_pair_id) else {
            return Ok(false);
        };
        if !record.active || record.snapshot.revision != expected_revision {
            return Ok(false);
        }
        record.active = false;
        Ok(true)
    }
}

impl BindingStore for MemoryBindingStore {
    fn lookup_active(
        &self,
        bpc_pair_id: &str,
    ) -> Result<Option<BindingSnapshot>, BindingStoreError> {
        let records = self.records.lock().map_err(|_| BindingStoreError)?;
        Ok(records
            .get(bpc_pair_id)
            .filter(|record| record.active)
            .map(|record| record.snapshot.clone()))
    }

    fn recheck_active(&self, binding: &BindingSnapshot) -> Result<bool, BindingStoreError> {
        let records = self.records.lock().map_err(|_| BindingStoreError)?;
        let Some(current) = records.get(binding.bpc_pair_id()) else {
            return Ok(false);
        };
        Ok(current.active && current.snapshot == *binding)
    }
}

fn is_valid_identity(identity: &str) -> bool {
    !identity.is_empty()
        && identity.len() <= 128
        && identity.is_ascii()
        && !identity.bytes().any(is_http_control)
        && !matches!(identity, "__proto__" | "constructor" | "prototype")
}

/// Opaque TSK-adapter failure. Public callers receive generic denial rather
/// than store, lifecycle, or replay details.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("TSK verification unavailable")]
pub struct TskVerifierError;

/// Narrow TSK boundary. It accepts only the captured multi-value headers and
/// never gives the bridge access to a TSK shared secret.
pub trait TskRequestVerifier: Send + Sync {
    /// Verify and atomically consume TSK state when its authority accepts.
    fn verify(&self, request: &tsk::RequestData) -> Result<tsk::VerifyResult, TskVerifierError>;
}

/// Adapter for the pinned standalone TSK crate.
pub struct ProtocolTskVerifier<S> {
    store: S,
    config: tsk::TskServerConfig,
}

impl<S> ProtocolTskVerifier<S> {
    /// Construct a TSK adapter from an independently owned TSK authority.
    pub fn new(store: S, config: tsk::TskServerConfig) -> Self {
        Self { store, config }
    }
}

impl<S> TskRequestVerifier for ProtocolTskVerifier<S>
where
    S: tsk::TumblerStore,
{
    fn verify(&self, request: &tsk::RequestData) -> Result<tsk::VerifyResult, TskVerifierError> {
        tsk::verify_tsk_request(request, &self.store, self.config).map_err(|_| TskVerifierError)
    }
}

/// Redacted, domain-separated audit record. It has no raw headers, signatures,
/// request bodies, BPC key material, or TSK credential value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeAuditRecord {
    /// Correlation identifier shared with public generic failure responses.
    pub correlation_id: Uuid,
    /// A domain-separated HMAC over method/path/body only.
    pub request_context_digest: String,
    /// Lifecycle point for the audit record.
    pub phase: AuditPhase,
    /// Bounded internal classification; never send this to an untrusted caller.
    pub failure_class: Option<FailureClass>,
    /// Binding revision if a trusted binding was selected.
    pub binding_revision: Option<u64>,
}

/// Audit lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditPhase {
    /// Attempt was accepted for BPC verification.
    Attempt,
    /// Authorization completed successfully.
    Allowed,
    /// Authorization denied or became uncertain.
    Denied,
}

/// Bounded, secret-free protected telemetry classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Capture or header-cardinality policy rejected the request.
    Input,
    /// BPC returned a denial, malformed result, panic, or availability error.
    Bpc,
    /// No active binding matched the verified BPC pair.
    Binding,
    /// A request-supplied TSK identity differed from the durable binding.
    IdentityMismatch,
    /// TSK returned a denial or authority error.
    Tsk,
    /// A BPC/binding final fence changed after TSK consumption.
    FinalFence,
    /// Audit persistence was uncertain.
    Audit,
}

/// Audit persistence boundary. Production implementations must use a protected
/// transactional outbox and reconciliation; failures are fail-closed.
pub trait AuditSink: Send + Sync {
    /// Persist a secret-free record.
    fn record(&self, record: BridgeAuditRecord) -> Result<(), AuditError>;
}

/// Opaque protected-audit failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("audit persistence unavailable")]
pub struct AuditError;

/// No-op sink for tests and explicitly non-production local development.
#[derive(Debug, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _record: BridgeAuditRecord) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Independently managed key for audit-only request-context digests. It must
/// never be a BPC or TSK secret.
pub struct AuditContextKey([u8; 32]);

impl AuditContextKey {
    /// Construct an audit key from separately managed KMS/HSM material.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn digest(&self, request: &ImmutableRequest) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts fixed key length");
        write_length_delimited(&mut mac, AUDIT_DOMAIN);
        write_length_delimited(&mut mac, request.method().as_bytes());
        write_length_delimited(&mut mac, request.path_and_query().as_bytes());
        write_length_delimited(&mut mac, request.body());
        let bytes = mac.finalize().into_bytes();
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }
}

impl std::fmt::Debug for AuditContextKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditContextKey([REDACTED])")
    }
}

fn write_length_delimited(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

/// Generic public outcome. Denials intentionally expose no factor-specific
/// reason, state, or retry hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicDecision {
    /// Both factors and final fences succeeded.
    Authorized(CombinedAuthSnapshot),
    /// Request denied generically; use the correlation ID only with protected support/audit paths.
    Denied {
        /// Correlation identifier for protected support and audit lookup only.
        correlation_id: Uuid,
    },
}

impl PublicDecision {
    /// Correlation ID for either generic outcome.
    pub const fn correlation_id(&self) -> Uuid {
        match self {
            Self::Authorized(snapshot) => snapshot.correlation_id(),
            Self::Denied { correlation_id } => *correlation_id,
        }
    }
}

/// Immutable application-facing authorization result. Construction is private
/// to the coordinator, preventing handlers from forging factor success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedAuthSnapshot {
    principal_id: String,
    bpc_pair_id: String,
    tsk_client_id: String,
    binding_revision: u64,
    correlation_id: Uuid,
    tsk_response_headers: BTreeMap<String, String>,
}

impl CombinedAuthSnapshot {
    /// Server-controlled application principal.
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Verified BPC pair identity.
    pub fn bpc_pair_id(&self) -> &str {
        &self.bpc_pair_id
    }

    /// Exact durable TSK client identity.
    pub fn tsk_client_id(&self) -> &str {
        &self.tsk_client_id
    }

    /// Binding revision that passed the final authorization fence.
    pub const fn binding_revision(&self) -> u64 {
        self.binding_revision
    }

    /// Correlates the snapshot with protected audit records.
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Response headers to add exactly once after a successful protected request.
    pub fn tsk_response_headers(&self) -> &BTreeMap<String, String> {
        &self.tsk_response_headers
    }
}

/// HTTP-agnostic BPC-first composition coordinator.
pub struct CombinedVerifier<B, S, T, A> {
    bpc: B,
    bindings: S,
    tsk: T,
    audit: A,
    audit_key: AuditContextKey,
}

impl<B, S, T, A> CombinedVerifier<B, S, T, A>
where
    B: BpcGate,
    S: BindingStore,
    T: TskRequestVerifier,
    A: AuditSink,
{
    /// Construct a coordinator with independently owned factor and audit boundaries.
    pub fn new(bpc: B, bindings: S, tsk: T, audit: A, audit_key: AuditContextKey) -> Self {
        Self {
            bpc,
            bindings,
            tsk,
            audit,
            audit_key,
        }
    }

    /// Verify BPC before binding and TSK. Every denial is generic to callers;
    /// no BPC denial, panic, malformed result, stale result, duplicate header,
    /// or identity mismatch may invoke TSK lookup/validation/HOTP consumption.
    pub fn verify(&self, request: ImmutableRequest) -> PublicDecision {
        let digest = self.audit_key.digest(&request);
        if self
            .audit
            .record(BridgeAuditRecord {
                correlation_id: request.correlation_id(),
                request_context_digest: digest.clone(),
                phase: AuditPhase::Attempt,
                failure_class: None,
                binding_revision: None,
            })
            .is_err()
        {
            return PublicDecision::Denied {
                correlation_id: request.correlation_id(),
            };
        }

        if !preflight(&request) {
            return self.deny(&request, &digest, FailureClass::Input, None);
        }

        let bpc = match catch_unwind(AssertUnwindSafe(|| self.bpc.verify(&request))) {
            Ok(Ok(verification)) if verification.is_fresh_and_closed_scope() => verification,
            _ => return self.deny(&request, &digest, FailureClass::Bpc, None),
        };
        if request.exactly_one_header("x-bpc-pair-id") != Some(bpc.pair_id()) {
            return self.deny(&request, &digest, FailureClass::Bpc, None);
        }

        let binding = match self.bindings.lookup_active(bpc.pair_id()) {
            Ok(Some(binding)) if binding.bpc_pair_id() == bpc.pair_id() => binding,
            _ => return self.deny(&request, &digest, FailureClass::Binding, None),
        };
        let submitted_tsk_id = request
            .exactly_one_header("x-tsk-client-id")
            .expect("preflight established exactly one TSK client ID");
        if submitted_tsk_id.as_bytes() != binding.tsk_client_id().as_bytes() {
            return self.deny(
                &request,
                &digest,
                FailureClass::IdentityMismatch,
                Some(binding.revision()),
            );
        }

        let tsk_result = match self.tsk.verify(&request.tsk_request_data()) {
            Ok(result)
                if result.ok && result.client_id.as_deref() == Some(binding.tsk_client_id()) =>
            {
                result
            }
            _ => {
                return self.deny(
                    &request,
                    &digest,
                    FailureClass::Tsk,
                    Some(binding.revision()),
                );
            }
        };

        let bpc_still_current = catch_unwind(AssertUnwindSafe(|| self.bpc.recheck_current(&bpc)))
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        let binding_still_current = self.bindings.recheck_active(&binding).unwrap_or(false);
        if !bpc_still_current || !binding_still_current {
            return self.deny(
                &request,
                &digest,
                FailureClass::FinalFence,
                Some(binding.revision()),
            );
        }

        let snapshot = CombinedAuthSnapshot {
            principal_id: binding.principal_id().to_owned(),
            bpc_pair_id: binding.bpc_pair_id().to_owned(),
            tsk_client_id: binding.tsk_client_id().to_owned(),
            binding_revision: binding.revision(),
            correlation_id: request.correlation_id(),
            tsk_response_headers: tsk::build_tsk_response_headers(&tsk_result),
        };
        if self
            .audit
            .record(BridgeAuditRecord {
                correlation_id: request.correlation_id(),
                request_context_digest: digest,
                phase: AuditPhase::Allowed,
                failure_class: None,
                binding_revision: Some(binding.revision()),
            })
            .is_err()
        {
            return PublicDecision::Denied {
                correlation_id: request.correlation_id(),
            };
        }
        PublicDecision::Authorized(snapshot)
    }

    fn deny(
        &self,
        request: &ImmutableRequest,
        digest: &str,
        failure_class: FailureClass,
        binding_revision: Option<u64>,
    ) -> PublicDecision {
        let _ = self.audit.record(BridgeAuditRecord {
            correlation_id: request.correlation_id(),
            request_context_digest: digest.to_owned(),
            phase: AuditPhase::Denied,
            failure_class: Some(failure_class),
            binding_revision,
        });
        PublicDecision::Denied {
            correlation_id: request.correlation_id(),
        }
    }
}

fn preflight(request: &ImmutableRequest) -> bool {
    BPC_HEADERS.into_iter().chain(TSK_HEADERS).all(|header| {
        request
            .exactly_one_header(header)
            .is_some_and(|value| !value.is_empty())
    }) && request
        .exactly_one_header("x-tsk-client-id")
        .is_some_and(is_valid_identity)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct StubBpc {
        calls: AtomicUsize,
        succeed: AtomicBool,
        current: AtomicBool,
    }

    impl StubBpc {
        fn allowed() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                succeed: AtomicBool::new(true),
                current: AtomicBool::new(true),
            }
        }
    }

    impl BpcGate for StubBpc {
        fn verify(&self, request: &ImmutableRequest) -> Result<BpcVerification, BpcGateError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.succeed.load(Ordering::SeqCst) {
                return Err(BpcGateError);
            }
            Ok(BpcVerification::new(
                request.exactly_one_header("x-bpc-pair-id").unwrap(),
                1,
                1,
                true,
            ))
        }

        fn recheck_current(&self, _verification: &BpcVerification) -> Result<bool, BpcGateError> {
            Ok(self.current.load(Ordering::SeqCst))
        }
    }

    #[derive(Default)]
    struct CountingTsk {
        calls: AtomicUsize,
        succeed: AtomicBool,
    }

    impl CountingTsk {
        fn allowed() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                succeed: AtomicBool::new(true),
            }
        }
    }

    impl TskRequestVerifier for CountingTsk {
        fn verify(
            &self,
            _request: &tsk::RequestData,
        ) -> Result<tsk::VerifyResult, TskVerifierError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(tsk::VerifyResult {
                ok: self.succeed.load(Ordering::SeqCst),
                client_id: Some("tsk_client".to_owned()),
                error: None,
                rotation_required: false,
                requests_remaining: None,
                hotp_counters_remaining: None,
            })
        }
    }

    struct WrongClientTsk;

    impl TskRequestVerifier for WrongClientTsk {
        fn verify(
            &self,
            _request: &tsk::RequestData,
        ) -> Result<tsk::VerifyResult, TskVerifierError> {
            Ok(tsk::VerifyResult {
                ok: true,
                client_id: Some("different_client".to_owned()),
                error: None,
                rotation_required: false,
                requests_remaining: None,
                hotp_counters_remaining: None,
            })
        }
    }

    fn request(headers: impl IntoIterator<Item = (String, String)>) -> ImmutableRequest {
        ImmutableRequest::capture(
            Uuid::nil(),
            "POST",
            "/v1/protected?x=1",
            headers,
            b"{}".to_vec(),
            RequestLimits::default(),
        )
        .unwrap()
    }

    fn headers() -> Vec<(String, String)> {
        vec![
            ("X-BPC-Pair-ID".to_owned(), "pair_test".to_owned()),
            ("X-BPC-Signature".to_owned(), "signature".to_owned()),
            ("X-BPC-Signed-Data".to_owned(), "payload".to_owned()),
            ("X-BPC-Version".to_owned(), "1.0".to_owned()),
            ("X-TSK-Client-ID".to_owned(), "tsk_client".to_owned()),
            ("X-TSK-Key".to_owned(), "key".to_owned()),
            ("X-TSK-Version".to_owned(), "1".to_owned()),
        ]
    }

    fn verifier<'a>(
        bpc: &'a StubBpc,
        bindings: &'a MemoryBindingStore,
        tsk: &'a CountingTsk,
    ) -> CombinedVerifier<&'a StubBpc, &'a MemoryBindingStore, &'a CountingTsk, NoopAuditSink> {
        CombinedVerifier::new(
            bpc,
            bindings,
            tsk,
            NoopAuditSink,
            AuditContextKey::new([7_u8; 32]),
        )
    }

    impl BpcGate for &StubBpc {
        fn verify(&self, request: &ImmutableRequest) -> Result<BpcVerification, BpcGateError> {
            (*self).verify(request)
        }

        fn recheck_current(&self, verification: &BpcVerification) -> Result<bool, BpcGateError> {
            (*self).recheck_current(verification)
        }
    }

    impl BindingStore for &MemoryBindingStore {
        fn lookup_active(
            &self,
            bpc_pair_id: &str,
        ) -> Result<Option<BindingSnapshot>, BindingStoreError> {
            (*self).lookup_active(bpc_pair_id)
        }

        fn recheck_active(&self, binding: &BindingSnapshot) -> Result<bool, BindingStoreError> {
            (*self).recheck_active(binding)
        }
    }

    impl TskRequestVerifier for &CountingTsk {
        fn verify(
            &self,
            request: &tsk::RequestData,
        ) -> Result<tsk::VerifyResult, TskVerifierError> {
            (*self).verify(request)
        }
    }

    #[test]
    fn bpc_denial_never_touches_tsk() {
        let bpc = StubBpc::default();
        let bindings = MemoryBindingStore::default();
        bindings
            .activate("pair_test", "tsk_client", "principal")
            .unwrap();
        let tsk = CountingTsk::allowed();
        assert!(matches!(
            verifier(&bpc, &bindings, &tsk).verify(request(headers())),
            PublicDecision::Denied { .. }
        ));
        assert_eq!(bpc.calls.load(Ordering::SeqCst), 1);
        assert_eq!(tsk.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn duplicate_authentication_header_denies_before_bpc_or_tsk() {
        let bpc = StubBpc::allowed();
        let bindings = MemoryBindingStore::default();
        let tsk = CountingTsk::allowed();
        let mut duplicate = headers();
        duplicate.push(("x-tsk-client-id".to_owned(), "tsk_client".to_owned()));
        assert!(matches!(
            verifier(&bpc, &bindings, &tsk).verify(request(duplicate)),
            PublicDecision::Denied { .. }
        ));
        assert_eq!(bpc.calls.load(Ordering::SeqCst), 0);
        assert_eq!(tsk.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn binding_identity_mismatch_denies_before_tsk() {
        let bpc = StubBpc::allowed();
        let bindings = MemoryBindingStore::default();
        bindings
            .activate("pair_test", "different_client", "principal")
            .unwrap();
        let tsk = CountingTsk::allowed();
        assert!(matches!(
            verifier(&bpc, &bindings, &tsk).verify(request(headers())),
            PublicDecision::Denied { .. }
        ));
        assert_eq!(bpc.calls.load(Ordering::SeqCst), 1);
        assert_eq!(tsk.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn malformed_tsk_success_for_a_different_identity_is_denied() {
        let bpc = StubBpc::allowed();
        let bindings = MemoryBindingStore::default();
        bindings
            .activate("pair_test", "tsk_client", "principal")
            .unwrap();
        let bridge = CombinedVerifier::new(
            &bpc,
            &bindings,
            WrongClientTsk,
            NoopAuditSink,
            AuditContextKey::new([8_u8; 32]),
        );
        assert!(matches!(
            bridge.verify(request(headers())),
            PublicDecision::Denied { .. }
        ));
    }

    #[test]
    fn valid_bpc_binding_and_tsk_produce_one_snapshot_and_acknowledgement() {
        let bpc = StubBpc::allowed();
        let bindings = MemoryBindingStore::default();
        bindings
            .activate("pair_test", "tsk_client", "principal")
            .unwrap();
        let tsk = CountingTsk::allowed();
        let decision = verifier(&bpc, &bindings, &tsk).verify(request(headers()));
        let PublicDecision::Authorized(snapshot) = decision else {
            panic!("expected authorization");
        };
        assert_eq!(snapshot.principal_id(), "principal");
        assert_eq!(
            snapshot.tsk_response_headers().get("x-tsk-authenticated"),
            Some(&"1".to_owned())
        );
        assert_eq!(tsk.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn real_pinned_bpc_and_tsk_adapters_authorize_one_exact_request() {
        use bpc::{
            BpcKeyPair, BpcVerifier, MemoryNonceStore, MemoryPairRegistry, PairKind, PairMode,
            PairRecord, PairStatus, Scope, derive_request_hmac_key, sign_request,
        };
        use tsk::{
            InMemoryTumblerStore, MemoryStoreConfig, TskConfig, TskServerConfig, TumblerMapOptions,
            TumblerStore, generate_key_from_map, generate_tumbler_map,
        };

        const BPC_SECRET: &str = "ExampleSecret9!@";
        const BPC_PAIR_ID: &str = "pair_bridge";
        const TSK_NOW_MS: i64 = 1_750_000_000_000;

        let bpc_registry = MemoryPairRegistry::default();
        let bpc_key_pair = BpcKeyPair::generate().unwrap();
        bpc_registry
            .insert(PairRecord {
                id: BPC_PAIR_ID.to_owned(),
                name: "bridge test pair".to_owned(),
                scope: Scope::Admin,
                mode: PairMode::Development,
                request_hmac_key: derive_request_hmac_key(BPC_SECRET).unwrap(),
                public_jwk: bpc_key_pair.public_jwk().clone(),
                status: PairStatus::Active,
                created_at_ms: 0,
                expires_at_ms: None,
                max_requests: None,
                requests: 0,
                failed_signatures: 0,
                authorization_version: 1,
                kind: PairKind::Legitimate,
                canary_class: None,
            })
            .unwrap();
        let body = br#"{"operation":"transfer"}"#.to_vec();
        let (_, bpc_headers) = sign_request(
            bpc_key_pair.signing_key(),
            BPC_PAIR_ID,
            BPC_SECRET,
            "POST",
            "/v1/protected",
            &body,
        )
        .unwrap();

        let tsk_store = InMemoryTumblerStore::new(MemoryStoreConfig {
            max_entries: 100_000,
            max_age_ms: 0,
        })
        .unwrap();
        let tumbler_map = generate_tumbler_map(TumblerMapOptions::default(), TSK_NOW_MS).unwrap();
        let tsk_key = generate_key_from_map(&tumbler_map, TSK_NOW_MS).unwrap();
        tsk_store
            .set(&tumbler_map.client_id, tumbler_map.clone())
            .unwrap();

        let bindings = MemoryBindingStore::default();
        bindings
            .activate(BPC_PAIR_ID, &tumbler_map.client_id, "principal_bridge")
            .unwrap();
        let bridge = CombinedVerifier::new(
            ProtocolBpcGate::new(
                BpcVerifier::default(),
                bpc_registry,
                MemoryNonceStore::default(),
            ),
            bindings,
            ProtocolTskVerifier::new(
                tsk_store,
                TskServerConfig {
                    validation: TskConfig::default(),
                    now_ms: Some(TSK_NOW_MS),
                },
            ),
            NoopAuditSink,
            AuditContextKey::new([11_u8; 32]),
        );
        let request = ImmutableRequest::capture(
            Uuid::nil(),
            "POST",
            "/v1/protected",
            [
                ("x-bpc-pair-id".to_owned(), bpc_headers.pair_id),
                ("x-bpc-signature".to_owned(), bpc_headers.signature),
                ("x-bpc-signed-data".to_owned(), bpc_headers.signed_data),
                ("x-bpc-version".to_owned(), bpc_headers.version),
                ("x-tsk-client-id".to_owned(), tumbler_map.client_id.clone()),
                ("x-tsk-key".to_owned(), tsk_key),
                ("x-tsk-version".to_owned(), "1".to_owned()),
            ],
            body,
            RequestLimits::default(),
        )
        .unwrap();
        let PublicDecision::Authorized(snapshot) = bridge.verify(request) else {
            panic!("expected real standalone adapter authorization");
        };
        assert_eq!(snapshot.principal_id(), "principal_bridge");
        assert_eq!(snapshot.bpc_pair_id(), BPC_PAIR_ID);
        assert_eq!(snapshot.tsk_client_id(), tumbler_map.client_id);
        assert_eq!(
            snapshot.tsk_response_headers().get("x-tsk-authenticated"),
            Some(&"1".to_owned())
        );
    }

    #[test]
    fn final_bpc_or_binding_fence_denies_after_tsk_without_retry() {
        let bpc = StubBpc::allowed();
        bpc.current.store(false, Ordering::SeqCst);
        let bindings = MemoryBindingStore::default();
        bindings
            .activate("pair_test", "tsk_client", "principal")
            .unwrap();
        let tsk = CountingTsk::allowed();
        assert!(matches!(
            verifier(&bpc, &bindings, &tsk).verify(request(headers())),
            PublicDecision::Denied { .. }
        ));
        assert_eq!(tsk.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn request_context_digest_is_domain_separated_and_body_sensitive() {
        let headers = headers();
        let one = request(headers.clone());
        let two = ImmutableRequest::capture(
            Uuid::nil(),
            "POST",
            "/v1/protected?x=1",
            headers,
            b"{\"changed\":true}".to_vec(),
            RequestLimits::default(),
        )
        .unwrap();
        let key = AuditContextKey::new([9_u8; 32]);
        assert_ne!(key.digest(&one), key.digest(&two));
        assert!(!format!("{key:?}").contains('9'));
    }
}
