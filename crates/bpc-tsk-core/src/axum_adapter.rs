//! Axum admission middleware for protected BPC–TSK routes.
//!
//! Mount this middleware outside any body-decompression, URI-rewriting, retry,
//! or request-normalizing middleware. BPC signs the exact method, path/query,
//! and body bytes captured here. It intentionally returns one generic denial
//! shape and never delegates to BPC's standalone HTTP middleware.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use thiserror::Error;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    AuditSink, BindingStore, BpcGate, CombinedVerifier, ImmutableRequest, PublicDecision,
    RequestLimits, TskRequestVerifier,
};

const RESERVED_TSK_RESPONSE_HEADERS: [&str; 4] = [
    "x-tsk-authenticated",
    "x-tsk-rotation-required",
    "x-tsk-requests-remaining",
    "x-tsk-hotp-counters-remaining",
];

/// Default maximum number of concurrent blocking verification tasks per router state.
pub const DEFAULT_BLOCKING_ADMISSION_CAPACITY: usize = 64;

/// Largest accepted blocking verification capacity per router state.
pub const MAX_BLOCKING_ADMISSION_CAPACITY: usize = 1_024;

/// Rejection returned when blocking-admission configuration is unsafe.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BlockingAdmissionConfigError {
    /// The requested capacity is zero or exceeds the bounded maximum.
    #[error("blocking admission capacity must be within the documented nonzero maximum")]
    InvalidCapacity,
}

/// Shared state for [`bpc_tsk_admission`].
///
/// The verifier remains immutable for the lifetime of the Axum router. Its
/// authority dependencies, including BPC replay state and TSK state, must be
/// independently durable before this is used outside controlled testing.
pub struct BridgeAxumState<B, S, T, A> {
    verifier: Arc<CombinedVerifier<B, S, T, A>>,
    limits: RequestLimits,
    admission_permits: Arc<Semaphore>,
}

impl<B, S, T, A> Clone for BridgeAxumState<B, S, T, A> {
    fn clone(&self) -> Self {
        Self {
            verifier: Arc::clone(&self.verifier),
            limits: self.limits,
            admission_permits: Arc::clone(&self.admission_permits),
        }
    }
}

impl<B, S, T, A> BridgeAxumState<B, S, T, A> {
    /// Build protected-route state from a composition verifier and explicit
    /// admission limits.
    pub fn new(verifier: CombinedVerifier<B, S, T, A>, limits: RequestLimits) -> Self {
        Self {
            verifier: Arc::new(verifier),
            limits,
            admission_permits: Arc::new(Semaphore::new(DEFAULT_BLOCKING_ADMISSION_CAPACITY)),
        }
    }

    /// Build protected-route state with an explicit bounded blocking-admission
    /// capacity.
    ///
    /// This rejects zero and capacities larger than
    /// [`MAX_BLOCKING_ADMISSION_CAPACITY`], so an invalid configuration cannot
    /// create a router that might invoke the verifier.
    pub fn try_new(
        verifier: CombinedVerifier<B, S, T, A>,
        limits: RequestLimits,
        blocking_admission_capacity: usize,
    ) -> Result<Self, BlockingAdmissionConfigError> {
        if blocking_admission_capacity == 0
            || blocking_admission_capacity > MAX_BLOCKING_ADMISSION_CAPACITY
        {
            return Err(BlockingAdmissionConfigError::InvalidCapacity);
        }
        Ok(Self {
            verifier: Arc::new(verifier),
            limits,
            admission_permits: Arc::new(Semaphore::new(blocking_admission_capacity)),
        })
    }

    /// Returns the immutable composition verifier for router construction and
    /// protected observability wiring. Handlers should consume the snapshot in
    /// request extensions rather than calling it again.
    pub fn verifier(&self) -> &Arc<CombinedVerifier<B, S, T, A>> {
        &self.verifier
    }
}

/// BPC-first admission middleware for a protected Axum route.
///
/// The middleware captures all header values, reads the raw body within the
/// configured bound, and invokes the composition verifier before the next
/// handler. A successful handler receives a [`crate::CombinedAuthSnapshot`] in
/// request extensions. The TSK authenticated response headers are removed from
/// the handler response and replaced with the verified snapshot's values, so
/// they are emitted no more than once.
///
/// Factor/input denials receive the same empty `401` response with
/// `Cache-Control: no-store`, regardless of which factor or edge validation
/// failed. Blocking-capacity overload returns empty `503` with `Retry-After: 1`
/// before any factor work. Rate limiting, TLS termination, smuggling defenses, and
/// reverse-proxy header trust must be enforced by the surrounding deployment.
pub async fn bpc_tsk_admission<B, S, T, A>(
    State(state): State<BridgeAxumState<B, S, T, A>>,
    request: Request<Body>,
    next: Next,
) -> Response
where
    B: BpcGate + 'static,
    S: BindingStore + 'static,
    T: TskRequestVerifier + 'static,
    A: AuditSink + 'static,
{
    let (mut parts, body) = request.into_parts();
    let body = match to_bytes(body, state.limits.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => return generic_denial(),
    };
    let headers = match collect_headers(&parts.headers) {
        Ok(headers) => headers,
        Err(()) => return generic_denial(),
    };
    let path_and_query = parts.uri.path_and_query().map_or_else(
        || parts.uri.path().to_owned(),
        |value| value.as_str().to_owned(),
    );
    let captured = match ImmutableRequest::capture(
        Uuid::new_v4(),
        parts.method.as_str(),
        path_and_query,
        headers,
        body.clone().to_vec(),
        state.limits,
    ) {
        Ok(captured) => captured,
        Err(_) => return generic_denial(),
    };

    let permit = match Arc::clone(&state.admission_permits).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return resource_overload(),
    };
    let verifier = Arc::clone(&state.verifier);
    let decision = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verifier.verify(captured)
    })
    .await
    {
        Ok(decision) => decision,
        Err(_) => return generic_denial(),
    };
    let PublicDecision::Authorized(snapshot) = decision else {
        return generic_denial();
    };
    let authenticated_headers = match verified_tsk_response_headers(snapshot.tsk_response_headers())
    {
        Some(headers) => headers,
        None => return generic_denial(),
    };

    parts.extensions.insert(snapshot);
    let request = Request::from_parts(parts, Body::from(body));
    let mut response = next.run(request).await;
    install_verified_tsk_response_headers(response.headers_mut(), authenticated_headers);
    response
}

fn collect_headers(headers: &HeaderMap) -> Result<Vec<(String, String)>, ()> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = value.to_str().map_err(|_| ())?;
            Ok((name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn verified_tsk_response_headers(
    generated: &BTreeMap<String, String>,
) -> Option<Vec<(HeaderName, HeaderValue)>> {
    generated
        .iter()
        .map(|(name, value)| {
            if !RESERVED_TSK_RESPONSE_HEADERS.contains(&name.as_str()) {
                return None;
            }
            let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
            let value = HeaderValue::from_str(value).ok()?;
            Some((name, value))
        })
        .collect()
}

fn install_verified_tsk_response_headers(
    response_headers: &mut HeaderMap,
    authenticated_headers: Vec<(HeaderName, HeaderValue)>,
) {
    for name in RESERVED_TSK_RESPONSE_HEADERS {
        response_headers.remove(name);
    }
    for (name, value) in authenticated_headers {
        response_headers.insert(name, value);
    }
}

fn generic_denial() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

fn resource_overload() -> Response {
    let mut response = generic_denial();
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("1"));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{
        AuditContextKey, BpcGateError, BpcVerification, MemoryBindingStore, NoopAuditSink,
        TskVerifierError,
    };
    use axum::{Router, middleware, routing::post};
    use tower::ServiceExt;

    #[derive(Default)]
    struct CountingBpc {
        calls: Arc<AtomicUsize>,
    }

    impl BpcGate for CountingBpc {
        fn verify(&self, _request: &ImmutableRequest) -> Result<BpcVerification, BpcGateError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(BpcGateError)
        }

        fn recheck_current(&self, _verification: &BpcVerification) -> Result<bool, BpcGateError> {
            Err(BpcGateError)
        }
    }

    struct UnusedTsk;

    impl TskRequestVerifier for UnusedTsk {
        fn verify(
            &self,
            _request: &tsk_rust_protocol::RequestData,
        ) -> Result<tsk_rust_protocol::VerifyResult, TskVerifierError> {
            Err(TskVerifierError)
        }
    }

    struct PanicAudit;

    impl AuditSink for PanicAudit {
        fn record(&self, _record: crate::BridgeAuditRecord) -> Result<(), crate::AuditError> {
            panic!("test audit panic");
        }
    }

    fn admission_request() -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header("x-bpc-pair-id", "pair_test")
            .header("x-bpc-signature", "signature")
            .header("x-bpc-signed-data", "payload")
            .header("x-bpc-version", "1.0")
            .header("x-tsk-client-id", "tsk_client")
            .header("x-tsk-key", "key")
            .header("x-tsk-version", "1")
            .body(Body::empty())
            .unwrap()
    }

    fn denied_status(response: &Response) {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    #[test]
    fn explicit_blocking_capacity_rejects_zero_and_excessive_values() {
        let make_verifier = || {
            CombinedVerifier::new(
                CountingBpc::default(),
                MemoryBindingStore::default(),
                UnusedTsk,
                NoopAuditSink,
                AuditContextKey::new([1_u8; 32]),
            )
        };
        assert!(matches!(
            BridgeAxumState::try_new(make_verifier(), RequestLimits::default(), 0),
            Err(BlockingAdmissionConfigError::InvalidCapacity)
        ));
        assert!(matches!(
            BridgeAxumState::try_new(
                make_verifier(),
                RequestLimits::default(),
                MAX_BLOCKING_ADMISSION_CAPACITY + 1,
            ),
            Err(BlockingAdmissionConfigError::InvalidCapacity)
        ));
    }

    #[test]
    fn saturated_blocking_admission_returns_503_without_verifier_call() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let bpc = CountingBpc::default();
            let calls = Arc::clone(&bpc.calls);
            let state = BridgeAxumState::try_new(
                CombinedVerifier::new(
                    bpc,
                    MemoryBindingStore::default(),
                    UnusedTsk,
                    NoopAuditSink,
                    AuditContextKey::new([2_u8; 32]),
                ),
                RequestLimits::default(),
                1,
            )
            .unwrap();
            let permit = Arc::clone(&state.admission_permits)
                .try_acquire_owned()
                .unwrap();
            let app = Router::new()
                .route("/", post(|| async { StatusCode::NO_CONTENT }))
                .layer(middleware::from_fn_with_state(state, bpc_tsk_admission));

            let response = app.oneshot(admission_request()).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["retry-after"], "1");
            assert!(to_bytes(response.into_body(), 1).await.unwrap().is_empty());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "a saturated admission slot must not invoke the composition verifier",
            );
            drop(permit);
        });
    }

    #[test]
    fn blocking_task_panic_returns_generic_denial() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let state = BridgeAxumState::new(
                CombinedVerifier::new(
                    CountingBpc::default(),
                    MemoryBindingStore::default(),
                    UnusedTsk,
                    PanicAudit,
                    AuditContextKey::new([3_u8; 32]),
                ),
                RequestLimits::default(),
            );
            let app = Router::new()
                .route("/", post(|| async { StatusCode::NO_CONTENT }))
                .layer(middleware::from_fn_with_state(state, bpc_tsk_admission));

            let response = app.oneshot(admission_request()).await.unwrap();
            denied_status(&response);
        });
    }

    #[test]
    fn preserves_duplicate_header_values_for_composition_preflight() {
        let mut headers = HeaderMap::new();
        headers.append("x-tsk-client-id", HeaderValue::from_static("first"));
        headers.append("x-tsk-client-id", HeaderValue::from_static("second"));
        let captured = collect_headers(&headers).unwrap();
        assert_eq!(
            captured
                .iter()
                .filter(|(name, _)| name == "x-tsk-client-id")
                .count(),
            2
        );
    }

    #[test]
    fn verified_headers_replace_handler_control_header_values() {
        let generated = BTreeMap::from([
            ("x-tsk-authenticated".to_owned(), "1".to_owned()),
            ("x-tsk-rotation-required".to_owned(), "0".to_owned()),
        ]);
        let mut response_headers = HeaderMap::new();
        response_headers.append("x-tsk-authenticated", HeaderValue::from_static("0"));
        response_headers.append("x-tsk-authenticated", HeaderValue::from_static("1"));
        response_headers.insert("x-other", HeaderValue::from_static("preserved"));
        install_verified_tsk_response_headers(
            &mut response_headers,
            verified_tsk_response_headers(&generated).unwrap(),
        );
        assert_eq!(
            response_headers
                .get_all("x-tsk-authenticated")
                .iter()
                .count(),
            1
        );
        assert_eq!(response_headers["x-tsk-authenticated"], "1");
        assert_eq!(response_headers["x-tsk-rotation-required"], "0");
        assert_eq!(response_headers["x-other"], "preserved");
    }

    #[test]
    fn refuses_unrecognised_or_invalid_generated_response_headers() {
        let unexpected = BTreeMap::from([("x-not-a-tsk-header".to_owned(), "1".to_owned())]);
        assert!(verified_tsk_response_headers(&unexpected).is_none());
        let invalid_value =
            BTreeMap::from([("x-tsk-authenticated".to_owned(), "good\r\nbad".to_owned())]);
        assert!(verified_tsk_response_headers(&invalid_value).is_none());
    }
}
