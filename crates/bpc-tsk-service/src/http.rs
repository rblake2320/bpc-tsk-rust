use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use axum::{
    Extension, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use bpc_tsk_core::{
    AuditSink, BindingStore, BpcGate, CombinedAuthSnapshot, RequestLimits, TskRequestVerifier,
    axum_adapter::{BridgeAxumState, bpc_tsk_admission},
};
use http_body_util::BodyExt;
use tokio::{sync::Semaphore, time::Instant};

use crate::config::Config;

#[derive(Default)]
pub(crate) struct Readiness(AtomicU8);
impl Readiness {
    pub fn complete(&self) -> bool {
        self.0
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    pub fn shutdown(&self) {
        self.0.store(2, Ordering::Release);
    }
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire) == 1
    }
}

impl Config {
    pub(crate) fn request_limits(&self) -> RequestLimits {
        RequestLimits {
            max_header_count: self.max_header_count,
            max_header_bytes: self.max_header_bytes,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

pub(crate) fn protected_router<B, S, T, A>(state: BridgeAxumState<B, S, T, A>) -> Router
where
    B: BpcGate + 'static,
    S: BindingStore + 'static,
    T: TskRequestVerifier + 'static,
    A: AuditSink + 'static,
{
    Router::new()
        .route("/v1/protected", post(protected))
        .route_layer(middleware::from_fn_with_state(state, bpc_tsk_admission))
}

async fn protected(Extension(_snapshot): Extension<CombinedAuthSnapshot>) -> StatusCode {
    // Merely consume the unforgeable snapshot: no principal output or factor rerun.
    StatusCode::NO_CONTENT
}

#[derive(Clone)]
struct Edge {
    config: Config,
    ready: Arc<Readiness>,
    blocking: Arc<Semaphore>,
}

#[derive(Clone, Copy)]
pub(crate) struct Deadline(pub Instant);

pub(crate) fn router(protected: Router, ready: Arc<Readiness>, config: &Config) -> Router {
    let health = Router::new()
        .route("/livez", get(|| async { empty(StatusCode::NO_CONTENT) }))
        .route(
            "/readyz",
            get({
                let ready = Arc::clone(&ready);
                move || {
                    let ready = Arc::clone(&ready);
                    async move {
                        empty(if ready.is_ready() {
                            StatusCode::NO_CONTENT
                        } else {
                            StatusCode::SERVICE_UNAVAILABLE
                        })
                    }
                }
            }),
        );
    protected
        .merge(health)
        .fallback(|| async { empty(StatusCode::NOT_FOUND) })
        .method_not_allowed_fallback(|| async { empty(StatusCode::METHOD_NOT_ALLOWED) })
        .layer(middleware::from_fn_with_state(
            Edge {
                config: config.clone(),
                ready,
                blocking: Arc::new(Semaphore::new(config.blocking_admission)),
            },
            buffered_edge,
        ))
        .layer(middleware::from_fn(security))
}

pub(crate) const SECURITY_HEADERS: [(&str, &str); 6] = [
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    (
        "content-security-policy",
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox",
    ),
    ("x-frame-options", "DENY"),
    (
        "permissions-policy",
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), fullscreen=()",
    ),
];

fn install_security(response: &mut Response) {
    for (name, value) in SECURITY_HEADERS {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response.headers_mut().remove("server");
}

async fn security(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    install_security(&mut response);
    response
}

pub(crate) fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    install_security(&mut response);
    response
}

pub(crate) fn overload() -> Response {
    let mut response = empty(StatusCode::SERVICE_UNAVAILABLE);
    response
        .headers_mut()
        .insert("retry-after", HeaderValue::from_static("1"));
    response
}

pub(crate) fn validate_head(
    method: &str,
    target: &str,
    headers: &HeaderMap,
    config: &Config,
) -> Result<(), StatusCode> {
    let bad = StatusCode::BAD_REQUEST;
    if method.is_empty()
        || method.len() > config.max_method_bytes
        || !method.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
        || !target.starts_with('/')
        || target.contains('#')
        || target.bytes().any(|b| b < 0x20 || b == 0x7f)
        || headers.len() > config.max_header_count
    {
        return Err(bad);
    }
    let mut bytes = 0usize;
    for (name, value) in headers {
        if name == "forwarded" || name.as_str().starts_with("x-forwarded-") {
            return Err(bad);
        }
        let value = value.to_str().map_err(|_| bad)?;
        if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(bad);
        }
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|b| b.checked_add(value.len()))
            .ok_or(bad)?;
        if bytes > config.max_header_bytes {
            return Err(bad);
        }
    }
    let count = |name| headers.get_all(name).iter().count();
    if count("host") > 1
        || count("content-length") > 1
        || count("transfer-encoding") > 1
        || headers.contains_key("trailer")
        || headers.contains_key("expect")
        || (headers.contains_key("content-length") && headers.contains_key("transfer-encoding"))
    {
        return Err(bad);
    }
    if let Some(host) = headers.get("host") {
        let host = host.to_str().map_err(|_| bad)?;
        if host.is_empty()
            || host.contains('@')
            || host.parse::<axum::http::uri::Authority>().is_err()
        {
            return Err(bad);
        }
    }
    if let Some(value) = headers.get("transfer-encoding") {
        if !value.as_bytes().eq_ignore_ascii_case(b"chunked") {
            return Err(bad);
        }
    }
    if let Some(value) = headers.get("content-length") {
        let value = value.to_str().map_err(|_| bad)?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad);
        }
        let size = value.parse::<u64>().map_err(|_| bad)?;
        if size > config.max_body_bytes as u64 {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    Ok(())
}

async fn buffered_edge(State(edge): State<Edge>, request: Request<Body>, next: Next) -> Response {
    let target = request.uri().path_and_query().map_or("", |v| v.as_str());
    if let Err(status) = validate_head(
        request.method().as_str(),
        target,
        request.headers(),
        &edge.config,
    ) {
        return empty(status);
    }
    // A separate gate outside the raw adapter makes overload distinguishable
    // without translating any factor denial. It remains held through verification.
    let protected = request.uri().path() == "/v1/protected"
        || request
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .is_some_and(|path| path.as_str() == "/v1/protected");
    let _permit = if protected {
        if !edge.ready.is_ready() {
            return overload();
        }
        match Arc::clone(&edge.blocking).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return overload(),
        }
    } else {
        None
    };
    let deadline = request
        .extensions()
        .get::<Deadline>()
        .copied()
        .unwrap_or(Deadline(
            Instant::now() + Duration::from_millis(edge.config.request_timeout_ms),
        ));
    let (parts, mut body) = request.into_parts();
    let maximum = edge.config.max_body_bytes;
    let buffered = tokio::time::timeout_at(deadline.0, async {
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
            // Trailers are not in the signed header snapshot; reject even if undeclared.
            let data = frame.into_data().map_err(|_| StatusCode::BAD_REQUEST)?;
            if data.len() > maximum.saturating_sub(bytes.len()) {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            bytes.extend_from_slice(&data);
        }
        if let Some(length) = parts.headers.get("content-length") {
            if length.to_str().ok().and_then(|s| s.parse::<usize>().ok()) != Some(bytes.len()) {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        Ok(bytes)
    })
    .await;
    let bytes = match buffered {
        Err(_) => return empty(StatusCode::REQUEST_TIMEOUT),
        Ok(Err(status)) => return empty(status),
        Ok(Ok(bytes)) => bytes,
    };
    if Instant::now() >= deadline.0 {
        return empty(StatusCode::REQUEST_TIMEOUT);
    }
    if protected && !edge.ready.is_ready() {
        return overload();
    }
    // No timeout wraps started BPC/TSK work: cancellation would leave ambiguous
    // consumption. A 408 is exclusively a pre-factor admission outcome.
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpc_tsk_core::{
        AuditContextKey, BpcGateError, BpcVerification, CombinedVerifier, ImmutableRequest,
        MemoryBindingStore, NoopAuditSink, TskVerifierError,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    struct DenyBpc(Arc<AtomicUsize>);
    impl BpcGate for DenyBpc {
        fn verify(&self, _: &ImmutableRequest) -> Result<BpcVerification, BpcGateError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(BpcGateError)
        }
        fn recheck_current(&self, _: &BpcVerification) -> Result<bool, BpcGateError> {
            panic!("unexpected fence");
        }
    }
    struct NoTsk(Arc<AtomicUsize>);
    impl TskRequestVerifier for NoTsk {
        fn verify(
            &self,
            _: &tsk_rust_protocol::RequestData,
        ) -> Result<tsk_rust_protocol::VerifyResult, TskVerifierError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(TskVerifierError)
        }
    }
    fn app(
        config: &Config,
    ) -> (
        Router,
        Arc<Readiness>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let bpc = Arc::new(AtomicUsize::new(0));
        let tsk = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(AtomicUsize::new(0));
        let state = BridgeAxumState::try_new(
            CombinedVerifier::new(
                DenyBpc(Arc::clone(&bpc)),
                MemoryBindingStore::default(),
                NoTsk(Arc::clone(&tsk)),
                NoopAuditSink,
                AuditContextKey::new([1; 32]),
            ),
            config.request_limits(),
            config.blocking_admission,
        )
        .unwrap();
        let counter = Arc::clone(&handler);
        let protected = Router::new()
            .route(
                "/v1/protected",
                post(move |Extension(_): Extension<CombinedAuthSnapshot>| {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .route_layer(middleware::from_fn_with_state(state, bpc_tsk_admission));
        let ready = Arc::new(Readiness::default());
        (
            router(protected, Arc::clone(&ready), config),
            ready,
            bpc,
            tsk,
            handler,
        )
    }
    fn request(body: Body) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/protected?exact=%2F+a")
            .header("x-bpc-pair-id", "pair_test")
            .header("x-bpc-signature", "signature")
            .header("x-bpc-signed-data", "payload")
            .header("x-bpc-version", "1.0")
            .header("x-tsk-client-id", "tsk_client")
            .header("x-tsk-key", "credential")
            .header("x-tsk-version", "1")
            .body(body)
            .unwrap()
    }
    async fn assert_empty(response: Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        for (name, value) in SECURITY_HEADERS {
            assert_eq!(response.headers()[name], value);
        }
        assert!(!response.headers().contains_key("server"));
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
        assert!(!response.headers().contains_key("strict-transport-security"));
        assert!(
            axum::body::to_bytes(response.into_body(), 1)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn readiness_latch_and_liveness_do_not_touch_dependencies() {
        let config = crate::config::test_config();
        let (app, ready, bpc, tsk, handler) = app(&config);
        let health = |path| Request::builder().uri(path).body(Body::empty()).unwrap();
        assert_empty(
            app.clone().oneshot(health("/livez")).await.unwrap(),
            StatusCode::NO_CONTENT,
        )
        .await;
        assert_empty(
            app.clone().oneshot(health("/readyz")).await.unwrap(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
        assert!(ready.complete());
        assert_empty(
            app.clone().oneshot(health("/readyz")).await.unwrap(),
            StatusCode::NO_CONTENT,
        )
        .await;
        ready.shutdown();
        assert!(!ready.complete());
        assert_empty(
            app.clone().oneshot(health("/readyz")).await.unwrap(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .await;
        assert_empty(
            app.clone().oneshot(health("/livez")).await.unwrap(),
            StatusCode::NO_CONTENT,
        )
        .await;
        let response = app.oneshot(request(Body::empty())).await.unwrap();
        assert_eq!(response.headers()["retry-after"], "1");
        assert_empty(response, StatusCode::SERVICE_UNAVAILABLE).await;
        for calls in [bpc, tsk, handler] {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn generic_denial_never_executes_tsk_or_handler() {
        let config = crate::config::test_config();
        let (app, ready, bpc, tsk, handler) = app(&config);
        assert!(ready.complete());
        assert_empty(
            app.oneshot(request(Body::empty())).await.unwrap(),
            StatusCode::UNAUTHORIZED,
        )
        .await;
        assert_eq!(bpc.load(Ordering::SeqCst), 1);
        assert_eq!(tsk.load(Ordering::SeqCst), 0);
        assert_eq!(handler.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn security_headers_overwrite_handler_values() {
        let config = crate::config::test_config();
        let ready = Arc::new(Readiness::default());
        let protected = Router::new().route(
            "/test",
            get(|| async {
                let mut r = empty(StatusCode::NO_CONTENT);
                for (name, _) in SECURITY_HEADERS {
                    r.headers_mut()
                        .append(name, HeaderValue::from_static("unsafe"));
                }
                r.headers_mut()
                    .insert("server", HeaderValue::from_static("secret-server"));
                r
            }),
        );
        let response = router(protected, ready, &config)
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        for (name, _) in SECURITY_HEADERS {
            assert_eq!(response.headers().get_all(name).iter().count(), 1);
        }
        assert_empty(response, StatusCode::NO_CONTENT).await;
    }

    #[tokio::test]
    async fn all_forwarding_headers_are_rejected_before_admission() {
        let config = crate::config::test_config();
        let (app, ready, bpc, tsk, handler) = app(&config);
        ready.complete();
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-arbitrary",
        ] {
            let mut r = request(Body::empty());
            r.headers_mut()
                .insert(name, HeaderValue::from_static("untrusted"));
            assert_empty(
                app.clone().oneshot(r).await.unwrap(),
                StatusCode::BAD_REQUEST,
            )
            .await;
        }
        for calls in [bpc, tsk, handler] {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn framing_body_header_and_timeout_errors_have_no_factor_effects() {
        let mut config = crate::config::test_config();
        config.max_body_bytes = 3;
        let (app, ready, bpc, tsk, handler) = app(&config);
        ready.complete();
        assert_empty(
            app.clone()
                .oneshot(request(Body::from("1234")))
                .await
                .unwrap(),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
        let mut r = request(Body::empty());
        r.headers_mut()
            .insert("content-length", HeaderValue::from_static("4"));
        assert_empty(
            app.clone().oneshot(r).await.unwrap(),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
        let mut r = request(Body::empty());
        r.headers_mut()
            .insert("content-length", HeaderValue::from_static("2"));
        r.headers_mut()
            .insert("transfer-encoding", HeaderValue::from_static("chunked"));
        assert_empty(
            app.clone().oneshot(r).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        let mut r = request(Body::empty());
        r.headers_mut()
            .append("content-length", HeaderValue::from_static("0"));
        r.headers_mut()
            .append("content-length", HeaderValue::from_static("0"));
        assert_empty(
            app.clone().oneshot(r).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        let mut r = request(Body::empty());
        r.headers_mut()
            .insert("x-bad", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_empty(
            app.clone().oneshot(r).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        let mut r = request(Body::empty());
        r.headers_mut().insert(
            "x-big",
            HeaderValue::from_str(&"a".repeat(config.max_header_bytes)).unwrap(),
        );
        assert_empty(
            app.clone().oneshot(r).await.unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        let mut r = request(Body::empty());
        r.extensions_mut()
            .insert(Deadline(Instant::now() - Duration::from_millis(1)));
        assert_empty(
            app.clone().oneshot(r).await.unwrap(),
            StatusCode::REQUEST_TIMEOUT,
        )
        .await;
        let stream = futures_util::stream::iter([Err::<axum::body::Bytes, _>(
            std::io::Error::other("not-public"),
        )]);
        assert_empty(
            app.oneshot(request(Body::from_stream(stream)))
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
        )
        .await;
        for calls in [bpc, tsk, handler] {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn outer_blocking_overload_is_generic_503_without_factor_work() {
        let config = crate::config::test_config();
        let (protected, ready, bpc, tsk, handler) = app(&config);
        ready.complete();
        let edge = Edge {
            config,
            ready,
            blocking: Arc::new(Semaphore::new(1)),
        };
        let _permit = edge.blocking.acquire().await.unwrap();
        let app = protected.layer(middleware::from_fn_with_state(edge.clone(), buffered_edge));
        let response = app.oneshot(request(Body::empty())).await.unwrap();
        assert_eq!(response.headers()["retry-after"], "1");
        assert_empty(response, StatusCode::SERVICE_UNAVAILABLE).await;
        for calls in [bpc, tsk, handler] {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn buffer_preserves_exact_method_path_query_and_body() {
        let config = crate::config::test_config();
        let ready = Arc::new(Readiness::default());
        let protected = Router::new().route(
            "/exact",
            post(|request: Request<Body>| async move {
                assert_eq!(request.method().as_str(), "POST");
                assert_eq!(
                    request.uri().path_and_query().unwrap().as_str(),
                    "/exact?x=%2F+a&x=1"
                );
                assert_eq!(
                    axum::body::to_bytes(request.into_body(), 32)
                        .await
                        .unwrap()
                        .as_ref(),
                    &[0, 1, 0xff, b'\r', b'\n']
                );
                StatusCode::NO_CONTENT
            }),
        );
        let app = router(protected, ready, &config);
        assert_empty(
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/exact?x=%2F+a&x=1")
                    .body(Body::from(vec![0, 1, 0xff, b'\r', b'\n']))
                    .unwrap(),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT,
        )
        .await;
    }
}
