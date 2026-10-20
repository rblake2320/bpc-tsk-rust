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

/// Shared state for [`bpc_tsk_admission`].
///
/// The verifier remains immutable for the lifetime of the Axum router. Its
/// authority dependencies, including BPC replay state and TSK state, must be
/// independently durable before this is used outside controlled testing.
#[derive(Clone)]
pub struct BridgeAxumState<B, S, T, A> {
    verifier: Arc<CombinedVerifier<B, S, T, A>>,
    limits: RequestLimits,
}

impl<B, S, T, A> BridgeAxumState<B, S, T, A> {
    /// Build protected-route state from a composition verifier and explicit
    /// admission limits.
    pub fn new(verifier: CombinedVerifier<B, S, T, A>, limits: RequestLimits) -> Self {
        Self {
            verifier: Arc::new(verifier),
            limits,
        }
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
/// All rejected requests receive the same empty `401` response with
/// `Cache-Control: no-store`, regardless of which factor or edge validation
/// failed. Rate limiting, TLS termination, request-smuggling defenses, and
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

    let PublicDecision::Authorized(snapshot) = state.verifier.verify(captured) else {
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

#[cfg(test)]
mod tests {
    use super::*;

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
