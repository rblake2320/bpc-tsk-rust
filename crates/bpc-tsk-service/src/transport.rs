use std::{
    convert::Infallible,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::Instant,
};
use tower::ServiceExt;

use crate::{
    ServiceError,
    config::Config,
    http::{self, Deadline, Readiness},
};

struct Prefixed {
    stream: TcpStream,
    prefix: std::io::Cursor<Vec<u8>>,
}
impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = self.prefix.position() as usize;
        if position < self.prefix.get_ref().len() {
            let count = buf.remaining().min(self.prefix.get_ref().len() - position);
            buf.put_slice(&self.prefix.get_ref()[position..position + count]);
            self.prefix.set_position((position + count) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn error(stream: &mut TcpStream, status: StatusCode) {
    let mut response = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: 0\r\nconnection: close\r\n",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Error")
    );
    for (name, value) in http::SECURITY_HEADERS {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response.push_str("retry-after: 1\r\n");
    }
    response.push_str("\r\n");
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}

async fn head(stream: &mut TcpStream, config: &Config) -> Result<Vec<u8>, StatusCode> {
    let mut prefix = Vec::new();
    let end = loop {
        if let Some(end) = prefix.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if prefix.len() >= config.max_header_bytes {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut buffer = [0u8; 1024];
        let size = stream
            .read(&mut buffer)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if size == 0 {
            return Err(StatusCode::BAD_REQUEST);
        }
        prefix.extend_from_slice(&buffer[..size]);
    };
    if end > config.max_header_bytes {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut fields = vec![httparse::EMPTY_HEADER; config.max_header_count];
    let mut parsed = httparse::Request::new(&mut fields);
    if !matches!(parsed.parse(&prefix[..end]), Ok(httparse::Status::Complete(size)) if size == end)
        || parsed.version != Some(1)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut headers = HeaderMap::new();
    for header in parsed.headers.iter() {
        let name =
            HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| StatusCode::BAD_REQUEST)?;
        let value = HeaderValue::from_bytes(header.value).map_err(|_| StatusCode::BAD_REQUEST)?;
        headers.append(name, value);
    }
    if headers.get_all("host").iter().count() != 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    http::validate_head(
        parsed.method.unwrap_or(""),
        parsed.path.unwrap_or(""),
        &headers,
        config,
    )?;
    Ok(prefix)
}

async fn connection(
    mut stream: TcpStream,
    config: Config,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
) {
    let deadline = Instant::now() + Duration::from_millis(config.request_timeout_ms);
    let prefix = tokio::select! {
        _ = shutdown.changed() => { error(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await; return; },
        result = tokio::time::timeout_at(deadline, head(&mut stream, &config)) => match result {
            Ok(Ok(prefix)) => prefix,
            Ok(Err(status)) => { error(&mut stream, status).await; return; },
            Err(_) => { error(&mut stream, StatusCode::REQUEST_TIMEOUT).await; return; },
        }
    };
    if *shutdown.borrow() {
        error(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await;
        return;
    }
    let io = TokioIo::new(Prefixed {
        stream,
        prefix: std::io::Cursor::new(prefix),
    });
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let app = app.clone();
        async move {
            let mut request = request.map(Body::new);
            request.extensions_mut().insert(Deadline(deadline));
            let response = app
                .oneshot(request)
                .await
                .unwrap_or_else(|never: Infallible| match never {});
            Ok::<_, Infallible>(response)
        }
    });
    // One exact origin-form HTTP/1.1 request per connection. No HTTP/2,
    // keepalive, pipelined retry, URI normalization or transparent decompression.
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(config.max_header_count)
        .max_buf_size(32_768);
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {},
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

pub(crate) async fn serve(
    app: Router,
    config: &Config,
    ready: Arc<Readiness>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServiceError> {
    let listener = TcpListener::bind(config.listener)
        .await
        .map_err(|_| ServiceError("listener"))?;
    let capacity = Arc::new(Semaphore::new(config.max_concurrency));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.map_err(|_| ServiceError("listener"))?;
                if *shutdown.borrow() { error(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await; break; }
                let permit = match Arc::clone(&capacity).try_acquire_owned() {
                    Ok(permit) => permit,
                    // Bounded write, no additional spawned overload tasks.
                    Err(_) => { error(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await; continue; },
                };
                let config = config.clone(); let app = app.clone(); let shutdown = shutdown.clone();
                connections.spawn(async move { let _permit = permit; connection(stream, config, app, shutdown).await; });
            }
        }
    }
    ready.shutdown();
    drop(listener);
    if tokio::time::timeout(Duration::from_millis(config.drain_timeout_ms), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exchange(bytes: &[u8], timeout_ms: u64) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = crate::config::test_config();
        config.request_timeout_ms = timeout_ms;
        let ready = Arc::new(Readiness::default());
        ready.complete();
        let app = http::router(Router::new(), ready, &config);
        let (_tx, rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            connection(stream, config, app, rx).await;
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap();
        response
    }
    fn empty_status(response: &[u8], status: &str) {
        let response = std::str::from_utf8(response).unwrap();
        assert!(response.starts_with(status), "{response}");
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty());
        for (name, value) in http::SECURITY_HEADERS {
            assert!(headers.contains(&format!("{name}: {value}")));
        }
        assert!(!headers.contains("server:"));
    }

    #[tokio::test]
    async fn real_transport_health_and_security_headers() {
        empty_status(
            &exchange(b"GET /livez HTTP/1.1\r\nHost: local\r\n\r\n", 1000).await,
            "HTTP/1.1 204",
        );
        empty_status(
            &exchange(b"GET /readyz HTTP/1.1\r\nHost: local\r\n\r\n", 1000).await,
            "HTTP/1.1 204",
        );
    }
    #[tokio::test]
    async fn malformed_forwarded_framing_and_chunking_are_empty_400() {
        for request in [
            &b"GET /livez HTTP/1.1\r\nHost: local\r\nForwarded: for=secret\r\n\r\n"[..],
            &b"GET /livez HTTP/1.1\r\nHost: local\r\nX-Forwarded-Any: secret\r\n\r\n"[..],
            &b"POST /v1/protected HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            &b"GET /livez HTTP/1.1\r\nHost: local\r\nBad Header: bad\r\n\r\n"[..],
            &b"GET /livez HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\nNOT-A-CHUNK\r\n"[..],
            &b"GET /livez HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-secret: trailer\r\n\r\n"[..],
        ] { empty_status(&exchange(request, 1000).await, "HTTP/1.1 400"); }
    }
    #[tokio::test]
    async fn slow_header_and_body_are_empty_408() {
        empty_status(
            &exchange(b"GET /livez HTTP/1.1\r\n", 20).await,
            "HTTP/1.1 408",
        );
        empty_status(
            &exchange(
                b"GET /livez HTTP/1.1\r\nHost: local\r\nContent-Length: 2\r\n\r\nx",
                20,
            )
            .await,
            "HTTP/1.1 408",
        );
    }
}
