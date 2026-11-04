//! Loopback HTTP/1 listener and per-connection service (section 40 §7.3, H17).
//! One request per connection: keep-alive is off, so pipelined requests are
//! never parsed. Upgrades are never enabled. Responses carry no CORS headers.
use super::{
    admission::{self, MAX_BODY_BYTES, Refusal, Route},
    mcp::HttpBackend,
};
use crate::{
    HostedRouter, McpReply,
    client::{
        ClientOptions,
        lease::{CALL_TIMEOUT, Deadline},
    },
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header,
};
use se_types::Result;
use std::{
    convert::Infallible,
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr},
    pin::pin,
    sync::{Arc, Mutex, atomic::AtomicBool},
    task::Poll,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};

/// Active request connections; parked mail has its own negotiated session cap.
pub(crate) const ACTIVE_CONNECTIONS: usize = 64;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// hyper's smallest legal read buffer is 8 KiB; 16 KiB bounds the header block.
const MAX_HEADER_BYTES: usize = 16 * 1024;

pub struct HttpListener {
    listener: TcpListener,
    port: u16,
    slots: Arc<Semaphore>,
}
impl HttpListener {
    /// 127.0.0.1 only; never a wildcard or LAN address. `configured` is the
    /// stable `runtime.listen_port` init persisted: it is bound exactly, and a
    /// busy port refuses startup rather than moving silently. With no
    /// configured port, the OS picks one. Call inside the supplied runtime:
    /// registration needs its reactor.
    pub fn bind(configured: Option<u16>) -> Result<Self> {
        let io = |what: &str, error: std::io::Error| {
            se_core::scope::unreadable(what, &error.to_string()).with_cause(error)
        };
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, configured.unwrap_or(0)))
            .map_err(|e| match configured {
                Some(port) => io(
                    &format!("configured loopback port {port} (runtime.listen_port)"),
                    e,
                ),
                None => io("loopback HTTP bind", e),
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| io("loopback HTTP listener mode", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| io("loopback HTTP address", e))?
            .port();
        let listener =
            TcpListener::from_std(listener).map_err(|e| io("loopback HTTP registration", e))?;
        Ok(Self {
            listener,
            port,
            slots: Arc::new(Semaphore::new(ACTIVE_CONNECTIONS)),
        })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    /// The next connection that fits the active cap. Over-cap peers are closed
    /// at once rather than queued; the caller retries like any refused connect.
    pub(crate) async fn accept(&self) -> Result<(TcpStream, OwnedSemaphorePermit)> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(|error| {
                se_core::scope::unreadable("loopback HTTP accept", &error.to_string())
                    .with_cause(error)
            })?;
            match Arc::clone(&self.slots).try_acquire_owned() {
                Ok(permit) => return Ok((stream, permit)),
                Err(_) => drop(stream),
            }
        }
    }
}

/// Serve one connection to completion, or close it gracefully once the host
/// fence publishes its shutdown deadline. A proven parked wait releases the
/// active permit only after acquiring its separate session slot.
pub(crate) async fn connection(
    router: HostedRouter,
    stream: TcpStream,
    port: u16,
    permit: OwnedSemaphorePermit,
    mut shutdown: watch::Receiver<Option<Deadline>>,
) -> Result<()> {
    let peer = stream
        .peer_addr()
        .map_err(|error| se_core::scope::unreadable("HTTP native peer", &error.to_string()))?
        .ip();
    let permit = Arc::new(Mutex::new(Some(permit)));
    let active = Arc::clone(&permit);
    let service = hyper::service::service_fn(move |request| {
        let router = router.clone();
        let active = Arc::clone(&active);
        async move { Ok::<_, Infallible>(respond(&router, request, port, peer, active).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(MAX_HEADER_BYTES)
        .keep_alive(false);
    let mut served = pin!(builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service));
    let finished = if shutdown.borrow().is_some() {
        None
    } else {
        let mut fenced = pin!(shutdown.changed());
        poll_fn(|cx| {
            if let Poll::Ready(result) = served.as_mut().poll(cx) {
                return Poll::Ready(Some(result));
            }
            fenced.as_mut().poll(cx).map(|_| None)
        })
        .await
    };
    let result = match finished {
        Some(result) => result,
        None => {
            served.as_mut().graceful_shutdown();
            served.await
        }
    };
    drop(permit);
    // A client that disconnects mid-request is an ordinary closed connection.
    result.or_else(|error| {
        if error.is_incomplete_message() || error.is_canceled() || error.is_timeout() {
            Ok(())
        } else {
            Err(se_core::scope::unreadable(
                "loopback HTTP connection",
                &error.to_string(),
            ))
        }
    })
}

async fn respond(
    router: &HostedRouter,
    request: Request<Incoming>,
    port: u16,
    peer: IpAddr,
    active: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
) -> Response<Full<Bytes>> {
    let route = match admission::admit(&request, port) {
        Ok(route) => route,
        Err(refusal) => return refused(&refusal),
    };
    match route {
        Route::Livez => match serde_json::to_value(se_types::API_VERSION) {
            // Anonymous liveness: no counts, projects or readiness claims.
            Ok(api) => json(StatusCode::OK, &serde_json::json!({"ok": true, "api": api})),
            Err(_) => status_only(StatusCode::INTERNAL_SERVER_ERROR),
        },
        Route::Mail => {
            let secret = match admission::bearer(request.headers()) {
                Ok(Some(secret)) => Arc::new(secret),
                _ => {
                    return refused(&Refusal {
                        status: StatusCode::UNAUTHORIZED,
                        reason: "an active session bearer is required; relaunch the agent",
                        allow: None,
                    });
                }
            };
            let values = request.headers().get_all("last-event-id");
            let mut values = values.iter();
            let after = match values.next() {
                None => None,
                Some(value) => match value
                    .to_str()
                    .ok()
                    .and_then(|text| se_types::Cursor::new(text).ok())
                {
                    Some(cursor) => Some(cursor.as_str().to_owned()),
                    None => return status_only(StatusCode::BAD_REQUEST),
                },
            };
            if values.next().is_some() {
                return status_only(StatusCode::BAD_REQUEST);
            }
            let deadline = match request_deadline() {
                Ok(deadline) => deadline,
                Err(_) => return status_only(StatusCode::SERVICE_UNAVAILABLE),
            };
            match router.next_mail(secret, after, active, &deadline).await {
                Ok(page) => match serde_json::to_value(page) {
                    Ok(value) => json(StatusCode::OK, &value),
                    Err(_) => status_only(StatusCode::INTERNAL_SERVER_ERROR),
                },
                Err(error) => json(
                    StatusCode::CONFLICT,
                    &serde_json::json!({"error": error.body}),
                ),
            }
        }
        Route::Proof => {
            let deadline = match request_deadline() {
                Ok(deadline) => deadline,
                Err(_) => return status_only(StatusCode::SERVICE_UNAVAILABLE),
            };
            let body = Limited::new(request.into_body(), 1024).collect();
            let body =
                match tokio::time::timeout(deadline.remaining().unwrap_or_default(), body).await {
                    Ok(Ok(body)) => body.to_bytes(),
                    _ => return status_only(StatusCode::BAD_REQUEST),
                };
            let challenge = match serde_json::from_slice::<super::proof::Challenge>(&body) {
                Ok(challenge) => challenge,
                Err(_) => return status_only(StatusCode::BAD_REQUEST),
            };
            match router
                .local_http_proof(challenge, port, peer, &deadline)
                .await
            {
                Ok(value) => json(StatusCode::OK, &value),
                Err(_) => json(
                    StatusCode::CONFLICT,
                    &serde_json::json!({"error": "use a fresh challenge with the running host; obtain credentials only over protected IPC"}),
                ),
            }
        }
        Route::Mcp => {
            // A malformed header is carried into dispatch: lifecycle methods
            // stay anonymous, and only tool methods refuse it.
            let (secret, malformed) = match admission::bearer(request.headers()) {
                Ok(secret) => (secret, false),
                Err(_) => (None, true),
            };
            let deadline = match Deadline::from_options(&ClientOptions {
                expected_generation: None,
                timeout: CALL_TIMEOUT,
                cancelled: Arc::new(AtomicBool::new(false)),
            }) {
                Ok(deadline) => deadline,
                Err(_) => return status_only(StatusCode::SERVICE_UNAVAILABLE),
            };
            // Count actual bytes whatever Content-Length claimed, within the
            // same request clock as execution.
            let body = Limited::new(request.into_body(), MAX_BODY_BYTES).collect();
            let body = match tokio::time::timeout(CALL_TIMEOUT, body).await {
                Ok(Ok(body)) => body.to_bytes(),
                Ok(Err(_)) => {
                    return refused(&Refusal {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        reason: "body exceeds 1 MiB or ended early",
                        allow: None,
                    });
                }
                Err(_) => return status_only(StatusCode::REQUEST_TIMEOUT),
            };
            let mut backend = HttpBackend {
                router,
                deadline: &deadline,
                malformed,
            };
            match crate::mcp::dispatch(&body, secret.map(Arc::new), &mut backend).await {
                McpReply::Json(value) => json(StatusCode::OK, &value),
                McpReply::Accepted => status_only(StatusCode::ACCEPTED),
            }
        }
    }
}

fn refused(refusal: &Refusal) -> Response<Full<Bytes>> {
    let mut response = json(
        refusal.status,
        &serde_json::json!({"error": refusal.reason}),
    );
    if let Some(allow) = refusal.allow {
        response
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static(allow));
    }
    if refusal.status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

fn json(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(_) => return status_only(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn status_only(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

fn request_deadline() -> Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: CALL_TIMEOUT,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
