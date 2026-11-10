//! A connection owns its reader, writer, bounded operations and shutdown together.
use super::{
    limits::{Handshake, Limits},
    output::Output,
    *,
};
use crate::remote::{
    channel::unavailable,
    transport_io::{BudgetIo, Controls, FramedIo},
    wire::{ClientFrame, Phase, ServerFrame},
};
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::timeout;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};
mod io;
mod pump;
mod requests;
type Socket = WebSocketStream<io::CloseObserved<FramedIo<BudgetIo<TcpStream>>>>;

pub(super) async fn bounded<T: Send + 'static>(
    endpoint: &ClientEndpoint,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let deadline = crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    })?;
    endpoint
        .blocking
        .run(crate::runtime::BlockingClass::Foreground, &deadline, work)
        .await
}
pub(super) async fn serve(
    socket: TcpStream,
    endpoint: Arc<ClientEndpoint>,
    limits: Arc<Limits>,
    permit: Handshake,
) -> Result<()> {
    let output = Arc::new(Output::default());
    let controls = Arc::new(Controls::default());
    let mut socket = timeout(Duration::from_secs(10), async {
        socket
            .set_nodelay(true)
            .map_err(|_| unavailable("client TCP setup failed"))?;
        let io = BudgetIo::new(socket, controls.clone());
        let io = io::CloseObserved::new(FramedIo::new(io, controls.clone()), output.clone());
        let config = WebSocketConfig::default()
            .read_buffer_size(8192)
            .write_buffer_size(0)
            .max_write_buffer_size(REMOTE_FRAME_BYTES + 1024)
            .max_frame_size(Some(REMOTE_FRAME_BYTES))
            .max_message_size(Some(REMOTE_FRAME_BYTES));
        #[expect(
            clippy::result_large_err,
            reason = "The standard Upgrade callback requires the unboxed HTTP error response."
        )]
        let callback = |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                        response| { headers(request, response) };
        let socket = tokio_tungstenite::accept_hdr_async_with_config(io, callback, Some(config))
            .await
            .map_err(|_| unavailable("client HTTP Upgrade refused"))?;
        controls.framing();
        Ok::<_, SeError>(socket)
    })
    .await
    .map_err(|_| unavailable("HTTP header deadline exceeded (10 seconds)"))??;
    let connection = endpoint.security.accepted_connection()?;
    let (channel, waiting) = endpoint.security.pending_channel(connection)?;
    send(&mut socket, &ServerFrame::Open { channel }, Phase::PreAuth).await?;
    let admitted = timeout(Duration::from_secs(10), async {
        let device = waiting
            .await
            .map_err(|_| unavailable("SSH channel authorization was not completed"))?;
        let security = endpoint.security.clone();
        let checked = device.clone();
        let registered = output.clone();
        let ready = bounded(&endpoint, move || {
            let erased: Arc<dyn auth::OutputInvalidation> = registered;
            security.register_output(&checked, &erased)?;
            security.ready(&checked)
        })
        .await?;
        let slot = limits.device(&device.grant().device)?;
        send(&mut socket, &ServerFrame::Ready(ready), Phase::PreAuth).await?;
        Ok::<_, SeError>((device, slot))
    })
    .await
    .map_err(|_| unavailable("SSH channel authorization deadline exceeded (10 seconds)"))?;
    endpoint.security.cancel_channel(channel)?;
    let (device, slot) = match admitted {
        Ok(value) => value,
        Err(error) => {
            // The pre-auth error contains no private state. Busy, unreadable,
            // deadline and authority refusals must retain their distinct codes.
            let _ = send(
                &mut socket,
                &ServerFrame::Error {
                    id: None,
                    error: error.body.clone(),
                },
                Phase::PreAuth,
            )
            .await;
            return Err(error);
        }
    };
    controls.authenticated();
    drop(permit);
    pump::run(socket, endpoint, output, device, slot).await
}
#[expect(
    clippy::result_large_err,
    reason = "The standard WebSocket callback requires this exact HTTP response type."
)]
fn headers(
    request: &tokio_tungstenite::tungstenite::handshake::server::Request,
    response: tokio_tungstenite::tungstenite::handshake::server::Response,
) -> std::result::Result<
    tokio_tungstenite::tungstenite::handshake::server::Response,
    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
> {
    let headers = request.headers();
    let valid = request.method() == "GET"
        && request.uri().path() == CLIENT_DATA_PATH
        && request.uri().query().is_none()
        && headers.get_all("host").iter().count() == 1
        && headers
            .get("host")
            .is_some_and(|v| v.as_bytes() == b"localhost")
        && !headers.contains_key("origin")
        && !headers.contains_key("cookie")
        && !headers.contains_key("authorization")
        && !headers.contains_key("sec-websocket-extensions");
    if valid {
        Ok(response)
    } else {
        let mut response = tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(
            Some("native client endpoint refused".into()),
        );
        *response.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN;
        Err(response)
    }
}
async fn send(socket: &mut Socket, frame: &ServerFrame, phase: Phase) -> Result<()> {
    timeout(
        Duration::from_secs(5),
        socket.send(Message::text(wire::encode(frame, phase)?)),
    )
    .await
    .map_err(|_| unavailable("client write deadline exceeded"))?
    .map_err(|_| unavailable("client socket write failed"))
}
