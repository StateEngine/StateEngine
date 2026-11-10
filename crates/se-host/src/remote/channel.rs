//! A forwarded WebSocket bound to application authorization on the SSH pipe.
use super::{
    transport_io::{BudgetIo, Controls, FramedIo},
    wire::{Phase, ServerFrame},
    *,
};
use futures_util::StreamExt;
use se_types::{ApiVersion, Detail, Result, SeError, details};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

pub(super) type Socket = WebSocketStream<FramedIo<BudgetIo<TcpStream>>>;
pub(super) const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) fn unavailable(reason: &str) -> SeError {
    SeError::new(Detail::ListenerUnavailable(details::ListenerUnavailable {
        subject: "remote machine connection".into(), reason: reason.into(),
        next_step: "Check the saved SSH destination and machine name. Keep the original request key when retrying a send.".into(),
    }))
}
/// Resource pressure refuses one operation without changing its authority.
pub(super) fn busy(reason: &str) -> SeError {
    SeError::new(Detail::RemoteBusy(details::RemoteBusy {
        reason: reason.into(),
        next_step: "Let outstanding work finish or cancel a read/watch, then retry the request; retain the SSH binding and original send idempotency key.".into(),
    }))
}
pub(super) async fn open(
    route: &RemoteRoute,
    device: &MachineSession,
    signer: Arc<dyn CredentialSource>,
    blocking: &crate::runtime::BlockingPool,
    forwards: &ssh::Forwards,
) -> Result<Socket> {
    route.validate()?;
    device.scope.validate()?;
    if route.host != device.host {
        return Err(auth::refused("route and saved machine identities disagree"));
    }
    let mut controls = Arc::new(Controls::default());
    let mut socket = match transport(route, CLIENT_DATA_PATH, controls.clone()).await {
        Ok(socket) => socket,
        Err(error)
            if error.code() == se_types::Code::ListenerUnavailable && route.forward.is_some() =>
        {
            let config = route
                .forward
                .clone()
                .ok_or_else(|| unavailable("saved SSH binding absent"))?;
            forwards
                .restart(config, signer.clone(), blocking)
                .await
                .map_err(|restart| restart.with_cause(error))?;
            controls = Arc::new(Controls::default());
            transport(route, CLIENT_DATA_PATH, controls.clone()).await?
        }
        Err(error) => return Err(error),
    };
    timeout(Duration::from_secs(10), async {
        let channel = match receive(&mut socket, Phase::PreAuth).await? {
            ServerFrame::Open { channel } => channel,
            ServerFrame::Error { error, .. } => return Err(error.with_far_origin().into()),
            _ => return Err(auth::refused("native forwarded channel identity is absent")),
        };
        let credential = blocking
            .run_owned(
                &crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                    expected_generation: None,
                    timeout: Duration::from_secs(10),
                    cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                })?,
                move || signer.credential(),
            )
            .await?;
        let config = route.forward.clone().ok_or_else(|| {
            auth::refused("application authorization requires the owned SSH connection")
        })?;
        let authorized = forwards
            .authorize(
                config,
                ssh::Authorization {
                    channel,
                    hello: RemoteHello {
                        protocol: ApiVersion {
                            major: CLIENT_PROTOCOL_MAJOR,
                            minor: CLIENT_PROTOCOL_MINOR,
                        },
                        host: device.host,
                        grant: device.grant.clone(),
                        device: device.device.clone(),
                        authority_revision: device.authority_revision,
                    },
                    credential,
                },
            )
            .await?;
        if authorized.host != device.host
            || authorized.grant != device.grant
            || authorized.authority_revision != device.authority_revision
            || authorized.protocol
                != (ApiVersion {
                    major: CLIENT_PROTOCOL_MAJOR,
                    minor: CLIENT_PROTOCOL_MINOR,
                })
        {
            return Err(auth::refused(
                "SSH authorization changed the saved environment or session",
            ));
        }
        match receive(&mut socket, Phase::PreAuth).await? {
            ServerFrame::Ready(mut ready) => {
                // A concurrent native renewal can extend the same session
                // between the SSH authorization and its socket publication.
                if ready.expires_at < authorized.expires_at {
                    return Err(auth::refused("forwarded session lease moved backwards"));
                }
                ready.expires_at = authorized.expires_at;
                if ready != authorized {
                    return Err(auth::refused(
                        "forwarded listener disagrees with native SSH authorization",
                    ));
                }
            }
            ServerFrame::Error { error, .. } => return Err(error.with_far_origin().into()),
            _ => {
                return Err(auth::refused(
                    "forwarded listener disagrees with native SSH authorization",
                ));
            }
        }
        Ok::<_, SeError>(())
    })
    .await
    .map_err(|_| unavailable("SSH channel authorization deadline exceeded (10seconds)"))??;
    controls.authenticated();
    Ok(socket)
}
pub(super) async fn receive(socket: &mut Socket, phase: Phase) -> Result<ServerFrame> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => return wire::decode(text.as_bytes(), phase),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => (),
            Some(Ok(Message::Close(_))) | None => {
                return Err(unavailable("remote connection closed"));
            }
            Some(Err(tokio_tungstenite::tungstenite::Error::Io(_))) => {
                return Err(unavailable("remote transport interrupted"));
            }
            _ => {
                return Err(auth::refused(
                    "remote peer refused the closed JSON protocol; correct its version before retrying",
                ));
            }
        }
    }
}
pub(super) async fn transport(
    route: &RemoteRoute,
    path: &str,
    controls: Arc<Controls>,
) -> Result<Socket> {
    route.validate()?;
    // One deadline covers TCP and HTTP, rather than stacking timeout ladders.
    let socket = timeout(Duration::from_secs(10), async {
        let tcp = TcpStream::connect(route.address).await.map_err(|_| unavailable("the configured loopback forward is unreachable"))?;
        tcp.set_nodelay(true).map_err(|_| unavailable("TCP latency configuration failed"))?;
        let io = BudgetIo::new(tcp, controls.clone());
        let io = FramedIo::new(io, controls.clone());
        let ws_config = WebSocketConfig::default().read_buffer_size(8192).write_buffer_size(0)
            .max_write_buffer_size(REMOTE_FRAME_BYTES + 1024)
            .max_frame_size(Some(REMOTE_FRAME_BYTES)).max_message_size(Some(REMOTE_FRAME_BYTES));
        // Fixed Host/SNI localhost, no Origin/cookies/credential header, and no redirect.
        // TCP goes only to the already validated address; no URI DNS lookup occurs.
        let uri = format!("ws://localhost{path}");
        let (socket, _) = tokio_tungstenite::client_async_with_config(uri, io, Some(ws_config)).await
            .map_err(|error| match error {
                tokio_tungstenite::tungstenite::Error::Io(_)
                | tokio_tungstenite::tungstenite::Error::ConnectionClosed
                | tokio_tungstenite::tungstenite::Error::AlreadyClosed
                | tokio_tungstenite::tungstenite::Error::Protocol(tokio_tungstenite::tungstenite::error::ProtocolError::HandshakeIncomplete) => unavailable("native client WebSocket Upgrade interrupted"),
                _ => auth::refused("native client WebSocket Upgrade or protocol refused; correct the explicit route before retrying"),
            })?;
        controls.framing();
        Ok::<_, SeError>(socket)
    }).await.map_err(|_| unavailable("TCP/HTTP header deadline exceeded (10seconds)"))??;
    Ok(socket)
}
