//! Authenticated socket boundary supplied by the native host.
use super::{
    CredentialSource, MachineSession, RemoteFuture, RemoteRoute,
    transport_io::{BudgetIo, FramedIo},
};
use se_types::{Detail, SeError, details};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
pub type Socket = WebSocketStream<FramedIo<BudgetIo<TcpStream>>>;
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub fn unavailable(reason: &str) -> SeError {
    SeError::new(Detail::ListenerUnavailable(details::ListenerUnavailable {
        subject: "remote machine connection".into(), reason: reason.into(),
        next_step: "Check the saved SSH destination and machine name. Keep the original request key when retrying a send.".into(),
    }))
}
/// Resource pressure refuses one operation without changing its authority.
pub fn busy(reason: &str) -> SeError {
    SeError::new(Detail::RemoteBusy(details::RemoteBusy {
        reason: reason.into(),
        next_step: "Let outstanding work finish or cancel a read/watch, then retry the request; retain the SSH binding and original send idempotency key.".into(),
    }))
}

/// Opens the saved route and completes native authorization before returning.
pub trait PeerIo: Send + Sync {
    fn open<'a>(
        &'a self,
        route: RemoteRoute,
        device: &'a MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'a, Socket>;
}
