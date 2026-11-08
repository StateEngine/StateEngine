//! Optional client listener in the owning host; never a service/helper process.
use super::*;
use se_types::{Result, SeError};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
};
mod connection;
mod limits;
mod output;

/// Closed target-side execution. Implemented by the owning runtime's scoped
/// store/publisher adapter; no generic local operation or actor selector exists.
pub trait RemoteService: Send + Sync {
    fn execute(&self, request: auth::AuthorizedRemoteRequest) -> RemoteFuture<'_, wire::Reply>;
    fn watch(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> RemoteFuture<'_, Box<dyn RemoteWatchStream>>;
}
pub struct ClientEndpoint {
    pub security: Arc<auth::Security>,
    pub key: Arc<keys::ProtectedCredential>,
    pub cipher: Arc<keys::CursorCipher>,
    pub service: Arc<dyn RemoteService>,
    pub blocking: crate::runtime::BlockingPool,
}
pub struct ClientListener {
    listener: TcpListener,
    address: SocketAddr,
    limits: Arc<limits::Limits>,
}
pub struct ListenerExit {
    pub failed_connections: Option<u64>,
    pub last_error: Option<se_types::ErrorBody>,
    pub closed: bool,
}
impl ClientListener {
    pub fn bind(address: SocketAddr) -> Result<Self> {
        if !address.ip().is_loopback() {
            return Err(SeError::invalid(
                "remote R0 listener",
                "an explicit loopback address; non-loopback exposure is not admitted",
            ));
        }
        let io = |action: &str, error: std::io::Error| {
            se_core::scope::unreadable(
                &format!("remote listener at {address} ({action})"),
                &error.to_string(),
            )
            .with_cause(error)
        };
        let socket = std::net::TcpListener::bind(address).map_err(|error| {
            // Windows can report an exclusive busy port as PermissionDenied;
            // every native bind failure needs the local address and repair.
            SeError::new(se_types::Detail::ListenerUnavailable(
                se_types::details::ListenerUnavailable {
                    subject: format!("remote listener at {address}"),
                    reason: error.to_string(),
                    next_step: "Check local port reservations and socket permissions on this machine, then retry `se remote add SSH_ALIAS --name NAME` from the connecting machine. Preserve existing listeners and hosts.".into(),
                },
            ))
            .with_cause(error)
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|error| io("nonblocking setup", error))?;
        let address = socket
            .local_addr()
            .map_err(|error| io("local address", error))?;
        let listener =
            TcpListener::from_std(socket).map_err(|error| io("reactor registration", error))?;
        Ok(Self {
            listener,
            address,
            limits: Arc::new(limits::Limits::default()),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    /// The existing host supplies its shutdown fence. Dropping that fence also
    /// stops this listener; no independent lifetime or hidden runtime is created.
    pub async fn serve(
        self,
        endpoint: Arc<ClientEndpoint>,
        mut shutdown: watch::Receiver<bool>,
    ) -> ListenerExit {
        let mut tasks: JoinSet<Result<()>> = JoinSet::new();
        let mut failures = Some(0u64);
        let mut last_error = None;
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {biased;
                _=shutdown.changed()=>break,
                joined=tasks.join_next(),if !tasks.is_empty()=>{
                    match joined {
                        Some(Ok(Ok(())))=>(),
                        Some(Ok(Err(error)))=>{failures=failures.and_then(|n|n.checked_add(1));last_error=Some(error.into_body());}
                        Some(Err(_))=>{failures=failures.and_then(|n|n.checked_add(1));last_error=Some(super::channel::unavailable("client connection task failed").into_body());}
                        None=>(),
                    }
                }
                accepted=self.listener.accept()=>{
                    match accepted {
                        Ok((socket,peer))=>{
                            if let Ok(permit)=self.limits.handshake(peer.ip()) {
                                let endpoint=endpoint.clone();let limits=self.limits.clone();
                                tasks.spawn(async move {connection::serve(socket,endpoint,limits,permit).await});
                            }
                        }
                        Err(_)=>{failures=failures.and_then(|n|n.checked_add(1));last_error=Some(super::channel::unavailable("client listener accept failed").into_body());break;}
                    }
                }
            }
        }
        drop(self.listener);
        // Cancel untrusted network work immediately. Accepted SQLite operations
        // remain owned by the existing writer; transport drop cannot undo them.
        tasks.abort_all();
        let closed = tokio::time::timeout(Duration::from_secs(1), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        ListenerExit {
            failed_connections: failures,
            last_error,
            closed,
        }
    }
}
