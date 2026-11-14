//! Source connection protocols and immutable per-call authority context.
mod context;
pub use context::{RemoteCallContext, refused as authority_refused};
#[cfg(feature = "remote")]
mod entropy;
#[cfg(feature = "remote")]
pub use entropy::entropy;
#[cfg(feature = "listener")]
pub mod broker;
#[cfg(feature = "remote")]
pub mod channel;
#[cfg(feature = "remote")]
pub mod client;
#[cfg(feature = "remote")]
pub mod ssh;
#[cfg(feature = "remote")]
pub mod transport_io;
#[cfg(feature = "remote")]
pub mod wire;
use se_types::Result;
pub use se_types::remote::*;
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

pub type RemoteFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Allocated by the accepting host, never read from wire or a remote actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ClientConnectionId(std::num::NonZeroU64);
impl ClientConnectionId {
    pub fn new(serial: std::num::NonZeroU64) -> Self {
        Self(serial)
    }
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Route data, never a key or authority. R0 permits an existing loopback forward.
#[derive(Clone, Debug)]
pub struct RemoteRoute {
    #[cfg(feature = "remote")]
    pub forward: Option<ssh::ForwardConfig>,
    pub address: SocketAddr,
    pub host: RemoteHostId,
}
impl RemoteRoute {
    pub fn validate(&self) -> Result<()> {
        if !self.address.ip().is_loopback() || self.address.port() == 0 {
            return Err(se_types::SeError::invalid(
                "remote route",
                "a nonzero loopback port for an existing SSH forward in R0",
            ));
        }
        Ok(())
    }
}

/// Protected key implementation belongs to the security lane. Call on the
/// bounded blocking pool if loading/protecting the key performs filesystem I/O.
pub trait CredentialSource: Send + Sync {
    fn credential_sha256(&self) -> [u8; 32];
    fn credential(&self) -> Result<LinkSecret>;
}

/// One authenticated multiplexed connection; callers never choose its identity
/// by changing per-connection state. Every operation carries its own source fence.
pub trait RemoteClient: Send + Sync {
    fn reply(
        &self,
        _call: RemoteCallContext,
        _request: RemoteSendReply,
    ) -> RemoteFuture<'_, RemoteSendResult> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "remote reply",
                "a destination supporting durable return conversations; update both installations through pairing",
            ))
        })
    }
    fn resolve_contact(
        &self,
        _call: RemoteCallContext,
        _request: RemoteResolveContact,
    ) -> RemoteFuture<'_, RemoteContactResult> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "remote contact recovery",
                "a destination supporting scoped receipt recovery; update both installations through pairing",
            ))
        })
    }
    fn replies(
        &self,
        _call: RemoteCallContext,
        _request: RemoteReplies,
    ) -> RemoteFuture<'_, RemoteRepliesResult> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "remote return mail",
                "a destination supporting durable replies; update both installations through pairing",
            ))
        })
    }

    fn launch(
        &self,
        _call: RemoteCallContext,
        _request: RemoteLaunch,
    ) -> RemoteFuture<'_, RemoteLaunchResult> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "remote launch",
                "a destination supporting explicit Owner-approved saved-profile launches; update both installations",
            ))
        })
    }
    /// Join this connector's network tasks during owning-host shutdown. A
    /// transport adapter must provide its own closure witness, never a no-op.
    fn close(&self) -> RemoteFuture<'_, ()> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "remote client closure",
                "a connector that joins its owned transport tasks",
            ))
        })
    }
    fn list(
        &self,
        call: RemoteCallContext,
        request: RemoteList,
    ) -> RemoteFuture<'_, RemoteListResult>;
    fn watch(
        &self,
        call: RemoteCallContext,
        request: RemoteWatch,
    ) -> RemoteFuture<'_, Box<dyn RemoteWatchStream>>;
    fn send(
        &self,
        call: RemoteCallContext,
        request: RemoteSend,
    ) -> RemoteFuture<'_, RemoteSendResult>;
}

/// Cancellation/drop releases this subscription, not provider custody.
pub trait RemoteWatchStream: Send {
    fn next(&mut self, wait: Duration) -> RemoteFuture<'_, RemoteWatchBatch>;
}

/// Transport implementation supplies this seam; it cannot choose a key or
/// substitute a human principal when source-session admission fails.
pub trait RemoteConnector: Send + Sync {
    fn connect(
        &self,
        route: RemoteRoute,
        device: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>>;
}
