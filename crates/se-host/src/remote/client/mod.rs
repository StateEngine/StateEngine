//! Native forwarding and authorization adapter for the shared source client.
use super::*;
use std::sync::Arc;
#[derive(Clone)]
pub struct ClientConnector {
    inner: se_remote::client::ClientConnector,
    native: Arc<NativePeer>,
}
struct NativePeer {
    blocking: crate::runtime::BlockingPool,
    forwards: Arc<ssh::Forwards>,
}
impl ClientConnector {
    pub fn new(blocking: crate::runtime::BlockingPool) -> Self {
        Self::with_forwards(blocking, Arc::new(ssh::Forwards::default()))
    }
    pub fn with_forwards(
        blocking: crate::runtime::BlockingPool,
        forwards: Arc<ssh::Forwards>,
    ) -> Self {
        let native = Arc::new(NativePeer { blocking, forwards });
        Self {
            inner: se_remote::client::ClientConnector::new(native.clone()),
            native,
        }
    }
    pub fn forwards(&self) -> Arc<ssh::Forwards> {
        self.native.forwards.clone()
    }
    pub fn connect(
        &self,
        route: RemoteRoute,
        device: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>> {
        self.inner.connect(route, device, signer)
    }
}
impl RemoteConnector for ClientConnector {
    fn connect(
        &self,
        route: RemoteRoute,
        device: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>> {
        ClientConnector::connect(self, route, device, signer)
    }
}
impl se_remote::channel::PeerIo for NativePeer {
    fn open<'a>(
        &'a self,
        mut route: RemoteRoute,
        device: &'a MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'a, se_remote::channel::Socket> {
        Box::pin(async move {
            if let Some(config) = &route.forward {
                route.address = self
                    .forwards
                    .ensure(config.clone(), signer.clone(), &self.blocking)
                    .await?;
            }
            super::channel::open(&route, device, signer, &self.blocking, &self.forwards).await
        })
    }
}
