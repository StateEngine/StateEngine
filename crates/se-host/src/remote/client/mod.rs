//! Host adapter over `se_remote_host::client::ClientConnector`.
use super::*;
use std::sync::Arc;

#[derive(Clone)]
pub struct ClientConnector(se_remote_host::client::ClientConnector);

impl ClientConnector {
    pub fn new(blocking: crate::runtime::BlockingPool) -> Self {
        Self(se_remote_host::client::ClientConnector::new(Arc::new(
            RemoteBlockingRunner(blocking),
        )))
    }
    pub fn with_forwards(
        blocking: crate::runtime::BlockingPool,
        forwards: Arc<ssh::Forwards>,
    ) -> Self {
        Self(se_remote_host::client::ClientConnector::with_forwards(
            Arc::new(RemoteBlockingRunner(blocking)),
            forwards,
        ))
    }
    pub fn forwards(&self) -> Arc<ssh::Forwards> {
        self.0.forwards()
    }
    pub fn connect(
        &self,
        route: RemoteRoute,
        device: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>> {
        self.0.connect(route, device, signer)
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
