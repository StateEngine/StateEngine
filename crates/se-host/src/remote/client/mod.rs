//! Shared CLI/MCP connector: one pinned socket, per-call identity, bounded queues.
use super::channel::unavailable;
use super::wire::{ClientFrame, Phase, Reply, RequestId, ServerFrame};
use super::*;
use se_types::{Detail, Result, SeError, details};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
mod connection;
mod watch;
use connection::Connection;

#[derive(Clone)]
pub struct ClientConnector {
    blocking: crate::runtime::BlockingPool,
    forwards: Arc<ssh::Forwards>,
}
impl ClientConnector {
    pub fn new(blocking: crate::runtime::BlockingPool) -> Self {
        Self {
            blocking,
            forwards: Arc::new(ssh::Forwards::default()),
        }
    }
    pub fn with_forwards(
        blocking: crate::runtime::BlockingPool,
        forwards: Arc<ssh::Forwards>,
    ) -> Self {
        Self { blocking, forwards }
    }
    pub fn forwards(&self) -> Arc<ssh::Forwards> {
        self.forwards.clone()
    }
    pub fn connect(
        &self,
        route: RemoteRoute,
        device: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>> {
        Box::pin(async move {
            let client = Arc::new(Client {
                route,
                device,
                signer,
                blocking: self.blocking.clone(),
                forwards: self.forwards.clone(),
                connection: Arc::new(Mutex::new(None)),
                stopped: Arc::new(AtomicBool::new(false)),
            });
            client.connection().await?;
            Ok(client as Arc<dyn RemoteClient>)
        })
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
#[derive(Clone)]
struct Client {
    route: RemoteRoute,
    device: MachineSession,
    signer: Arc<dyn CredentialSource>,
    blocking: crate::runtime::BlockingPool,
    forwards: Arc<ssh::Forwards>,
    connection: Arc<Mutex<Option<Arc<Connection>>>>,
    stopped: Arc<AtomicBool>,
}
impl Client {
    async fn connection(&self) -> Result<Arc<Connection>> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(unavailable(
                "source connector has been closed by its owning host",
            ));
        }
        let mut current = self.connection.lock().await;
        if self.stopped.load(Ordering::Acquire) {
            return Err(unavailable(
                "source connector has been closed by its owning host",
            ));
        }
        if let Some(connection) = current.as_ref().filter(|c| !c.closed()) {
            return Ok(connection.clone());
        }
        if let Some(old) = current.as_ref() {
            old.close().await?;
            old.check_retry()?;
        }
        *current = None;
        let mut route = self.route.clone();
        if let Some(config) = &route.forward {
            route.address = self
                .forwards
                .ensure(config.clone(), self.signer.clone(), &self.blocking)
                .await?;
        }
        let socket = super::channel::open(
            &route,
            &self.device,
            self.signer.clone(),
            &self.blocking,
            &self.forwards,
        )
        .await?;
        let connection = Connection::new(socket);
        *current = Some(connection.clone());
        Ok(connection)
    }
    fn invocation(
        &self,
        call: &RemoteCallContext,
        request: RemoteRequest,
    ) -> Result<RemoteInvocation> {
        let invocation = call.invocation(&self.device, request)?;
        let (verb, targets) = match &invocation.request {
            RemoteRequest::List(r) => (RemoteVerb::List, r.targets.as_slice()),
            RemoteRequest::Watch(r) => (RemoteVerb::Watch, r.targets.as_slice()),
            RemoteRequest::Send(r) => (RemoteVerb::Send, std::slice::from_ref(&r.target)),
        };
        if !self.device.scope.verbs.contains(&verb)
            || targets.iter().any(|t| {
                !self.device.scope.targets.is_empty() && !self.device.scope.targets.contains(t)
            })
        {
            return Err(unavailable(
                "request is outside this device's exact saved scope",
            ));
        }
        Ok(invocation)
    }
}
impl RemoteClient for Client {
    fn close(&self) -> RemoteFuture<'_, ()> {
        Box::pin(async move {
            self.stopped.store(true, Ordering::Release);
            let mut current = self.connection.lock().await;
            if let Some(connection) = current.as_ref() {
                connection.close().await?;
            }
            *current = None;
            Ok(())
        })
    }
    fn list(
        &self,
        call: RemoteCallContext,
        request: RemoteList,
    ) -> RemoteFuture<'_, RemoteListResult> {
        Box::pin(async move {
            let invocation = self.invocation(&call, RemoteRequest::List(request))?;
            let connection = self.connection().await?;
            let result = connection.once(Arc::new(call), invocation).await?;
            match result {
                Reply::List(value) if value.schema == RemoteListResult::SCHEMA => Ok(*value),
                _ => Err(unavailable("remote list response type/schema mismatch")),
            }
        })
    }
    fn watch(
        &self,
        call: RemoteCallContext,
        request: RemoteWatch,
    ) -> RemoteFuture<'_, Box<dyn RemoteWatchStream>> {
        Box::pin(async move {
            self.invocation(&call, RemoteRequest::Watch(request.clone()))?;
            let mut stream = watch::Watch::new(self.clone(), Arc::new(call), request);
            stream.start().await?;
            Ok(Box::new(stream) as Box<dyn RemoteWatchStream>)
        })
    }
    fn send(
        &self,
        call: RemoteCallContext,
        request: RemoteSend,
    ) -> RemoteFuture<'_, RemoteSendResult> {
        Box::pin(async move {
            let key = request.idempotency_key.to_string();
            let invocation = self.invocation(&call, RemoteRequest::Send(request))?;
            let connection = self.connection().await?;
            // Once enqueue succeeds, a missing response is UNKNOWN, never failed or accepted.
            let result = connection.once(Arc::new(call), invocation).await;
            match result {
                Ok(Reply::Send(value)) if value.schema == RemoteSendResult::SCHEMA => Ok(*value),
                Ok(_) => Err(unknown_send(key)),
                Err(error) => Err(error),
            }
        })
    }
}
fn unknown_send(key: String) -> SeError {
    SeError::from(
        se_types::ErrorBody::new(Detail::CommitOutcomeUnknown(
            details::CommitOutcomeUnknown {
                operation: "remote.send".into(),
                key: Some(key),
                natural_events: Vec::new(),
            },
        ))
        .with_retry(se_types::Retry::AfterReread),
    )
}
