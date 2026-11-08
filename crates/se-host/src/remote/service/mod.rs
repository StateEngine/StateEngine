//! The owning host's closed list/watch/send adapter. No remote Owner snapshot.
use super::*;
use se_types::{Result, SeError};
use std::{sync::Arc, time::Duration};
mod list;
mod send;
mod watch;
#[derive(Clone)]
pub struct Service {
    router: crate::runtime::HostedRouter,
    store: Arc<session::SecurityStore>,
    live: Arc<publish::LivePublisher>,
    cursors: cursor::Cursors,
}
impl Service {
    pub fn new(
        router: crate::runtime::HostedRouter,
        store: Arc<session::SecurityStore>,
        live: Arc<publish::LivePublisher>,
        cipher: Arc<keys::CursorCipher>,
        host: RemoteHostId,
    ) -> Self {
        let cursors = cursor::Cursors::new(cipher, host, store.info.clone());
        Self {
            router,
            store,
            live,
            cursors,
        }
    }
    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.router.check_open()?;
        let deadline =
            crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                expected_generation: Some(self.router.execution.generation),
                timeout: Duration::from_secs(10),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })?;
        self.router
            .execution
            .blocking
            .run(crate::runtime::BlockingClass::Foreground, &deadline, work)
            .await
    }
}
impl listener::RemoteService for Service {
    fn execute(&self, request: auth::AuthorizedRemoteRequest) -> RemoteFuture<'_, wire::Reply> {
        Box::pin(async move {
            match request.request() {
                RemoteRequest::List(input) => {
                    let input = input.clone();
                    let service = self.clone();
                    self.blocking(move || list::page(&service, &request, &input))
                        .await
                        .map(|value| wire::Reply::List(Box::new(value)))
                }
                RemoteRequest::Send(_) => self
                    .send(request)
                    .await
                    .map(|value| wire::Reply::Send(Box::new(value))),
                RemoteRequest::Watch(_) => Err(SeError::invalid(
                    "watch request",
                    "the retained bounded subscription path",
                )),
            }
        })
    }
    fn watch(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> RemoteFuture<'_, Box<dyn RemoteWatchStream>> {
        Box::pin(async move {
            self.router.check_open()?;
            Ok(Box::new(watch::Watch::new(self.clone(), request)?) as Box<dyn RemoteWatchStream>)
        })
    }
}
