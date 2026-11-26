//! Shared optional remote-client seams. Declaring these values starts no task,
//! listener, timer or allocation. Design 45 §§3–6 and 47 §§5/9 govern consumers.
#[cfg(feature = "remote")]
pub use se_remote_host::channel;
#[cfg(feature = "remote")]
use se_types::Result;
#[cfg(feature = "remote")]
use std::sync::Arc;
#[cfg(feature = "remote")]
pub mod client;
#[cfg(feature = "remote")]
pub(crate) mod control;
#[cfg(feature = "remote")]
pub use control::{BootstrapSession, startup_notice};
#[cfg(feature = "remote")]
pub(crate) use se_remote_host::cursor;
#[cfg(feature = "remote")]
pub use se_remote_host::listener;
#[cfg(feature = "remote")]
pub use se_remote_host::publish;
#[cfg(feature = "remote")]
pub use se_remote_host::ssh;
#[cfg(feature = "remote")]
pub mod service;
#[cfg(feature = "remote")]
pub use client::ClientConnector;
mod owner_input;
#[cfg(feature = "remote")]
pub(crate) use owner_input::OwnerCall;
pub use owner_input::OwnerInput;
#[cfg(feature = "remote")]
pub use owner_input::{LaunchPermissionChange, SourcePermissionChange};
#[cfg(feature = "remote")]
pub use se_remote_host::session;
#[cfg(not(feature = "remote"))]
pub mod session {}
pub use se_remote::RemoteCallContext;
#[cfg(feature = "remote")]
pub use se_remote::wire;
pub use se_remote::{
    ClientConnectionId, CredentialSource, RemoteClient, RemoteConnector, RemoteFuture, RemoteRoute,
    RemoteWatchStream,
};
pub use se_types::remote::*;

#[cfg(feature = "remote")]
pub use se_remote_host::auth;
#[cfg(feature = "remote")]
pub use se_remote_host::keys;

#[cfg(feature = "remote")]
pub use se_remote_host::read;

#[cfg(feature = "remote")]
pub use se_remote_host::bindings;
#[cfg(feature = "listener")]
pub mod broker;

#[cfg(feature = "remote")]
pub(crate) use se_remote_host::view_request;

#[cfg(feature = "remote")]
pub struct RemoteBlockingRunner(pub crate::runtime::BlockingPool);

#[cfg(feature = "remote")]
impl se_remote_host::BlockingRunner for RemoteBlockingRunner {
    fn run_foreground(
        &self,
        timeout: std::time::Duration,
        work: Box<dyn FnOnce() -> Result<Box<dyn std::any::Any + Send>> + Send>,
    ) -> RemoteFuture<'_, Box<dyn std::any::Any + Send>> {
        Box::pin(async move {
            let deadline =
                crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                    expected_generation: None,
                    timeout,
                    cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                })?;
            self.0
                .run(crate::runtime::BlockingClass::Foreground, &deadline, work)
                .await
        })
    }
    fn run_owned(
        &self,
        timeout: std::time::Duration,
        work: Box<dyn FnOnce() -> Result<Box<dyn std::any::Any + Send>> + Send>,
    ) -> RemoteFuture<'_, Box<dyn std::any::Any + Send>> {
        Box::pin(async move {
            let deadline =
                crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                    expected_generation: None,
                    timeout,
                    cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                })?;
            self.0.run_owned(&deadline, work).await
        })
    }
}

#[cfg(feature = "remote")]
pub(crate) fn remote_deadline() -> Result<crate::client::lease::Deadline> {
    crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout: std::time::Duration::from_secs(30),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}

#[cfg(feature = "remote")]
impl se_remote_host::WriterFaultObserver for crate::runtime::tasks::OwnershipFault {
    fn observe_writer(&self, error: &se_store::StoreError) {
        crate::runtime::tasks::OwnershipFault::observe_writer(self, error);
    }
}
