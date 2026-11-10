//! Optional state created only by explicit native Owner control.
use super::*;
use se_core::store_error::store_error;
use se_types::{Result, SeError};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, watch};
mod add;
mod commands;
mod machine;
pub use machine::BootstrapSession;
mod endpoint;
mod policy;
mod revocations;
mod startup;
pub(crate) use commands::execute;
pub use startup::startup_notice;
struct Running {
    address: std::net::SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<listener::ListenerExit>>,
    closed: bool,
}
pub(crate) struct Control {
    security: Arc<auth::Security>,
    key: Arc<keys::ProtectedCredential>,
    cipher: Arc<keys::CursorCipher>,
    records: Arc<bindings::ProtectedBindings>,
    files: Arc<dyn se_store::StateFiles>,
    startup: startup::Fence,
    live: RwLock<Option<Arc<publish::LivePublisher>>>,
    local_watches: broker::watch::Watches,
    live_setup: Mutex<()>,
    running: Mutex<Option<Running>>,
    closing: AtomicBool,
    configure: Mutex<()>,
}
impl Control {
    pub(crate) fn live(&self) -> Result<Option<Arc<publish::LivePublisher>>> {
        match self.live.read() {
            Ok(value) => Ok(value.clone()),
            Err(poisoned) => {
                // Retire optional observations without breaking canonical capture.
                if let Some(publisher) = &*poisoned.into_inner() {
                    let _ = publisher.fence();
                }
                Err(SeError::invalid(
                    "remote publisher",
                    "unpoisoned optional host state; restart the owning host",
                ))
            }
        }
    }
    pub(crate) fn request_close(&self) {
        self.closing.store(true, Ordering::Release);
        if let Ok(running) = self.running.try_lock()
            && let Some(running) = &*running
        {
            running.shutdown.send_replace(true);
        }
    }
    pub(crate) async fn prepare(
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        initialize: bool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<(Arc<Self>, auth::VerifiedLocalOwner)> {
        router.check_open()?;
        if let Some(control) = router.execution.mail_waits.remote_control() {
            control.security.owner(&owner)?;
            return Ok((control.clone(), owner));
        }
        let context = router.execution.clone();
        let (mut control, owner) = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                if owner.generation != context.generation.get()
                    || owner.deadline <= std::time::Instant::now()
                {
                    return Err(SeError::invalid(
                        "remote Owner control",
                        "this generation's current native human admission",
                    ));
                }
                let control =
                    Self::load(&context, owner.owner.clone(), initialize.then_some(&owner))?;
                Ok((control, owner))
            })
            .await?;
        control.finish_startup(&router.execution, deadline).await?;
        let control = Arc::new(control);
        router.check_open()?;
        router
            .execution
            .mail_waits
            .install_remote_control(control.clone())?;
        let control = router
            .execution
            .mail_waits
            .remote_control()
            .ok_or_else(|| SeError::invalid("remote control", "its installed optional host state"))?
            .clone();
        control.security.owner(&owner)?;
        Ok((control, owner))
    }
    fn load(
        context: &crate::ExecutionContext,
        owner: se_types::HumanId,
        initialize: Option<&auth::VerifiedLocalOwner>,
    ) -> Result<Self> {
        let root = context.state_directory.clone();
        let files: Arc<dyn se_store::StateFiles> = Arc::new(
            crate::state_files::Files::open_with_policy(
                &root,
                crate::state_files::FilePolicy::Host,
            )
            .map_err(|error| store_error(&error))?,
        );
        let path = root.join("remote-keys/host.identity.key");
        let key = Arc::new(match initialize {
            Some(owner) => keys::ProtectedCredential::initialize(owner, files.clone(), path)?,
            None => keys::ProtectedCredential::open(files.clone(), path)?,
        });
        let cipher = Arc::new(match initialize {
            Some(owner) => keys::CursorCipher::initialize(owner, files.clone(), root.clone())?,
            None => keys::CursorCipher::load(files.clone(), root.clone())?,
        });
        let store = Arc::new(
            super::session::SecurityStore::new(
                context.reader.as_ref().clone(),
                context.writer.clone(),
                context.generation.get(),
                owner,
            )?
            .with_owner_fault(context.ownership_fault.clone()),
        );
        let security = Arc::new(auth::Security::new(
            store,
            &*key,
            context.generation,
            context.blocking.clone(),
        )?);
        let startup = startup::Fence::load(&*files, &root, &security)?;
        let records = Arc::new(bindings::ProtectedBindings::new(files.clone(), root));
        Ok(Self {
            security,
            key,
            cipher,
            records,
            files,
            startup,
            live: RwLock::new(None),
            local_watches: broker::watch::Watches::default(),
            live_setup: Mutex::new(()),
            running: Mutex::new(None),
            closing: AtomicBool::new(false),
            configure: Mutex::new(()),
        })
    }
    pub(crate) async fn close(&self) -> Result<()> {
        self.request_close();
        self.stop_listener().await
    }
    async fn stop_listener(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        let _setup = self.live_setup.lock().await;
        self.local_watches.close()?;
        let (publisher, mut failure) = match self.live.write() {
            Ok(mut live) => (live.take(), None),
            Err(poisoned) => (
                poisoned.into_inner().take(),
                Some(SeError::invalid(
                    "remote publisher",
                    "unpoisoned optional host state; restart the owning host",
                )),
            ),
        };
        if let Some(publisher) = publisher
            && let Err(error) = publisher.fence()
        {
            failure = Some(error);
        }
        if let Some(listener) = running.as_mut() {
            listener.shutdown.send_replace(true);
            if let Some(task) = listener.task.as_mut() {
                let result = task.await;
                // A completed JoinHandle must never be polled again on retry.
                listener.task = None;
                listener.closed = result.is_ok_and(|exit| exit.closed);
            }
            if !listener.closed {
                return Err(SeError::invalid(
                    "remote listener close",
                    "joined network tasks before releasing writer and host custody; retain this host until closure is proved",
                ));
            }
            *running = None;
        }
        failure.map_or(Ok(()), Err)
    }
}
