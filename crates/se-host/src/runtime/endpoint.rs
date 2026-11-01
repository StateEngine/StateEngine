//! Protected rendezvous publication under the retained exclusive lease. The
//! endpoint is a routing hint; its absence never grants direct-store authority.
use super::*;
use crate::{EndpointRecord, IpcEndpoint, IpcListener, client::endpoint as codec};
use se_core::store_error::store_error;
use se_store::RuntimeLease;
use se_types::{Read, Result, SeError};
use std::{
    io::{Read as ByteRead, Write},
    path::PathBuf,
    sync::Arc,
};

/// Shared by listener preparation and a CLI that cannot authenticate a
/// protected endpoint. This diagnostic neither connects nor retires any address;
/// manual recovery remains conditional on stopping the host and holding its lease.
pub fn endpoint_recovery_error(directory: &std::path::Path, reason: &str) -> SeError {
    SeError::new(se_types::Detail::StateConflict(
        se_types::details::StateConflict {
            subject: directory.join("endpoint.json").display().to_string(),
            reason: reason.into(),
            next_step: format!(
                "Stop any runtime using this data home ({}). Acquire and hold an exclusive lock on {} while you move only {} aside; then release the lock and retry se up for this same home. Preserve the store, credentials and machine identity; do not remove or connect to the mismatched address.",
                directory.display(),
                directory.join("runtime.lock").display(),
                directory.join("endpoint.json").display()
            ),
        },
    ))
}

pub struct HostedListener {
    pub(crate) listener: IpcListener,
    pub(crate) publication: EndpointPublication,
}
impl HostedListener {
    pub async fn accept(
        &mut self,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<crate::AcceptedIpcStream> {
        self.listener.accept(cancelled).await
    }

    pub(crate) async fn finish_transport(
        self,
        blocking: &BlockingPool,
    ) -> (Result<()>, Result<()>) {
        let Self {
            listener,
            publication,
        } = self;
        #[cfg(windows)]
        let started = std::time::Instant::now();
        let closed = match super::shutdown::cleanup_deadline() {
            Ok(bound) => listener.close_joined(blocking, &bound).await,
            Err(error) => Err(error),
        };
        #[cfg(windows)]
        super::shutdown::trace("transport-close-return", started, closed.is_ok());
        // Admission is fenced and tasks joined. Even failed native close must
        // attempt compare-and-remove; its error retains any pending reservation.
        let retired = match super::shutdown::cleanup_deadline() {
            Ok(bound) => {
                RetainedEndpoint { publication }
                    .retire(blocking, &bound)
                    .await
            }
            Err(error) => Err(error),
        };
        #[cfg(windows)]
        super::shutdown::trace("endpoint-retirement-return", started, retired.is_ok());
        (closed, retired)
    }
    pub fn endpoint(&self) -> &EndpointRecord {
        &self.publication.record
    }
    pub fn endpoint_recovery(&self) -> Option<&se_core::ops::EndpointRecovery> {
        self.publication.recovery.as_ref()
    }
    /// The supervisor first joins its connections. Native listener closure
    /// returns a retained endpoint for the separate owned-file retirement port.
    pub async fn close_transport(
        self,
        blocking: &BlockingPool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<RetainedEndpoint> {
        self.listener
            .close_joined(blocking, deadline)
            .await
            .map_err(|error| {
                se_core::scope::unreadable("IPC transport pending release", &error.to_string())
                    .with_cause(error)
            })?;
        blocking
            .run_owned(deadline, move || {
                self.publication.verify()?;
                Ok(RetainedEndpoint {
                    publication: self.publication,
                })
            })
            .await
    }
}
pub(crate) struct EndpointPublication {
    lease: Arc<HostLease>,
    path: PathBuf,
    record: EndpointRecord,
    recovery: Option<se_core::ops::EndpointRecovery>,
}
impl EndpointPublication {
    fn publish(
        lease: Arc<HostLease>,
        directory: PathBuf,
        record: EndpointRecord,
        recovery: Option<se_core::ops::EndpointRecovery>,
    ) -> Result<Self> {
        let bytes = codec::encode_endpoint(&record)?;
        let path = directory.join("endpoint.json");
        let staged = lease
            .files()
            .create_staging(&directory)
            .map_err(|e| store_error(&e))?;
        let mut file = staged.file;
        file.write_all(bytes.as_bytes())
            .map_err(|e| io_error("write staged endpoint", e))?;
        file.sync_all()
            .map_err(|e| io_error("sync staged endpoint", e))?;
        drop(file);
        lease
            .files()
            .publish_no_replace(&staged.path, &path)
            .map_err(|e| store_error(&e))?;
        let published = Self {
            lease,
            path,
            record,
            recovery,
        };
        published.verify()?;
        Ok(published)
    }
    fn retire_stale(
        lease: &HostLease,
        directory: &std::path::Path,
        expected_address: &crate::IpcEndpoint,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Option<se_core::ops::EndpointRecovery>> {
        let path = directory.join("endpoint.json");
        let mut recovery = None;
        let previous = match lease.files().readback(&path).map_err(|e| store_error(&e))? {
            Read::Absent { .. } => None,
            Read::Present { value: mut prior } => {
                let mut bytes = Vec::new();
                (&mut prior)
                    .take(crate::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| io_error("read stale endpoint", e))?;
                drop(prior);
                let record = codec::decode_endpoint(&bytes)?;
                if &record.address != expected_address {
                    recovery = Some(super::recovery::retain(&lease.files.0, &bytes)?);
                    None
                } else {
                    Some(bytes)
                }
            }
            Read::Unreadable { reason, .. } => {
                return Err(se_core::scope::unreadable("stale endpoint", &reason));
            }
            Read::Unknown { what } => {
                return Err(se_core::scope::unreadable("stale endpoint", &what));
            }
        };
        let cleanup = (|| -> Result<()> {
            deadline.remaining()?;
            #[cfg(unix)]
            {
                let crate::IpcEndpoint::UnixSocket(socket) = expected_address else {
                    return Err(SeError::invalid(
                        "stale endpoint",
                        "the native Unix socket address",
                    ));
                };
                let bound = deadline.native_bound();
                if let Some(stale) = se_proc::native_ipc::NativeUnixSocketCleanup::observe(
                    &socket.to_local()?,
                    &bound,
                )
                .map_err(crate::client::lease::native_error)?
                {
                    stale
                        .compare_remove(&bound)
                        .map_err(crate::client::lease::native_error)?;
                }
            }
            if let Some(previous) = previous {
                use sha2::Digest;
                lease
                    .files()
                    .remove_owned(&path, sha2::Sha256::digest(&previous).into())
                    .map_err(|e| store_error(&e))?;
            }
            Ok(())
        })();
        cleanup.map_err(|error| {
            super::recovery::after_retention(directory, recovery.as_ref(), error)
        })?;
        Ok(recovery)
    }
    fn verify(&self) -> Result<()> {
        let mut file = match self
            .lease
            .files()
            .readback(&self.path)
            .map_err(|e| store_error(&e))?
        {
            Read::Present { value } => value,
            _ => {
                return Err(SeError::invalid(
                    "published endpoint",
                    "the present protected file owned by this runtime",
                ));
            }
        };
        let mut bytes = Vec::new();
        (&mut file)
            .take(crate::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error("read published endpoint", e))?;
        let expected = codec::encode_endpoint(&self.record)?;
        if bytes != expected.as_bytes() {
            return Err(SeError::invalid(
                "published endpoint",
                "the exact bytes published by this epoch/generation",
            ));
        }
        Ok(())
    }
}
/// Native transport is closed; protected endpoint retirement still belongs to
/// the compare-and-remove native effect port. This value retains the OS lease
/// until that effect is independently read back as absent.
pub struct RetainedEndpoint {
    publication: EndpointPublication,
}
impl RetainedEndpoint {
    pub fn path(&self) -> &std::path::Path {
        &self.publication.path
    }
    pub fn expected_sha256(&self) -> Result<[u8; 32]> {
        use sha2::Digest;
        Ok(
            sha2::Sha256::digest(codec::encode_endpoint(&self.publication.record)?.as_bytes())
                .into(),
        )
    }
    /// Compare-and-remove the exact publication, then read native absence back.
    /// Native socket/pipe closure and accepted-task joins precede this method.
    pub async fn retire(
        self,
        blocking: &BlockingPool,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        blocking
            .run_owned(deadline, move || {
                let expected = self.expected_sha256()?;
                self.publication
                    .lease
                    .files()
                    .remove_owned(&self.publication.path, expected)
                    .map_err(|error| store_error(&error))?;
                self.verify_retired()
            })
            .await
    }
    pub fn verify_retired(self) -> Result<()> {
        match self
            .publication
            .lease
            .files()
            .readback(&self.publication.path)
            .map_err(|e| store_error(&e))?
        {
            Read::Absent { .. } => Ok(()),
            _ => Err(SeError::invalid(
                "endpoint retirement",
                "witnessed native absence after the exact owned removal effect",
            )),
        }
    }
}
impl HostedRuntime {
    pub async fn listen(
        &mut self,
        runtime: tokio::runtime::Handle,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<HostedListener> {
        let listener = self.publish_listener(runtime, deadline).await?;
        self.activate_listener();
        Ok(listener)
    }
    /// Detached process entry publishes while admission remains fenced. The
    /// native inherited channel must commit this exact owner before a router
    /// exists. The finite native wait is joined on the supplied blocking pool.
    #[cfg(any(target_os = "linux", windows))]
    pub async fn listen_bootstrap(
        &mut self,
        runtime: tokio::runtime::Handle,
        mut bootstrap: se_proc::RuntimeBootstrap,
        instance: se_proc::HostInstanceId,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<HostedListener> {
        let prepared = async {
            let identity = bootstrap.identity();
            if identity.machine != self.epoch.owner.fields().machine
                || identity.pid.0 != self.epoch.owner.fields().pid.get()
                || identity.image != self.epoch.owner.fields().executable.to_local()?
            {
                return Err(SeError::invalid(
                    "host bootstrap",
                    "the exact native owner of this lease",
                ));
            }
            let listener = self.publish_listener(runtime, deadline).await?;
            self.phase = crate::HostPhase::Activating;
            Ok(listener)
        }
        .await;
        let listener = match prepared {
            Ok(value) => value,
            Err(error) => {
                bootstrap
                    .report_startup_failure("host listener preparation", &error.to_string())
                    .map_err(|failure| {
                        se_core::scope::unreadable(
                            "native startup diagnostic",
                            &format!("{failure:?}"),
                        )
                    })?;
                return Err(error);
            }
        };
        // Keep the uncommitted guard outside a closure until admission succeeds;
        // dropping a rejected closure would exit before publication cleanup.
        let admission = self.execution.blocking.admit_owned(deadline).await;
        let (mut bootstrap, committed) = match admission {
            Ok(permit) => {
                self.execution
                    .blocking
                    .run_admitted_owned(permit, move || {
                        let committed =
                            bootstrap.await_commit_retained(instance).map_err(|error| {
                                se_core::scope::unreadable(
                                    "native runtime commit",
                                    &format!("{error:?}"),
                                )
                            });
                        Ok((bootstrap, committed))
                    })
                    .await?
            }
            Err(error) => (bootstrap, Err(error)),
        };
        if let Err(error) = committed {
            let (closed, retired) = listener.finish_transport(&self.execution.blocking).await;
            let pending: Vec<_> = closed.err().into_iter().chain(retired.err()).collect();
            let message = format!(
                "{error}; listener cleanup pending: {}",
                pending
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            let diagnostic = bootstrap.report_startup_failure("host commit cleanup", &message);
            let error = se_core::scope::unreadable("failed host bootstrap cleanup", &message)
                .with_cause(BootstrapCleanup {
                    error,
                    _pending: pending,
                });
            // The uncommitted guard remains here through both cleanup attempts;
            // its ordinary fail-closed Drop may now end the child safely.
            return Err(match diagnostic {
                Ok(()) => error,
                Err(failure) => se_core::scope::unreadable(
                    "native startup diagnostic",
                    &format!("{failure:?}; {error}"),
                )
                .with_cause(error),
            });
        }
        drop(bootstrap);
        self.activate_listener();
        Ok(listener)
    }
    fn activate_listener(&mut self) {
        self.phase = crate::HostPhase::Ready;
        self.fenced
            .store(false, std::sync::atomic::Ordering::Release);
    }
    async fn publish_listener(
        &mut self,
        runtime: tokio::runtime::Handle,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<HostedListener> {
        if self.phase != crate::HostPhase::Prepared {
            return Err(SeError::invalid(
                "host listener",
                "one prepared runtime before publication",
            ));
        }
        let directory = self.state_directory.clone();
        let lease = Arc::clone(&self.lease);
        let epoch = self.epoch.clone();
        let generation = self.generation();
        let kind = self.kind;
        let image_sha256 = self.image_sha256;
        let slots = self.execution.blocking.foreground_admission();
        let limits = self.limits.clone();
        let bind_deadline = deadline.clone();
        #[cfg(unix)]
        let socket_paths = self.socket_paths.clone();
        let listener = self
            .execution
            .blocking
            .run_owned(deadline, move || {
                #[cfg(unix)]
                let address = IpcEndpoint::UnixSocket(se_types::NativePath::from_local(
                    socket_paths
                        .prepare(&directory, &bind_deadline.native_bound())
                        .map_err(crate::client::lease::native_error)?,
                )?);
                #[cfg(windows)]
                let address = address(&directory)?;
                let record = EndpointRecord {
                    schema: 1,
                    address,
                    epoch,
                    generation,
                    kind,
                    listener_port: None,
                    api: se_types::API_VERSION,
                    package_version: env!("CARGO_PKG_VERSION").into(),
                    image_sha256,
                };
                let recovery = EndpointPublication::retire_stale(
                    &lease,
                    &directory,
                    &record.address,
                    &bind_deadline,
                )?;
                se_proc::native_ipc::publish_image_cache(
                    &directory,
                    image_sha256,
                    &bind_deadline.native_bound(),
                )
                .map_err(crate::client::lease::native_error)?;
                let listener =
                    IpcListener::bind_with_limits(record.clone(), runtime, slots, &limits)
                        .map_err(|error| {
                            super::recovery::after_retention(&directory, recovery.as_ref(), error)
                        })?;
                let retained = recovery.clone();
                let publication = match EndpointPublication::publish(
                    lease,
                    directory.clone(),
                    record,
                    recovery,
                ) {
                    Ok(publication) => publication,
                    Err(error) => {
                        let error = match listener.close() {
                            Ok(crate::IpcClose::Closed) => error,
                            Ok(crate::IpcClose::PendingRelease { error: close }) | Err(close) => se_core::scope::unreadable(
                                "listener publication cleanup",
                                &format!(
                                    "publication failed: {error}; listener close failed: {close}"
                                ),
                            )
                            .with_cause(error.with_cause(close)),
                        };
                        return Err(super::recovery::after_retention(
                            &directory,
                            retained.as_ref(),
                            error,
                        ));
                    }
                };
                Ok(HostedListener {
                    listener,
                    publication,
                })
            })
            .await?;
        Ok(listener)
    }
}
/// Default address for an embedding without explicit Unix platform roots.
/// A CLI with resolved Unix inputs uses UnixSocketPaths::expected_path instead;
/// both comparisons precede any connection to a busy home's endpoint record.
pub fn runtime_endpoint_address(directory: &std::path::Path) -> Result<IpcEndpoint> {
    #[cfg(unix)]
    {
        Ok(IpcEndpoint::UnixSocket(se_types::NativePath::from_local(
            se_proc::native_ipc::UnixSocketPaths::default()
                .expected_path(directory)
                .map_err(crate::client::lease::native_error)?,
        )?))
    }
    #[cfg(windows)]
    {
        address(directory)
    }
}
#[cfg(windows)]
fn address(directory: &std::path::Path) -> Result<IpcEndpoint> {
    {
        use sha2::Digest;
        let peer =
            se_proc::native_ipc::observe_ipc_self().map_err(crate::client::lease::native_error)?;
        let se_proc::native_ipc::IpcPrincipal::Windows { sid } = peer.principal() else {
            return Err(SeError::invalid("IPC owner", "a native Windows SID"));
        };
        let digest = sha2::Sha256::digest(sid.as_bytes());
        let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let _ = directory;
        Ok(IpcEndpoint::WindowsPipe(format!(
            r"\\.\pipe\stateengine-{hash}"
        )))
    }
}
fn io_error(subject: &str, error: std::io::Error) -> SeError {
    se_core::scope::unreadable(subject, &error.to_string()).with_cause(error)
}

#[derive(Debug)]
struct BootstrapCleanup {
    error: SeError,
    _pending: Vec<SeError>,
}
impl std::fmt::Display for BootstrapCleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for BootstrapCleanup {}
