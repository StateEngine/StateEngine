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

    pub fn endpoint(&self) -> &EndpointRecord {
        &self.publication.record
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
}
impl EndpointPublication {
    fn publish(lease: Arc<HostLease>, directory: PathBuf, record: EndpointRecord) -> Result<Self> {
        let bytes = codec::encode_endpoint(&record)?;
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
        let path = directory.join("endpoint.json");
        lease
            .files()
            .publish_no_replace(&staged.path, &path)
            .map_err(|e| store_error(&e))?;
        let published = Self {
            lease,
            path,
            record,
        };
        published.verify()?;
        Ok(published)
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
            let permit = self.execution.blocking.admit_owned(deadline).await?;
            Ok((listener, permit))
        }
        .await;
        let (listener, permit) = match prepared {
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
        self.execution
            .blocking
            .run_admitted_owned(permit, move || {
                bootstrap.await_commit(instance).map_err(|error| {
                    se_core::scope::unreadable("native runtime commit", &format!("{error:?}"))
                })?;
                Ok(())
            })
            .await?;
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
        let listener = self
            .execution
            .blocking
            .run_owned(deadline, move || {
                let record = EndpointRecord {
                    schema: 1,
                    address: address(&directory)?,
                    epoch,
                    generation,
                    kind,
                    listener_port: None,
                    api: se_types::API_VERSION,
                    package_version: env!("CARGO_PKG_VERSION").into(),
                    image_sha256,
                };
                let listener =
                    IpcListener::bind_with_limits(record.clone(), runtime, slots, &limits)?;
                let publication = match EndpointPublication::publish(lease, directory, record) {
                    Ok(publication) => publication,
                    Err(error) => {
                        listener.close()?;
                        return Err(error);
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
fn address(directory: &std::path::Path) -> Result<IpcEndpoint> {
    #[cfg(unix)]
    {
        Ok(IpcEndpoint::UnixSocket(se_types::NativePath::from_local(
            directory.join("runtime.sock"),
        )?))
    }
    #[cfg(windows)]
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
