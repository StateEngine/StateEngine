//! Private standalone/embedded entry preparation. Installed CLI creates the
//! runtime only after initialization; embedded callers supply their own Handle.
use super::*;
use crate::client::lease::Deadline;
use crate::state_files::{FilePolicy, Files};
use se_core::store_error::store_error;
use se_store::{HostStore, ReadStore, RuntimeLease, StateFiles, StoreFactory, WriterOwner};
use se_types::{Generation, HostEpoch, Read, Result, SeError};
use std::{fs::File, num::NonZeroU32, path::PathBuf, sync::Arc, time::Duration};
use tokio::runtime::Handle;

/// The launched host's store wait. The background checkpoint's TRUNCATE holds
/// the WAL write lock across its whole copy-and-fsync of up to 64 MiB; at 250
/// ms an ordinary write refused under runner load ("store-busy after 0 ms",
/// issue #196). One second rides out that hold, stays within the store's 5000
/// ms bound and the stop protocol's deadline. A caller that wants the typed
/// StoreBusy refusal must keep its own deadline strictly above this wait:
/// with equal clocks the caller deadline can win under load and report
/// commit-outcome-unknown for a write that never ran.
pub const HOST_STORE_BUSY_TIMEOUT: Duration = Duration::from_millis(1000);

/// Receipt of the required startup-only native initialization. Construct this
/// before configuration/store access or worker creation in the process entry.
pub struct HostProcessInitialization {
    _native: se_proc::FileOwnerInitialization,
}
pub fn initialize_host_process() -> Result<HostProcessInitialization> {
    se_proc::initialize_file_creation_owner()
        .map(|_native| HostProcessInitialization { _native })
        .map_err(|error| {
            se_core::scope::unreadable("host file-owner initialization", &error.to_string())
                .with_cause(error)
        })
}
pub struct HostStart {
    pub state_directory: PathBuf,
    /// Allocated from the caller's native current-process observation, never IPC.
    pub epoch: HostEpoch,
    pub kind: crate::HostKind,
    pub writer: se_store::WriterOptions,
    pub limits: crate::HostLimits,
}
/// Exclusive OS lock retained by every writer reference. There is no destructor
/// that removes lock files, unlinks another endpoint, or changes file protection.
pub struct HostLease {
    pub(crate) files: Files,
    identity: se_store::LeaseIdentity,
    _lock: File,
}
impl RuntimeLease for HostLease {
    fn identity(&self) -> se_store::StoreResult<se_store::LeaseIdentity> {
        Ok(self.identity.clone())
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}
pub struct HostedRuntime {
    #[cfg(target_os = "linux")]
    pub(super) atlas_owner: Option<Arc<super::atlas_owner::Service>>,
    pub(crate) channels: Arc<std::sync::OnceLock<Arc<crate::channels::Channels>>>,
    pub(crate) channel_transport: Option<Arc<dyn crate::channels::ChannelTransport>>,
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) memory_reclaim: Option<super::memory::MemoryReclaim>,
    #[cfg(unix)]
    pub(crate) socket_paths: se_proc::native_ipc::UnixSocketPaths,
    pub(crate) execution: ExecutionContext,
    pub(crate) sources: TranscriptBindings,
    pub(crate) admission_reads: se_store::ReadPhasePool,
    pub(crate) configuration: Option<se_config::config_policy::ConfigFile>,
    pub(crate) configuration_file: Option<PathBuf>,
    pub(crate) prepared_requests: Arc<std::sync::OnceLock<crate::PreparedRequestProofs>>,
    pub(crate) writer: Option<se_store::SqliteWriter>,
    pub(crate) drain: Option<std::pin::Pin<Box<super::drain::WriterDrain>>>,
    pub(crate) drained: Option<se_store::SqliteHost>,
    pub(crate) flush: Option<se_store::FlushReport>,
    pub(crate) storage_report: Option<StorageDrainReport>,
    pub(crate) shutdown_deadline: Option<Deadline>,
    pub(crate) lease: Arc<HostLease>,
    pub(crate) epoch: HostEpoch,
    pub(crate) phase: crate::HostPhase,
    pub(crate) connection_failures: Option<u64>,
    pub(crate) last_connection_error: Option<se_types::ErrorBody>,
    pub(crate) fenced: Arc<std::sync::atomic::AtomicBool>,
    /// Trusted capture stays open after request admission closes, so the
    /// coordinator's shutdown can make its final capture; storage drain fences it.
    pub(crate) capture_fenced: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) response_bytes: std::num::NonZeroU32,
    pub(crate) limits: crate::HostLimits,
    pub(crate) state_directory: PathBuf,
    pub(crate) owner: se_types::HumanId,
    pub(crate) kind: crate::HostKind,
    pub(crate) image_sha256: se_types::Sha256,
    /// Set once by serve when its loopback HTTP listener is bound.
    pub(crate) http_port: Arc<std::sync::OnceLock<u16>>,
    /// Bound before publication; serve takes it.
    pub(crate) http: Option<crate::HttpListener>,
    /// Native custody the store recorded before this generation took ownership,
    /// handed once to the coordinator's reconciliation.
    pub(crate) retained_custody: Option<Vec<se_store::OwnerGuardProcess>>,
    /// An embedder's in-process stop request, consumed by serve.
    pub(crate) local_stop: Option<tokio::sync::watch::Receiver<bool>>,
    /// Started on demand rather than by an explicit `se up`.
    pub(crate) auto_start: bool,
    /// The launch coordinator's activity count, attached before serve.
    pub(crate) activity: Option<tokio::sync::watch::Receiver<u32>>,
}
impl HostedRuntime {
    /// Explicit executable/embedding inputs; the library never reads ambient
    /// XDG_RUNTIME_DIR or TMPDIR. Resolve these before listener publication.
    #[cfg(unix)]
    pub fn configure_unix_socket_paths(
        &mut self,
        paths: se_proc::native_ipc::UnixSocketPaths,
    ) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared {
            return Err(SeError::invalid(
                "runtime socket paths",
                "explicit paths before listener publication",
            ));
        }
        self.socket_paths = paths;
        Ok(())
    }
    /// File and SQLite work run as one finite startup job before listener
    /// publication. Open never initializes missing state or invents a discovered G.
    pub async fn prepare(
        _initialized: HostProcessInitialization,
        options: HostStart,
        runtime: Handle,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Self> {
        let blocking = BlockingPool::with_jobs(runtime, options.limits.blocking_jobs)?;
        let work_pool = blocking.clone();
        let work_deadline = deadline.clone();
        blocking
            .run_owned(deadline, move || prepare(options, work_pool, work_deadline))
            .await
    }
    pub fn configure(&mut self, configuration: se_config::config_policy::ConfigFile) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared {
            return Err(SeError::invalid(
                "host configuration",
                "resolved configuration before listener publication",
            ));
        }
        configuration.validate()?;
        self.configuration = Some(configuration);
        self.configuration_file = None;
        Ok(())
    }
    /// Attach validated configuration and the exact file selected by the entry
    /// adapter. Embedded callers without a file continue to use `configure`.
    pub fn configure_file(
        &mut self,
        configuration: se_config::config_policy::ConfigFile,
        file: PathBuf,
    ) -> Result<()> {
        if !file.is_absolute() {
            return Err(SeError::invalid(
                "configuration file",
                "an absolute selected path",
            ));
        }
        self.configure(configuration)?;
        self.configuration_file = Some(file);
        Ok(())
    }
    pub fn blocking_pool(&self) -> BlockingPool {
        self.execution.blocking.clone()
    }
    pub fn generation(&self) -> Generation {
        self.execution.generation
    }
    pub fn epoch(&self) -> &HostEpoch {
        &self.epoch
    }
    pub fn phase(&self) -> crate::HostPhase {
        self.phase
    }
    /// The loopback MCP port, once serve has bound it; None before that.
    pub fn http_port(&self) -> Option<u16> {
        self.http_port.get().copied()
    }
}
fn present<T>(read: Read<T>, subject: &str) -> Result<T> {
    match read {
        Read::Present { value } => Ok(value),
        Read::Absent { checked } => Err(se_core::scope::unreadable(
            subject,
            &format!("absent ({checked}); run explicit se init"),
        )),
        Read::Unreadable { reason, .. } => Err(se_core::scope::unreadable(subject, &reason)),
        Read::Unknown { what } => Err(se_core::scope::unreadable(subject, &what)),
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn prepare(
    options: HostStart,
    blocking: BlockingPool,
    deadline: crate::client::lease::Deadline,
) -> Result<HostedRuntime> {
    deadline.remaining()?;
    if options.limits.response_bytes.get() as usize > crate::client::wire::MAX_FRAME_BYTES
        || options.limits.active_connections.get() > 256
        || options.limits.preauth_connections.get() > 64
        || options.limits.preauth_connections > options.limits.active_connections
    {
        return Err(SeError::invalid(
            "host ingress limits",
            "at most 1 MiB per reply, 256 active connections and min(active,64) pending handshakes",
        ));
    }
    let files = Files::open_with_policy(&options.state_directory, FilePolicy::Host)
        .map_err(|e| store_error(&e))?;
    let lock_path = options.state_directory.join("runtime.lock");
    let lock = present(
        files.readback(&lock_path).map_err(|e| store_error(&e))?,
        "runtime lock",
    )?;
    acquire_runtime_lease(&lock, &deadline)?;
    let store_options = se_store::StoreOptions {
        state_directory: options.state_directory.clone(),
        busy_timeout: HOST_STORE_BUSY_TIMEOUT,
    };
    // The legacy one-core split can run foreground and maintenance together.
    // Every other configuration shares its finite-work budget with these reads.
    let reader_capacity = options
        .limits
        .blocking_jobs
        .max(NonZeroU32::MIN.saturating_add(1));
    let reader = present(
        se_store::SqliteFactory::open_reader_with_capacity(&store_options, reader_capacity)
            .map_err(|e| store_error(&e))?,
        "state store",
    )?;
    let admission_reads = reader
        .phase_pool(super::admission_reads::pin)
        .map_err(|error| store_error(&error))?;
    let inventory = reader
        .owner_guard(&files, owner_budget()?)
        .map_err(|e| store_error(&e))?;
    let [owner] = inventory.owners.as_slice() else {
        return Err(SeError::invalid("host owner", "one protected store owner"));
    };
    // Recorded native custody is the Come back case after a crash or with a
    // live agent. It is retained for the coordinator's reconciliation, which
    // runs before readiness; it never blocks taking ownership.
    let retained_custody = inventory.processes.clone();
    deadline.remaining()?;
    let old = reader.runtime_owner().map_err(|e| store_error(&e))?;
    let (previous, expected) = match old {
        Read::Present { value } => (
            Some(value.generation),
            se_store::Expected::Revision(value.revision),
        ),
        Read::Absent { .. } => (None, se_store::Expected::Absent),
        Read::Unreadable { reason, .. } => {
            return Err(se_core::scope::unreadable("runtime owner", &reason));
        }
        Read::Unknown { what } => return Err(se_core::scope::unreadable("runtime owner", &what)),
    };
    let next = previous
        .map_or(Some(1), |generation| generation.get().checked_add(1))
        .filter(|g| *g <= i64::MAX as u64)
        .ok_or_else(|| {
            SeError::invalid("runtime generation", "an available monotonic generation")
        })?;
    let generation = Generation::new(next)?;
    let lease = Arc::new(HostLease {
        files,
        identity: se_store::LeaseIdentity {
            store: Some(inventory.store.id.clone()),
            generation: next,
            mode: se_store::LeaseMode::Host,
        },
        _lock: lock,
    });
    let peer =
        se_proc::native_ipc::observe_ipc_self().map_err(crate::client::lease::native_error)?;
    peer.verify_instance(&options.epoch.owner, peer.image_sha256())
        .map_err(crate::client::lease::native_error)?;
    let mut host = present(
        se_store::SqliteFactory::open_host(&store_options, lease.as_ref())
            .map_err(|e| store_error(&e))?,
        "host store",
    )?;
    let facts = allocate_facts()?;
    let admission = se_store::Admission {
        scope: se_store::Scope::Registry,
        actor: se_store::Actor::Human(owner.clone()),
        session: None,
        generation: next,
    };
    deadline.remaining()?;
    host.record_runtime_ownership(
        se_store::AtomicBatch {
            expected_incarnation: inventory.store.incarnation,
            admission: admission.clone(),
            request: None,
            import_checkpoint: None,
            events: vec![se_store::NewEvent {
                header: se_store::EventHeader {
                    event: facts.event,
                    scope: admission.scope,
                    actor: admission.actor,
                    session: None,
                    origin: inventory.store.id,
                    door: se_store::Door::Host,
                    occurred_at_us: facts.occurred_at_us,
                    cause: None,
                    supersedes: None,
                },
                body: se_store::EventBody::RuntimeOwnerEstablished {
                    epoch: options.epoch.clone(),
                    generation,
                    expected_owner_generation: previous,
                    expected,
                    witnesses: vec![],
                    recovered: None,
                },
            }],
        },
        lease.as_ref(),
    )
    .map_err(|e| store_error(&e))?;
    // Ownership is committed. Return its writer/lease custody even if the
    // native commit consumed the final part of the admission budget.
    // A commit group's limit is smaller than total admitted outstanding work.
    let pending_writes =
        super::failure::PendingWrites::new(options.writer.queue_requests.get() as usize);
    let writer = host
        .start_writer(options.writer, lease.clone())
        .map_err(|e| store_error(&e))?;
    let execution = ExecutionContext {
        atlas: Arc::default(),
        mail_waits: crate::http::mail::Waits::new(options.limits.sessions.get() as usize),
        http_proofs: Arc::default(),
        state_directory: options.state_directory.clone(),
        reader: Arc::new(reader),
        reads: admission_reads.clone(),
        writer: writer.client(),
        blocking,
        generation,
        pending_writes,
        custody: Arc::default(),
        ownership_fault: Arc::default(),
    };
    Ok(HostedRuntime {
        #[cfg(target_os = "linux")]
        atlas_owner: None,
        channels: Arc::default(),
        channel_transport: None,
        #[cfg(unix)]
        socket_paths: Default::default(),
        execution,
        admission_reads,
        configuration: None,
        configuration_file: None,
        prepared_requests: Arc::default(),
        writer: Some(writer),
        drain: None,
        drained: None,
        flush: None,
        storage_report: None,
        shutdown_deadline: None,
        lease,
        epoch: options.epoch,
        phase: crate::HostPhase::Prepared,
        connection_failures: Some(0),
        last_connection_error: None,
        fenced: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        capture_fenced: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        sources: TranscriptBindings::new(options.limits.sessions.get() as usize),
        response_bytes: options.limits.response_bytes,
        limits: options.limits,
        state_directory: options.state_directory,
        owner: owner.clone(),
        kind: options.kind,
        image_sha256: peer.image_sha256(),
        http_port: Arc::default(),
        http: None,
        retained_custody: Some(retained_custody),
        local_stop: None,
        auto_start: false,
        activity: None,
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        memory_reclaim: matches!(options.kind, crate::HostKind::Standalone)
            .then(super::memory::MemoryReclaim::default),
    })
}
pub(crate) fn owner_budget() -> Result<se_store::ReadBudget> {
    Ok(se_store::ReadBudget {
        page: se_types::PageRequest {
            after: None,
            limit: std::num::NonZeroU32::new(1000)
                .ok_or_else(|| SeError::invalid("owner budget", "positive items"))?,
            max_bytes: std::num::NonZeroU32::new(2 * 1024 * 1024)
                .ok_or_else(|| SeError::invalid("owner budget", "positive bytes"))?,
        },
        deadline: Duration::from_secs(5),
    })
}
pub(crate) fn allocate_facts() -> Result<se_core::dispatch::CallFacts> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| se_core::scope::unreadable("system clock", &e.to_string()))?;
    let mut random = [0; 40];
    se_proc::fill_entropy(&mut random)
        .map_err(|e| se_core::scope::unreadable("host identity entropy", &e.to_string()))?;
    let mut event = [0; 10];
    event.copy_from_slice(&random[..10]);
    let mut message = [0; 10];
    message.copy_from_slice(&random[10..20]);
    let mut agent = [0; 10];
    agent.copy_from_slice(&random[20..30]);
    let mut profile_event = [0; 10];
    profile_event.copy_from_slice(&random[30..]);
    Ok(se_core::dispatch::CallFacts {
        event: se_types::EventId::from_parts(time.as_millis() as u64, event)?,
        message: se_types::MessageId::from_parts(time.as_millis() as u64, message)?,
        agent: se_types::AgentId::from_parts(time.as_millis() as u64, agent)?,
        profile_event: se_types::EventId::from_parts(time.as_millis() as u64, profile_event)?,
        occurred_at_us: i64::try_from(time.as_micros())
            .map_err(|_| SeError::invalid("system clock", "representable microseconds"))?,
        door: se_store::Door::Host,
    })
}

pub(crate) fn now_unix_micros() -> Result<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| se_core::scope::unreadable("system clock", &error.to_string()))?;
    i64::try_from(elapsed.as_micros())
        .map_err(|_| SeError::invalid("system clock", "representable Unix microseconds"))
}

fn acquire_runtime_lease(
    lock: &std::fs::File,
    deadline: &crate::client::lease::Deadline,
) -> Result<()> {
    // A finite direct read can win the gap between the parent's rendezvous
    // observation and this child acquiring its writer lease. Wait inside the
    // original preparation deadline; no store work precedes exclusive custody.
    // A competing writer must refuse immediately so its parent can rendezvous
    // with the winner instead of leaving a successor queued behind its lease.
    loop {
        deadline.remaining()?;
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                match lock.try_lock_shared() {
                    Ok(()) => lock.unlock().map_err(|error| {
                        se_core::scope::unreadable(
                            "startup reader lease release",
                            &error.to_string(),
                        )
                    })?,
                    Err(std::fs::TryLockError::WouldBlock) => {
                        return Err(SeError::new(se_types::Detail::StateConflict(
                            se_types::details::StateConflict {
                                subject: "runtime lease".into(),
                                reason: "Another writer holds the runtime lease".into(),
                                next_step: "Use se status for this data home; use the existing host or retry se up after it stops".into(),
                            },
                        )));
                    }
                    Err(std::fs::TryLockError::Error(error)) => {
                        return Err(se_core::scope::unreadable(
                            "exclusive runtime lease",
                            &error.to_string(),
                        ));
                    }
                }
                std::thread::sleep(deadline.remaining()?.min(Duration::from_millis(10)));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(se_core::scope::unreadable(
                    "exclusive runtime lease",
                    &error.to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::HOST_STORE_BUSY_TIMEOUT;
    use std::time::Duration;

    #[test]
    fn the_host_store_wait_rides_out_a_checkpoint_truncate() {
        assert_eq!(HOST_STORE_BUSY_TIMEOUT.as_millis(), 1000);
        assert!(HOST_STORE_BUSY_TIMEOUT <= Duration::from_secs(5));
    }
}
