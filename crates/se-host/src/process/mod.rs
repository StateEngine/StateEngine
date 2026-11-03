//! Host-owned process supervisor. Requests await owned jobs; dropping a client
//! never drops a native lifecycle, accepted write, provider drain or cleanup debt.
mod attach;
mod capture;
mod cold_stop;
mod control;
mod dispatch;
mod events;
mod files;
mod integration;
mod launch;
mod launch_util;
mod native_record;
mod owned;
mod recovery;
mod release;
mod remove;
mod remove_receipt;
mod requests;
mod shutdown;
mod stop;
mod store;
mod supervisor;
pub use recovery::Reconciliation;
pub use shutdown::ProcessDrain;

use crate::{BlockingPool, ClaudeHarness, PreparedRequestProofs, ProviderIoPlatform};
use se_core::config_policy::ConfigFile;
use se_proc::{NativeProcessRuntime, ProcessRuntime};
use se_types::{HostEpoch, NativePath, Result};
use std::{path::PathBuf, sync::Arc};

pub struct ProcessOptions {
    pub helper_executable: NativePath,
    pub linux_delegation: se_proc::LinuxDelegation,
    /// Active native custody slots, including unresolved cleanup. Larger
    /// deployments must explicitly budget their additional per-slot memory.
    pub maximum_sessions: u32,
}
impl ProcessOptions {
    /// Section 30's default native custody budget, independent of stored sessions.
    pub const DEFAULT_MAXIMUM_SESSIONS: u32 = 16;
}
pub struct ProcessConfiguration {
    pub home: PathBuf,
    pub helper_executable: NativePath,
    pub epoch: HostEpoch,
    pub configuration: ConfigFile,
    pub http_port: u16,
    pub linux_delegation: se_proc::LinuxDelegation,
    pub maximum_sessions: u32,
}
pub struct LaunchCoordinator {
    native: Arc<NativeProcessRuntime>,
    io: Arc<dyn ProviderIoPlatform>,
    harness: Arc<ClaudeHarness>,
    options: ProcessConfiguration,
    store: store::Store,
    owner: se_proc::ProcessIdentity,
    human: se_types::HumanId,
    host: se_proc::HostInstanceId,
    jobs: supervisor::Jobs,
    activity: tokio::sync::watch::Sender<u32>,
    controls: requests::Controls,
    capture: crate::runtime::CaptureHandle,
    proofs: PreparedRequestProofs,
    stopping: std::sync::atomic::AtomicBool,
    orphans: std::sync::Mutex<std::collections::BTreeSet<se_types::LifecycleId>>,
}
impl LaunchCoordinator {
    pub fn prepared_request_proofs(&self) -> PreparedRequestProofs {
        self.proofs.clone()
    }

    /// Compose the one startup order: bind, install, take the protected
    /// inventory and reconcile it before the caller publishes readiness.
    pub async fn install(
        host_runtime: &mut crate::HostedRuntime,
        requested: ProcessOptions,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<(Arc<Self>, Reconciliation)> {
        host_runtime.bind_loopback()?;
        let coordinator = Self::open(host_runtime, requested, deadline).await?;
        host_runtime.install_prepared_request_proofs(coordinator.prepared_request_proofs())?;
        host_runtime.install_custody(
            Arc::new(coordinator.clone()),
            coordinator.subscribe_activity(),
        )?;
        let inventory = host_runtime.take_retained_custody();
        let report = coordinator.reconcile(inventory, deadline).await?;
        Ok((coordinator, report))
    }
    /// Called once, after loopback listener publication selected its actual
    /// port and before accepting process operations. All native setup is finite.
    pub async fn open(
        host_runtime: &crate::HostedRuntime,
        requested: ProcessOptions,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Arc<Self>> {
        let context = host_runtime.execution_context();
        let options = ProcessConfiguration {
            home: host_runtime.state_directory.clone(),
            helper_executable: requested.helper_executable,
            epoch: host_runtime.epoch.clone(),
            configuration: host_runtime.configuration().cloned().ok_or_else(|| {
                se_core::scope::unreadable(
                    "process configuration",
                    "load the data home's validated configuration before launch",
                )
            })?,
            http_port: host_runtime.http_port().ok_or_else(|| {
                se_core::scope::unreadable(
                    "process coordinator",
                    "bind the real loopback listener before installation",
                )
            })?,
            linux_delegation: requested.linux_delegation,
            maximum_sessions: requested.maximum_sessions,
        };
        let pool = context.blocking.clone();
        #[cfg(unix)]
        let runtime = pool.handle();
        let machine = options.epoch.owner.fields().machine.clone();
        let helper = options.helper_executable.to_local()?;
        let delegation = options.linux_delegation.clone();
        let maximum = options.maximum_sessions;
        let mut host = [0; 16];
        se_proc::fill_entropy(&mut host).map_err(|e| error("host process identity", e))?;
        let host = se_proc::HostInstanceId(host);
        let (native, owner) = pool
            .run_owned(deadline, move || {
                let identity = se_proc::current_runtime_identity(machine.clone())
                    .map_err(|e| error("native host identity", e))?;
                let native = NativeProcessRuntime::open(se_proc::HostConfig {
                    machine,
                    instance: host,
                    helper_executable: helper,
                    linux_delegation: delegation,
                    limits: se_proc::ResourceLimits {
                        max_lifecycles: maximum,
                        max_diagnostic_members: 128,
                        max_observation_bytes: 1024 * 1024,
                        max_stdio_buffer_bytes: 4 * 1024 * 1024,
                    },
                    #[cfg(unix)]
                    reactor: Arc::new(events::Reactor { runtime }),
                })
                .map_err(|e| error("native process arena", e))?;
                Ok((Arc::new(native), identity.process))
            })
            .await?;
        #[cfg(unix)]
        let io: Arc<dyn ProviderIoPlatform> = Arc::new(crate::UnixProviderIo);
        #[cfg(windows)]
        let io: Arc<dyn ProviderIoPlatform> = Arc::new(crate::WindowsProviderIo::new(
            native.clone(),
            se_proc::StdioLimits {
                max_read_bytes: 256 * 1024,
                max_write_bytes: 1024 * 1024,
                max_buffer_bytes: 4 * 1024 * 1024,
            },
        ));
        let harness = Arc::new(ClaudeHarness::new(
            io.clone(),
            options.helper_executable.to_local()?,
            options.home.clone(),
            options.http_port,
        ));
        Ok(Arc::new(Self {
            native,
            io,
            harness,
            store: store::Store {
                reader: context.reader.clone(),
                writer: context.writer.clone(),
                pool: context.blocking.clone(),
                generation: context.generation,
                pending: context.pending_writes.clone(),
            },
            options,
            capture: host_runtime.capture_handle(),
            proofs: PreparedRequestProofs::new(maximum),
            owner,
            human: host_runtime.owner.clone(),
            host,
            jobs: supervisor::Jobs::default(),
            activity: tokio::sync::watch::channel(0).0,
            controls: requests::Controls::default(),
            stopping: std::sync::atomic::AtomicBool::new(false),
            orphans: std::sync::Mutex::default(),
        }))
    }
}
fn error(subject: &str, cause: impl std::fmt::Debug) -> se_types::SeError {
    se_core::scope::unreadable(subject, &format!("{cause:?}"))
}
