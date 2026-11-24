//! Host-owned process supervisor. Requests await owned jobs; dropping a client
//! never drops a native lifecycle, accepted write, provider drain or cleanup debt.
mod acp;
mod attach;
mod attended;
mod capture;
mod catch_up;
mod codex_capture;
pub(crate) mod codex_server;
mod cold_stop;
mod control;
mod delegate;
mod dispatch;
mod embedded_stop;
mod ephemeral;
mod events;
mod files;
mod git_workspace;
mod integration;
mod launch;
pub(crate) mod launch_util;
mod mail;
mod monitor;
mod native_record;
mod nudge;
mod owned;
mod provider_status;
#[cfg(unix)]
mod reactor;
mod readiness;
mod recovery;
mod release;
#[cfg(feature = "remote")]
mod remote_launch;
#[cfg(feature = "remote")]
mod remote_live;
mod remove;
mod remove_receipt;
mod requests;
mod resume_source;
#[path = "../secode_service/mod.rs"]
mod secode;
mod shutdown;
mod startup_stop;
mod status;
mod stop;
pub(crate) mod store;
mod supervisor;
mod takeover;
mod tasks;
mod wake;
mod window;
#[cfg(target_os = "linux")]
mod window_join;
pub use monitor::mail_wake_interval;
pub use recovery::Reconciliation;
pub use shutdown::ProcessDrain;

use crate::{ClaudeHarness, CodexHarness, PreparedRequestProofs, ProviderIoPlatform};
use se_config::config_policy::ConfigFile;
use se_proc::{NativeProcessRuntime, ProcessRuntime};
use se_types::{HostEpoch, NativePath, Result};
use std::{path::PathBuf, sync::Arc};

pub struct ProcessOptions {
    pub helper_executable: NativePath,
    pub linux_delegation: se_proc::LinuxDelegation,
    /// Active native custody slots, including unresolved cleanup. Larger
    /// deployments must explicitly budget their additional per-slot memory.
    pub maximum_sessions: u32,
    /// Window in which a restarted host restores control of the original
    /// live provider after a native crash. Independent judges shorten it at
    /// spawn; the production default stays 20 s.
    pub restore_deadline_ms: u64,
    /// Window given to a headless provider to exit after stdin closure before
    /// forced stop. `None` keeps the production default; an explicit value is
    /// capped by the stop budget at the staging site.
    pub stop_grace_ms: Option<u32>,
}
impl ProcessOptions {
    /// Section 30's default native custody budget, independent of stored sessions.
    pub const DEFAULT_MAXIMUM_SESSIONS: u32 = 16;
    /// Default provider-control restore window.
    pub const DEFAULT_RESTORE_DEADLINE_MS: u64 = 20_000;
    /// Upper bound for an explicitly injected restore window.
    pub const MAX_RESTORE_DEADLINE_MS: u64 = 3_600_000;
    /// Default provider graceful-stop window before forced stop.
    pub const DEFAULT_STOP_GRACE_MS: u32 = 5_000;
    /// Upper bound for an explicitly injected graceful-stop window.
    pub const MAX_STOP_GRACE_MS: u32 = 3_600_000;
}
pub struct ProcessConfiguration {
    pub home: PathBuf,
    pub helper_executable: NativePath,
    pub epoch: HostEpoch,
    pub configuration: ConfigFile,
    pub http_port: u16,
    pub linux_delegation: se_proc::LinuxDelegation,
    pub maximum_sessions: u32,
    pub restore_deadline_ms: u64,
    pub stop_grace_ms: Option<u32>,
}
pub struct LaunchCoordinator {
    #[cfg(any(windows, target_os = "macos"))]
    repository_watches: std::sync::Mutex<Vec<se_repository::RepositoryWatch>>,
    kind: crate::HostKind,
    native: Arc<NativeProcessRuntime>,
    io: Arc<dyn ProviderIoPlatform>,
    harness: Arc<ClaudeHarness>,
    codex: Arc<CodexHarness>,
    secode: Arc<crate::harness::secode_process::SecodeHarness>,
    acp: Arc<crate::harness::acp::AcpHarness>,
    secode_services: secode::Services,
    codex_server: codex_server::CodexServer,
    options: ProcessConfiguration,
    configuration_file: Option<PathBuf>,
    store: store::Store,
    capability_admission: crate::runtime::AdmissionContext,
    owner: se_proc::ProcessIdentity,
    human: se_types::HumanId,
    host: se_proc::HostInstanceId,
    jobs: supervisor::Jobs,
    activity: tokio::sync::watch::Sender<u32>,
    controls: requests::Controls,
    capture: crate::runtime::CaptureHandle,
    atlas: Arc<crate::atlas_runtime::read_port::AtlasOwnerPort>,
    proofs: PreparedRequestProofs,
    stopping: std::sync::atomic::AtomicBool,
    orphans: std::sync::Mutex<std::collections::BTreeSet<se_types::LifecycleId>>,
    ephemeral_ttl: Arc<ephemeral::TtlTimer>,
    delegate_create_lock: tokio::sync::Mutex<()>,
}
struct ProviderHarnesses {
    claude: Arc<ClaudeHarness>,
    codex: Arc<CodexHarness>,
    secode: Arc<crate::harness::secode_process::SecodeHarness>,
    acp: Arc<crate::harness::acp::AcpHarness>,
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
        let service_failures = coordinator.recover_secode_services(deadline).await?;
        let mut report = coordinator.reconcile(inventory, deadline).await?;
        report.unproved.extend(service_failures);
        if let Err(failure) = coordinator.adopt_recorded_codex_server(deadline).await {
            report
                .unproved
                .push(format!("Codex shared server custody: {}", failure.body));
        }
        match coordinator.sweep_ephemeral_expired(deadline).await {
            Ok(Some(next_delay)) => coordinator.arm_ephemeral_ttl(next_delay),
            Ok(None) => {}
            Err(failure) => {
                report
                    .unproved
                    .push(format!("Ephemeral TTL sweep: {}", failure.body));
                coordinator.arm_ephemeral_ttl(ephemeral::SWEEP_RETRY_INTERVAL);
            }
        }
        coordinator.watch_codex_server();
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
        let options = Self::process_configuration(host_runtime, requested)?;
        let pool = context.blocking.clone();
        let maximum = options.maximum_sessions;
        let helper = options.helper_executable.to_local()?;
        let mut host = [0; 16];
        se_proc::fill_entropy(&mut host).map_err(|e| error("host process identity", e))?;
        let host = se_proc::HostInstanceId(host);
        let (native, owner) = Self::open_native_runtime(
            &pool,
            &options,
            #[cfg(unix)]
            &context,
            helper,
            #[cfg(unix)]
            host_runtime.fenced.clone(),
            deadline,
            host,
        )
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
        let providers = Self::provider_harnesses(
            #[cfg(unix)]
            host_runtime,
            io.clone(),
            &pool,
            &options,
            &context,
            maximum,
        )?;
        Ok(Arc::new(Self {
            #[cfg(any(windows, target_os = "macos"))]
            repository_watches: std::sync::Mutex::new(Vec::new()),
            kind: host_runtime.kind,
            native,
            io,
            harness: providers.claude,
            codex: providers.codex,
            secode: providers.secode,
            acp: providers.acp,
            secode_services: secode::Services::default(),
            codex_server: codex_server::CodexServer::default(),
            // Installation precedes readiness; retain admission without opening a router.
            capability_admission: host_runtime.admission_context(),
            store: store::Store::for_execution(&context),
            options,
            configuration_file: host_runtime.configuration_file.clone(),
            capture: host_runtime.capture_handle(),
            atlas: context.atlas.clone(),
            proofs: PreparedRequestProofs::new(maximum),
            owner,
            human: host_runtime.owner.clone(),
            host,
            jobs: supervisor::Jobs::default(),
            activity: tokio::sync::watch::channel(0).0,
            controls: requests::Controls::default(),
            stopping: std::sync::atomic::AtomicBool::new(false),
            orphans: std::sync::Mutex::default(),
            ephemeral_ttl: Arc::new(ephemeral::TtlTimer::new()),
            delegate_create_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// Compose the process configuration from the runtime and requested options.
    fn process_configuration(
        host_runtime: &crate::HostedRuntime,
        requested: ProcessOptions,
    ) -> Result<ProcessConfiguration> {
        Ok(ProcessConfiguration {
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
            restore_deadline_ms: requested.restore_deadline_ms,
            stop_grace_ms: requested.stop_grace_ms,
        })
    }
    /// Open the native process arena and read the live runtime identity.
    async fn open_native_runtime(
        pool: &crate::BlockingPool,
        options: &ProcessConfiguration,
        #[cfg(unix)] context: &crate::runtime::ExecutionContext,
        helper: PathBuf,
        #[cfg(unix)] fence: Arc<std::sync::atomic::AtomicBool>,
        deadline: &crate::client::lease::Deadline,
        host: se_proc::HostInstanceId,
    ) -> Result<(Arc<NativeProcessRuntime>, se_proc::ProcessIdentity)> {
        let machine = options.epoch.owner.fields().machine.clone();
        let delegation = options.linux_delegation.clone();
        let maximum = options.maximum_sessions;
        #[cfg(unix)]
        let runtime = pool.handle();
        #[cfg(unix)]
        let fault = context.ownership_fault.clone();
        pool.run_owned(deadline, move || {
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
                reactor: Arc::new(events::Reactor {
                    runtime,
                    fault,
                    fence,
                }),
            })
            .map_err(|e| error("native process arena", e))?;
            Ok((Arc::new(native), identity.process))
        })
        .await
    }
    /// Build the provider harnesses over the shared IO platform.
    fn provider_harnesses(
        #[cfg(unix)] host_runtime: &crate::HostedRuntime,
        io: Arc<dyn ProviderIoPlatform>,
        pool: &crate::BlockingPool,
        options: &ProcessConfiguration,
        context: &crate::runtime::ExecutionContext,
        maximum: u32,
    ) -> Result<ProviderHarnesses> {
        #[cfg(unix)]
        let socket_root = host_runtime
            .socket_paths
            .runtime_directory
            .clone()
            .or_else(|| host_runtime.socket_paths.temporary_directory.clone())
            .unwrap_or_else(std::env::temp_dir);
        #[cfg(not(unix))]
        let socket_root = options.home.clone();
        let claude = Arc::new(
            ClaudeHarness::new(
                io.clone(),
                options.helper_executable.to_local()?,
                options.home.clone(),
                options.http_port,
            )
            .with_bells(context.mail_waits.bells.clone())
            .with_atlas_hooks(
                (options.configuration.atlas.enabled && options.configuration.atlas.hooks)
                    .then_some(crate::atlas_hooks::hook_configuration),
            ),
        );
        let codex = Arc::new(
            CodexHarness::new(
                io.clone(),
                pool.clone(),
                options.home.clone(),
                socket_root,
                options.http_port,
                options.configuration.clone(),
            )
            .with_forwarder(options.helper_executable.to_local()?)
            .with_atlas_helper(
                options.helper_executable.to_local()?,
                crate::atlas_hooks::hook_configuration,
            ),
        );
        let secode = Arc::new(crate::harness::secode_process::SecodeHarness::new(
            io.clone(),
            options.home.clone(),
            maximum,
        ));
        let acp = Arc::new(crate::harness::acp::AcpHarness::new(
            io.clone(),
            options.configuration.clone(),
            options.helper_executable.to_local()?,
            options.home.clone(),
            options.http_port,
        ));
        Ok(ProviderHarnesses {
            claude,
            codex,
            secode,
            acp,
        })
    }
}
impl LaunchCoordinator {
    fn harness_for(&self, provider: se_store::Provider) -> Result<&dyn crate::Harness> {
        match provider {
            se_store::Provider::Claude => Ok(self.harness.as_ref()),
            se_store::Provider::Codex => Ok(self.codex.as_ref()),
            se_store::Provider::SeCode => Ok(self.secode.as_ref()),
            se_store::Provider::Acp => Ok(self.acp.as_ref()),
        }
    }
}
fn error(subject: &str, cause: impl std::fmt::Debug) -> se_types::SeError {
    se_core::scope::unreadable(subject, &format!("{cause:?}"))
}
/// A missing recorded root names its remedy instead of a generic unreadable
/// blob: a moved repository re-attaches with `se project move`.
pub(crate) fn prepare_error(e: se_proc::ProcError) -> se_types::SeError {
    let missing_root = matches!(
        e.detail.as_ref(),
        se_proc::ProcErrorDetail::Input { field, reason }
            if e.code == se_proc::ProcErrorCode::LaunchFailed
                && field == "native operation"
                && reason == "resolve cwd"
                && e
                    .native
                    .as_ref()
                    .is_some_and(|n| n.api == "resolve cwd" && n.code == Some(2))
    );
    if missing_root {
        return se_types::SeError::new(se_types::Detail::SourceUnreadable(
            se_types::details::SourceUnreadable {
                subject: "native scope preparation".into(),
                reason: format!("the recorded project root is missing: {e:?}"),
                next_step: "If the repository was renamed or moved, run `se project move <new-folder>` (it verifies the recorded git identity) and retry; otherwise restore the folder at the recorded path and retry.".into(),
            },
        ));
    }
    error("native scope preparation", e)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/support/script_launcher_independent.rs"]
mod script_launcher_independent;
