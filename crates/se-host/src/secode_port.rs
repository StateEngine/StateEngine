//! Host port adapter connecting `LaunchCoordinator` and `owned::Work` to `se_secode_service`.
#[path = "rebind/service.rs"]
mod rebind;
#[cfg(all(test, feature = "listener", any(target_os = "linux", windows)))]
#[path = "../tests/support/secode_registered_rebind.rs"]
mod registered_rebind_test;
#[path = "rebind/mail.rs"]
mod restart_mail;

use super::*;
use crate::client::lease::Deadline;
#[cfg(all(test, feature = "listener", any(target_os = "linux", windows)))]
use se_secode_service::{Auxiliary, custody::Journal};
use se_secode_service::{
    Coordinator, HostPort, PendingRestart, PortFuture, SecodeWork, Service, ServiceSlot,
    lock_service,
};
pub(in crate::process) use se_secode_service::{Prepared, RestartControl, Services, custody, mail};
use se_types::Result;
use std::path::{Path, PathBuf};

#[cfg(all(test, feature = "listener", any(target_os = "linux", windows)))]
pub(super) struct AuxiliaryLaunch {
    pub auxiliary: Auxiliary,
    pub executable: se_proc::NativeExecutableInvocation,
    pub arguments: Vec<std::ffi::OsString>,
    pub cwd: PathBuf,
    pub policy: se_proc::LaunchPolicy,
    pub input: Option<se_types::Secret>,
}

impl HostPort for LaunchCoordinator {
    fn services(&self) -> &Services {
        &self.secode_services
    }
    fn native(&self) -> &Arc<NativeProcessRuntime> {
        &self.native
    }
    fn io(&self) -> &Arc<dyn ProviderIoPlatform> {
        &self.io
    }
    fn secode_harness(&self) -> &Arc<crate::harness::secode_process::SecodeHarness> {
        &self.secode
    }
    fn owner(&self) -> &se_proc::ProcessIdentity {
        &self.owner
    }
    fn host_id(&self) -> se_proc::HostInstanceId {
        self.host
    }
    fn home(&self) -> &Path {
        &self.options.home
    }
    fn epoch(&self) -> &se_types::HostEpoch {
        &self.options.epoch
    }
    fn generation(&self) -> se_types::Generation {
        self.store.generation
    }
    fn configuration(&self) -> &se_config::config_policy::ConfigFile {
        &self.options.configuration
    }
    fn configuration_file(&self) -> Option<&Path> {
        self.configuration_file.as_deref()
    }
    fn http_port(&self) -> u16 {
        self.options.http_port
    }
    fn maximum_sessions(&self) -> u32 {
        self.options.maximum_sessions
    }
    fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.store.pool.handle()
    }
    fn run_blocking<'a, T: Send + 'static>(
        &'a self,
        deadline: &'a Deadline,
        op: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> PortFuture<'a, T> {
        Box::pin(async move { self.store.pool.run_owned(deadline, op).await })
    }
    fn store_read<'a, T: Send + 'static>(
        &'a self,
        admission: se_store::Admission,
        deadline: &'a Deadline,
        op: impl FnOnce(&mut se_core::commit::Cx<'_, se_store::SqliteSnapshot>) -> Result<T>
        + Send
        + 'static,
    ) -> PortFuture<'a, T> {
        Box::pin(async move { self.store.read(admission, deadline, op).await })
    }
    fn commit_step<'a, O: Send + 'static, T: Send + 'static>(
        &'a self,
        admission: se_store::Admission,
        deadline: &'a Deadline,
        plan: impl FnOnce(
            &se_core::dispatch::Kernel,
            &mut se_core::commit::Cx<'_, se_store::SqliteSnapshot>,
        ) -> Result<se_core::commit::OpStep<O, T>>
        + Send
        + 'static,
        finish: impl FnOnce(
            &se_core::dispatch::Kernel,
            &mut se_core::commit::Cx<'_, se_store::SqliteSnapshot>,
            T,
            se_store::CommitReceipt,
        ) -> Result<O>
        + Send
        + 'static,
    ) -> PortFuture<'a, O> {
        Box::pin(async move {
            super::mail::commit::step(&self.store, admission, deadline, plan, finish).await
        })
    }
    fn resolve_secode_provider<'a>(&'a self, deadline: &'a Deadline) -> PortFuture<'a, PathBuf> {
        Box::pin(async move {
            let selected_file = self.configuration_file.clone();
            let configuration = self.options.configuration.clone();
            self.store
                .pool
                .run_owned(deadline, move || {
                    super::launch_util::resolve_provider(
                        &configuration,
                        se_types::Provider::SeCode,
                        selected_file.as_deref(),
                        None,
                    )
                })
                .await
        })
    }
    fn saved_session_capability<'a>(
        &'a self,
        profile: PathBuf,
        policy_hash: Option<se_types::Sha256>,
        expected: crate::SessionIdentity,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, se_types::Secret> {
        Box::pin(async move {
            let authority = self.capability_admission.clone();
            self.store
                .pool
                .run_owned(deadline, move || {
                    authority.saved_session_capability(&profile, policy_hash, &expected)
                })
                .await
        })
    }
    fn is_job_unsettled(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<bool> {
        Ok(self
            .find_job(project, agent)?
            .is_some_and(|job| !job.settled.load(std::sync::atomic::Ordering::Acquire)))
    }
    fn mark_job_mail_pending(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<()> {
        if let Some(job) = self.find_job(project, agent)? {
            job.mail_pending
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }
    fn observe_client_stream(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<se_types::Read<String>> {
        let Some(job) = self.find_job(project, agent)? else {
            return Ok(se_types::Read::Unknown {
                what: "This runtime has no retained original client stream binding.".into(),
            });
        };
        let Ok(work) = job.state.try_lock() else {
            return Ok(se_types::Read::Unknown {
                what: "The original client binding is busy; no stream observation was made.".into(),
            });
        };
        let Some(binding) = work
            .binding
            .as_ref()
            .and_then(|binding| binding.get::<crate::secode_process::Binding>())
        else {
            return Ok(se_types::Read::Absent {
                checked:
                    "The original stream binding has been retired; no replacement pipe was opened."
                        .into(),
            });
        };
        let diagnostics = binding
            .diagnostics
            .lock()
            .map_err(|_| error("SE Code stream observation", "poisoned diagnostics"))?;
        if let Some(failure) = &diagnostics.failure {
            return Ok(se_types::Read::Unreadable {
                source: "original SE Code output".into(),
                reason: se_types::SeError::from(failure.clone()).to_string(),
                error: Some(Box::new(failure.clone())),
            });
        }
        if diagnostics.recovered {
            return Ok(se_types::Read::Absent {
                checked: "The former runtime's streams were lost; authenticated canonical reads continue and no old pipe was reopened.".into(),
            });
        }
        Ok(se_types::Read::Present {
            value: format!(
                "stdout {}; stderr {}; {} retained diagnostic bytes, {} omitted bytes. Stream state does not imply client or service liveness.",
                if diagnostics.output_closed {
                    "closed"
                } else {
                    "open"
                },
                if diagnostics.error_closed {
                    "closed"
                } else {
                    "open"
                },
                diagnostics.stderr.len(),
                diagnostics.omitted_stderr_bytes
            ),
        })
    }
    fn adopt_restart<'a>(
        &'a self,
        service: &'a mut Service,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move { LaunchCoordinator::adopt_restart(self, service, deadline).await })
    }
    fn restore_restart_state<'a>(
        &'a self,
        service: &'a mut Service,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, ()> {
        Box::pin(
            async move { LaunchCoordinator::restore_restart_state(self, service, deadline).await },
        )
    }
    fn verify_captured_end<'a>(
        &'a self,
        admission: se_store::Admission,
        source: se_store::RecordId,
        end: u64,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            LaunchCoordinator::verify_captured_end(self, admission, source, end, deadline).await
        })
    }
    fn native_instance(
        &self,
        root: &se_proc::ProcessIdentity,
        argv: [u8; 32],
        boot: &se_types::BootId,
    ) -> Result<se_types::ProcessInstance> {
        super::native_record::instance(root, argv, boot)
    }

    fn allocate_facts() -> Result<se_core::dispatch::CallFacts> {
        crate::runtime::start::allocate_facts()
    }

    fn open_owned_file(
        path: &Path,
        subject: &str,
        deadline: &Deadline,
    ) -> Result<Option<se_proc::OwnedFile>> {
        use crate::state_files::{Acquisition, AcquisitionRetry};
        let mut retry = AcquisitionRetry::new(deadline.at());
        deadline.remaining()?;
        loop {
            match retry
                .acquire(|| se_proc::OwnedFile::open(path))
                .map_err(|failure| failure.into_public(|native| error(subject, native)))?
            {
                Acquisition::Ready(file) => {
                    deadline.remaining()?;
                    return Ok(file);
                }
                Acquisition::Wait(delay) => {
                    deadline.remaining()?;
                    std::thread::sleep(delay);
                }
            }
        }
    }
}

impl SecodeWork for owned::Work {
    fn project_id(&self) -> &se_types::ProjectId {
        &self.meta.project.id
    }
    fn agent_id(&self) -> &se_types::AgentId {
        &self.meta.agent.id
    }
    fn owner(&self) -> &se_types::HumanId {
        &self.meta.owner
    }
    fn session(&self) -> &se_types::SessionId {
        &self.meta.session
    }
    fn lifecycle(&self) -> &se_types::LifecycleId {
        &self.meta.lifecycle
    }
    fn provider(&self) -> se_store::Provider {
        self.meta.provider
    }
    fn capture_enabled(&self) -> bool {
        self.meta.capture
    }
    fn conversation(&self) -> &se_types::Read<se_types::ProviderSessionId> {
        &self.meta.conversation
    }
    fn set_conversation(&mut self, conversation: se_types::Read<se_types::ProviderSessionId>) {
        self.meta.conversation = conversation;
    }
    fn cleanup_admission(&self) -> &se_store::Admission {
        &self.cleanup_admission
    }
    fn secode(&self) -> Option<&Prepared> {
        self.secode.as_ref()
    }
    fn secode_mut(&mut self) -> &mut Option<Prepared> {
        &mut self.secode
    }
    fn binding_mut(&mut self) -> &mut Option<crate::HarnessBinding> {
        &mut self.binding
    }
    fn secode_service_lost(&self) -> bool {
        self.secode_service_lost
    }
    fn set_secode_service_lost(&mut self, lost: bool) {
        self.secode_service_lost = lost;
    }
    fn capture_source(&self) -> Option<se_store::RecordId> {
        self.capture_source
    }
    fn set_capture_source(&mut self, source: Option<se_store::RecordId>) {
        self.capture_source = source;
    }
    fn set_last_capture(&mut self, event: Option<se_types::EventId>) {
        self.last_capture = event;
    }
    fn capture_failure(&self) -> Option<&se_types::ErrorBody> {
        self.capture_failure.as_ref()
    }
    fn set_capture_failure(&mut self, failure: Option<se_types::ErrorBody>) {
        self.capture_failure = failure;
    }
    fn capture_flushed(&self) -> bool {
        self.capture_flushed
    }
    fn set_capture_flushed(&mut self, flushed: bool) {
        self.capture_flushed = flushed;
    }
    fn set_model(&mut self, model: Option<String>) {
        self.meta.model = model;
    }
    fn process_retired(&self) -> bool {
        self.process_retired
    }
    fn native_already_reconciled(&self) -> bool {
        self.native_already_reconciled
    }
    fn session_retired(&self) -> bool {
        self.session_retired
    }
    fn credentials_revoked(&self) -> bool {
        self.credentials_revoked
    }
    fn active(&self) -> bool {
        self.active
    }
    fn set_active(&mut self, active: bool) {
        self.active = active;
    }
    fn activated(&self) -> bool {
        self.activated
    }
    fn stop_key(&self) -> Option<&se_types::IdempotencyKey> {
        self.stop_key.as_ref()
    }
    fn mail_in_flight(&self) -> bool {
        self.mail.flight.is_some()
    }
    fn nudge_secode_completion(&self) {
        if let Some(binding) = self
            .binding
            .as_ref()
            .and_then(|binding| binding.get::<crate::secode_process::Binding>())
        {
            // Canonical reads remain live even when the original pipe ended.
            binding.completion.nudge();
        }
    }
    fn report_mail_diagnostic(&self, failure: &se_types::SeError) {
        crate::process::mail::diagnostic::report(self, failure);
    }
}

impl LaunchCoordinator {
    /// Direct down/uninstall must recover auxiliary custody even if no client
    /// process remains in the ordinary session inventory.
    pub fn secode_recovery_required(home: &Path, deadline: &Deadline) -> Result<bool> {
        se_secode_service::secode_recovery_required::<LaunchCoordinator>(home, deadline)
    }
    pub(in crate::process) async fn secode_input_intent(
        &self,
        identity: &crate::SessionIdentity,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .secode_input_intent(identity, deadline)
            .await
    }
    pub(in crate::process) async fn preflight_secode(
        &self,
        plan: &se_core::ops::agent_launch::LaunchPlan,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self).preflight_secode(plan, deadline).await
    }
    pub(in crate::process) async fn prepare_secode(
        &self,
        work: &mut owned::Work,
        request: &crate::HarnessRequest,
        images: Arc<std::sync::Mutex<crate::harness::secode_process::Images>>,
        deadline: &Deadline,
    ) -> Result<Prepared> {
        Coordinator(self)
            .prepare_secode(work, request, images, deadline)
            .await
    }
    pub(in crate::process) async fn recover_secode_services(
        &self,
        deadline: &Deadline,
    ) -> Result<Vec<String>> {
        Coordinator(self).recover_secode_services(deadline).await
    }
    pub(in crate::process) async fn restore_secode_work(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self).restore_secode_work(work, deadline).await
    }
    pub(in crate::process) async fn capture_secode(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self).capture_secode(work, deadline).await
    }
    pub(in crate::process) async fn deny_secode_approvals(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .deny_secode_approvals(work, deadline)
            .await
    }
    pub(in crate::process) async fn settle_secode(
        &self,
        work: &mut owned::Work,
        witness: &se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .settle_secode(work, witness, deadline)
            .await
    }
    pub(in crate::process) async fn shutdown_secode(
        &self,
        deadline: &Deadline,
    ) -> Result<Vec<String>> {
        Coordinator(self).shutdown_secode(deadline).await
    }
    pub(in crate::process) async fn secode_client_closed(
        &self,
        work: &mut owned::Work,
        witness: &se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .secode_client_closed(work, witness, deadline)
            .await
    }
    #[cfg(all(test, feature = "listener", any(target_os = "linux", windows)))]
    pub(in crate::process) async fn start_secode_auxiliary(
        &self,
        service: &mut Service,
        launch: AuxiliaryLaunch,
        deadline: &Deadline,
    ) -> Result<se_proc::ProcessRecord> {
        Coordinator(self)
            .start_secode_auxiliary(
                service,
                launch.auxiliary,
                launch.executable,
                launch.arguments,
                launch.cwd,
                launch.policy,
                launch.input,
                deadline,
            )
            .await
    }
    pub(in crate::process) async fn require_secode_capability_settled(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .require_secode_capability_settled(work, deadline)
            .await
    }
    pub(in crate::process) async fn maintain_secode_capability(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Option<tokio::time::Instant> {
        Coordinator(self)
            .maintain_secode_capability(work, deadline)
            .await
    }
    pub(in crate::process) async fn reconcile_recovered_secode_notice(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .reconcile_recovered_secode_notice(work, deadline)
            .await
    }
    pub(in crate::process) async fn offer_secode_notice(
        &self,
        work: &owned::Work,
        reservation: &se_core::ops::mail::Reservation,
        deadline: &Deadline,
    ) -> Result<String> {
        Coordinator(self)
            .offer_secode_notice(work, reservation, deadline)
            .await
    }
    pub(in crate::process) async fn reconcile_secode_notice(
        &self,
        work: &owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .reconcile_secode_notice(work, deadline)
            .await
    }
    pub(in crate::process) async fn retire_secode_notice(
        &self,
        work: &owned::Work,
        notice: &se_types::NoticeId,
        deadline: &Deadline,
    ) -> Result<()> {
        Coordinator(self)
            .retire_secode_notice(work, notice, deadline)
            .await
    }
    pub(in crate::process) async fn observe_secode_output(
        &self,
        output: se_core::ops::AnyOutput,
        deadline: &Deadline,
    ) -> Result<se_core::ops::AnyOutput> {
        Coordinator(self)
            .observe_secode_output(output, deadline)
            .await
    }
}
