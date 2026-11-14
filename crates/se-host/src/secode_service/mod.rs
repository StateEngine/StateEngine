//! Coordinator-owned private services. Provider adapters cannot spawn them.
mod capability;
mod capture;
mod custody;
mod diagnostic;
mod lost;
mod mail;
mod native;
mod permission;
mod prepare;
mod provision;
mod readiness;
mod recovery;
mod replacement;
mod resume;
mod retirement;
mod status;
mod stop;
use super::*;
use crate::client::lease::Deadline;
use custody::Journal;
use se_types::Result;

pub(in crate::process) type Prepared = crate::harness::secode_process::Managed;
type ServiceSlot = Arc<tokio::sync::Mutex<Service>>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Auxiliary {
    Bootstrap,
    Service,
    Retirement,
}
impl Auxiliary {
    const ALL: [Self; 3] = [Self::Bootstrap, Self::Service, Self::Retirement];
}

#[derive(Clone)]
struct PendingSave {
    journal: Journal,
    expected: Option<[u8; 32]>,
}
pub(super) struct Service {
    journal: Journal,
    path: PathBuf,
    digest: Option<[u8; 32]>,
    pending_save: Option<PendingSave>,
    wake: Arc<events::Wake>,
    bootstrap: Option<Arc<se_proc::OwnedProcess>>,
    process: Option<Arc<se_proc::OwnedProcess>>,
    retirement: Option<Arc<se_proc::OwnedProcess>>,
    bootstrap_output: Option<Arc<diagnostic::Output>>,
    service_output: Option<Arc<diagnostic::Output>>,
    retirement_output: Option<Arc<diagnostic::Output>>,
    control: Option<Arc<crate::harness::secode_process::Control>>,
    failure: Option<String>,
    capability_failure: Option<String>,
    live: crate::harness::secode_process::LiveBinding,
    capability_check_at: Option<tokio::time::Instant>,
}
#[derive(Default)]
pub(super) struct Services(
    pub  tokio::sync::Mutex<
        std::collections::BTreeMap<(se_types::ProjectId, se_types::AgentId), ServiceSlot>,
    >,
    pub std::sync::Mutex<Option<String>>,
);

impl Services {
    async fn get(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
        deadline: &Deadline,
    ) -> Result<Option<ServiceSlot>> {
        let services =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), self.0.lock())
                .await
                .map_err(|_| error("SE Code custody", "service registry is busy"))?;
        Ok(services.get(&(project.clone(), agent.clone())).cloned())
    }
}
async fn lock_service<'a>(
    slot: &'a ServiceSlot,
    deadline: &Deadline,
) -> Result<tokio::sync::MutexGuard<'a, Service>> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), slot.lock())
        .await
        .map_err(|_| error("SE Code custody", "this agent's retained service is busy"))
}

impl Service {
    fn current(&self) -> Result<crate::harness::secode_process::QualifiedControl> {
        self.live.resolve(
            self.control.clone().ok_or_else(|| {
                error("SE Code current binding", "authenticated control is absent")
            })?,
            self.journal
                .identity
                .clone()
                .ok_or_else(|| error("SE Code current binding", "original identity is absent"))?,
        )
    }
    async fn persist(
        &mut self,
        coordinator: &LaunchCoordinator,
        deadline: &Deadline,
    ) -> Result<()> {
        // Reconcile the exact previous bytes before later cleanup changes the
        // journal. Publication may have succeeded while its readback failed.
        self.persist_pending(coordinator, deadline).await?;
        self.pending_save = Some(PendingSave {
            journal: self.journal.clone(),
            expected: self.digest,
        });
        self.persist_pending(coordinator, deadline).await
    }
    async fn persist_pending(
        &mut self,
        coordinator: &LaunchCoordinator,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(pending) = self.pending_save.clone() else {
            return Ok(());
        };
        let path = self.path.clone();
        let custody_deadline = deadline.clone();
        self.digest = Some(
            coordinator
                .store
                .pool
                .run_owned(deadline, move || {
                    pending
                        .journal
                        .save(&path, pending.expected, &custody_deadline)
                })
                .await?,
        );
        self.pending_save = None;
        Ok(())
    }
    fn checkpoint(&mut self, auxiliary: Auxiliary, kind: se_proc::CheckpointKind) -> Result<()> {
        let checkpoint = self.journal.checkpoint(kind)?;
        *self.journal.auxiliary_mut(auxiliary) = Some(checkpoint);
        Ok(())
    }
    fn owner(&self, auxiliary: Auxiliary) -> &Option<Arc<se_proc::OwnedProcess>> {
        match auxiliary {
            Auxiliary::Bootstrap => &self.bootstrap,
            Auxiliary::Service => &self.process,
            Auxiliary::Retirement => &self.retirement,
        }
    }
    fn owner_mut(&mut self, auxiliary: Auxiliary) -> &mut Option<Arc<se_proc::OwnedProcess>> {
        match auxiliary {
            Auxiliary::Bootstrap => &mut self.bootstrap,
            Auxiliary::Service => &mut self.process,
            Auxiliary::Retirement => &mut self.retirement,
        }
    }
    fn output(&self, auxiliary: Auxiliary) -> &Option<Arc<diagnostic::Output>> {
        match auxiliary {
            Auxiliary::Bootstrap => &self.bootstrap_output,
            Auxiliary::Service => &self.service_output,
            Auxiliary::Retirement => &self.retirement_output,
        }
    }
    fn output_mut(&mut self, auxiliary: Auxiliary) -> &mut Option<Arc<diagnostic::Output>> {
        match auxiliary {
            Auxiliary::Bootstrap => &mut self.bootstrap_output,
            Auxiliary::Service => &mut self.service_output,
            Auxiliary::Retirement => &mut self.retirement_output,
        }
    }
}

impl LaunchCoordinator {
    /// Direct down/uninstall must recover auxiliary custody even if no client
    /// process remains in the ordinary session inventory.
    pub fn secode_recovery_required(home: &std::path::Path, deadline: &Deadline) -> Result<bool> {
        Ok(recovery::inventory(home, deadline)?
            .iter()
            .any(|(_, journal, _)| !journal.retired))
    }
    pub(in crate::process) async fn secode_input_intent(
        &self,
        identity: &crate::SessionIdentity,
        deadline: &Deadline,
    ) -> Result<()> {
        let slot = self
            .secode_services
            .get(&identity.project, &identity.agent, deadline)
            .await?
            .ok_or_else(|| error("SE Code input intent", "original service absent"))?;
        let mut service = lock_service(&slot, deadline).await?;
        if service.journal.session != identity.session || service.journal.initial_offered {
            return Err(error(
                "SE Code input intent",
                "original offer is already attempted or belongs to another session; reconcile its key without replay",
            ));
        }
        service.journal.initial_offered = true;
        service.persist(self, deadline).await
    }
    pub(in crate::process) async fn preflight_secode(
        &self,
        plan: &se_core::ops::agent_launch::LaunchPlan,
        deadline: &Deadline,
    ) -> Result<()> {
        use crate::Harness;
        if cfg!(windows) {
            return Err(se_types::SeError::new(se_types::Detail::FeatureUnavailable(
                se_types::details::FeatureUnavailable {
                    subject: "headless SE Code services on Windows".into(),
                    reason: "private profile-directory protection is not yet qualified".into(),
                    next_step: "Run headless SE Code on Linux. On Windows, use a Claude or Codex agent; for a new project, run se init --provider codex after signing in to Codex.".into(),
                },
            )));
        }
        if !plan.input.detach {
            return Err(crate::harness::secode_process::incompatible(
                "managed SE Code currently requires --detach for its owned headless launch",
            ));
        }
        if plan.resolved.bypass && !plan.resolved.network {
            return Err(crate::harness::secode_process::incompatible(
                "the named bypass profile disables the sandbox and cannot enforce offline shell access; select a sandboxed profile or explicitly enable network in that named bypass profile",
            ));
        }
        let git_write = self
            .options
            .configuration
            .profiles
            .get(&plan.profile.named_profile)
            .is_some_and(|profile| profile.git_write);
        if !matches!(
            plan.resolved.approval,
            se_config::config_policy::Approval::Never
        ) {
            return Err(crate::harness::secode_process::incompatible(
                "this headless host has no interactive approval transport; select a saved profile with approval = never",
            ));
        }
        if let Some(failure) = self
            .secode_services
            .1
            .lock()
            .map_err(|_| error("SE Code custody inventory", "poisoned inventory state"))?
            .as_ref()
        {
            return Err(error("SE Code custody inventory", failure));
        }
        let selected_file = self.configuration_file.clone();
        let configuration = self.options.configuration.clone();
        let executable = self
            .store
            .pool
            .run_owned(deadline, move || {
                super::launch_util::resolve_provider(
                    &configuration,
                    se_types::Provider::SeCode,
                    selected_file.as_deref(),
                    None,
                )
            })
            .await?;
        self.secode
            .probe(
                crate::ProbeRequest {
                    kind: crate::HarnessKind::Secode,
                    command: executable.clone(),
                },
                super::launch_util::call(self.store.generation, deadline)?,
            )
            .await?;
        if matches!(
            plan.resolved.sandbox,
            se_config::config_policy::EffectiveSandbox::WorkspaceWrite
        ) && !git_write
        {
            let selected = self.secode.images(&executable)?;
            let server = self
                .store
                .pool
                .run_owned(deadline, move || {
                    selected
                        .lock()
                        .map_err(|_| error("SE Code sandbox capability", "poisoned custody"))?
                        .server_invocation()
                })
                .await?;
            crate::harness::secode_process::sandbox::require_capability(server, deadline).await?;
        }
        if !plan.replayed
            && matches!(plan.conversation, se_types::Read::Present { .. })
            && !self
                .secode
                .images(&executable)?
                .lock()
                .map_err(|_| error("SE Code resume capabilities", "poisoned image registry"))?
                .resume_supported
        {
            return Err(crate::harness::secode_process::incompatible(
                "the selected service has no qualified input-free release of a human-stop hold; retain the saved session, or explicitly request --new for a different conversation",
            ));
        }
        Ok(())
    }
}
