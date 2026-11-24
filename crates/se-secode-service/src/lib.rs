//! Coordinator-owned private SE Code services. Provider adapters cannot spawn them.
mod capability;
mod capture;
pub mod custody;
mod diagnostic;
mod lost;
pub mod mail;
mod native;
mod permission;
mod port;
mod prepare;
mod provision;
mod readiness;
mod recovery;
mod replacement;
mod resume;
mod retirement;
mod status;
mod stop;

pub use port::{
    HostPort, PortFuture, SecodeWork, Wake, call_context, prepare_error, retain_recovery_artifact,
    wait_wake,
};
pub use prepare::ready;
pub use se_harness::secode_process::Managed as Prepared;

use custody::Journal;
use port::error;
use se_harness::{
    Deadline, Harness, HarnessKind, ProbeRequest, ProviderIoPlatform, ProviderStream,
    SessionIdentity, StreamRead,
};
use se_proc::NativeProcessRuntime;
use se_types::{NativePath, Result};
use std::{path::PathBuf, sync::Arc};

/// Zero-cost coordinator handle executing SE Code service operations against a `HostPort`.
pub struct Coordinator<'a, H: HostPort>(pub &'a H);

pub type ServiceSlot = Arc<tokio::sync::Mutex<Service>>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Auxiliary {
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

pub struct RestartControl {
    pub(crate) control: Arc<se_harness::secode_process::Control>,
    pub(crate) reply_sent: bool,
    pub(crate) mail_notified: bool,
    pub(crate) identity: se_store::CredentialRestart,
    pub(crate) adopted: bool,
    pub(crate) session_hash: [u8; 32],
    pub(crate) restart_key: String,
}

impl RestartControl {
    pub fn control(&self) -> &Arc<se_harness::secode_process::Control> {
        &self.control
    }

    pub fn identity(&self) -> &se_store::CredentialRestart {
        &self.identity
    }

    pub fn adopted(&self) -> bool {
        self.adopted
    }

    pub fn reply_sent(&self) -> bool {
        self.reply_sent
    }

    pub fn session_hash(&self) -> [u8; 32] {
        self.session_hash
    }

    pub fn restart_key(&self) -> &str {
        &self.restart_key
    }
}

pub struct Service {
    pub(crate) restart: Option<RestartControl>,
    pub(crate) journal: Journal,
    path: PathBuf,
    digest: Option<[u8; 32]>,
    pending_save: Option<PendingSave>,
    wake: Arc<Wake>,
    bootstrap: Option<Arc<se_proc::OwnedProcess>>,
    pub(crate) process: Option<Arc<se_proc::OwnedProcess>>,
    retirement: Option<Arc<se_proc::OwnedProcess>>,
    bootstrap_output: Option<Arc<diagnostic::Output>>,
    service_output: Option<Arc<diagnostic::Output>>,
    retirement_output: Option<Arc<diagnostic::Output>>,
    pub(crate) control: Option<Arc<se_harness::secode_process::Control>>,
    pub(crate) failure: Option<String>,
    capability_failure: Option<String>,
    pub(crate) live: se_harness::secode_process::LiveBinding,
    pub(crate) capability_check_at: Option<tokio::time::Instant>,
}

#[derive(Default)]
pub struct Services(
    pub  tokio::sync::Mutex<
        std::collections::BTreeMap<(se_types::ProjectId, se_types::AgentId), ServiceSlot>,
    >,
    pub std::sync::Mutex<Option<String>>,
);

impl Services {
    pub async fn get(
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

pub async fn lock_service<'a>(
    slot: &'a ServiceSlot,
    deadline: &Deadline,
) -> Result<tokio::sync::MutexGuard<'a, Service>> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), slot.lock())
        .await
        .map_err(|_| error("SE Code custody", "this agent's retained service is busy"))
}

impl Service {
    pub fn new(journal: Journal, path: PathBuf) -> Self {
        Self {
            restart: None,
            journal,
            path,
            digest: None,
            pending_save: None,
            wake: Arc::new(Wake::default()),
            bootstrap: None,
            process: None,
            retirement: None,
            bootstrap_output: None,
            service_output: None,
            retirement_output: None,
            control: None,
            failure: None,
            capability_failure: None,
            live: Default::default(),
            capability_check_at: None,
        }
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    pub fn restart(&self) -> Option<&RestartControl> {
        self.restart.as_ref()
    }

    pub fn process(&self) -> Option<&Arc<se_proc::OwnedProcess>> {
        self.process.as_ref()
    }

    pub fn register_image(&mut self, digest: se_types::Sha256, resume_supported: bool) {
        self.journal.input_free_resume = resume_supported;
        self.journal.server_sha256 = Some(digest);
        self.journal.retired = false;
    }

    /// Record a newly accepted restart challenge, invalidating the prior live
    /// binding and persisting the superseded restart key before arming the
    /// replacement control.
    #[allow(
        clippy::too_many_arguments,
        reason = "restart registration pairs control, identity, session hash, and key atomically"
    )]
    pub async fn register_restart<H: HostPort>(
        &mut self,
        host: &H,
        restart_key: String,
        control: Arc<se_harness::secode_process::Control>,
        identity: se_store::CredentialRestart,
        session_hash: [u8; 32],
        deadline: &Deadline,
    ) -> Result<()> {
        let same_restart = self
            .restart
            .as_ref()
            .is_some_and(|old| old.restart_key == restart_key);
        if !same_restart {
            self.live.invalidate()?;
        }
        if self.journal.restart_key.as_deref() != Some(&restart_key) {
            self.journal.restart_key = Some(restart_key.clone());
            self.journal.restart_effect = None;
            self.journal.restart_settled = false;
            self.journal.restart_reply_sent = false;
            self.journal.superseded_by_restart = true;
            self.persist(host, deadline).await?;
        }
        if !same_restart {
            self.restart = Some(RestartControl {
                control,
                reply_sent: false,
                mail_notified: false,
                identity,
                adopted: false,
                session_hash,
                restart_key,
            });
            self.capability_check_at = None;
        }
        Ok(())
    }

    /// Reconstruct pending restart challenge state from committed credential
    /// heads after a host restart.
    #[allow(
        clippy::too_many_arguments,
        reason = "restart restoration pairs control, identity, session hash, and key atomically"
    )]
    pub async fn restore_restart<H: HostPort>(
        &mut self,
        host: &H,
        restart_key: String,
        control: Arc<se_harness::secode_process::Control>,
        identity: se_store::CredentialRestart,
        session_hash: [u8; 32],
        deadline: &Deadline,
    ) -> Result<()> {
        if self.journal.restart_key.as_deref() != Some(restart_key.as_str()) {
            self.journal.restart_key = Some(restart_key.clone());
            self.journal.restart_effect = None;
            self.journal.restart_settled = false;
            self.journal.restart_reply_sent = false;
            self.journal.superseded_by_restart = true;
            self.persist(host, deadline).await?;
        }
        self.live.invalidate()?;
        self.restart = Some(RestartControl {
            control,
            reply_sent: self.journal.restart_reply_sent,
            mail_notified: false,
            identity,
            adopted: false,
            session_hash,
            restart_key,
        });
        self.capability_check_at = None;
        Ok(())
    }

    /// Mark the matching restart's rebind reply as durably sent and clear any
    /// cached capability check timer.
    pub async fn mark_restart_reply_sent<H: HostPort>(
        &mut self,
        host: &H,
        restart_key: &str,
        deadline: &Deadline,
    ) -> Result<()> {
        let mut saved = Ok(());
        if self
            .restart
            .as_ref()
            .is_some_and(|restart| restart.restart_key == restart_key)
        {
            if !self.journal.restart_reply_sent {
                self.journal.restart_reply_sent = true;
                saved = self.persist(host, deadline).await;
            }
            if let Some(restart) = self.restart.as_mut() {
                restart.reply_sent = true;
            }
            self.capability_check_at = None;
        }
        saved
    }

    /// Publish a verified replacement control and binding into `live` and mark
    /// the restart adopted together so the two states cannot diverge.
    pub fn publish_adopted_restart(
        &mut self,
        control: Arc<se_harness::secode_process::Control>,
        binding: se_harness::secode_process::NoticeBinding,
    ) -> Result<()> {
        self.live.publish_restart(control, binding)?;
        if let Some(restart) = self.restart.as_mut() {
            restart.adopted = true;
        }
        Ok(())
    }

    /// Persist the in-flight or discovered restart notice effect before settling it.
    pub async fn record_restart_effect<H: HostPort>(
        &mut self,
        host: &H,
        effect: se_store::RecordId,
        deadline: &Deadline,
    ) -> Result<()> {
        if self.journal.restart_effect != Some(effect) {
            self.journal.restart_effect = Some(effect);
            self.persist(host, deadline).await?;
        }
        Ok(())
    }

    /// Clear any pending pre-restart notice, persist `restart_settled`, and
    /// mark unread mail notification armed for the adopted restart.
    pub async fn settle_restart_mail<H: HostPort>(
        &mut self,
        host: &H,
        deadline: &Deadline,
    ) -> Result<()> {
        self.journal.notice = None;
        self.journal.restart_settled = true;
        self.persist(host, deadline).await?;
        if let Some(restart) = self.restart.as_mut() {
            restart.mail_notified = true;
        }
        Ok(())
    }

    /// Mark unread mail notification armed once for an already-settled restart,
    /// returning `true` only on the first transition.
    pub fn mark_restart_mail_notified(&mut self) -> bool {
        if let Some(restart) = self.restart.as_mut()
            && !restart.mail_notified
        {
            restart.mail_notified = true;
            return true;
        }
        false
    }

    pub fn current(&self) -> Result<se_harness::secode_process::QualifiedControl> {
        self.live.resolve(
            self.control
                .clone()
                .or_else(|| {
                    self.restart
                        .as_ref()
                        .filter(|restart| restart.adopted)
                        .map(|restart| restart.control.clone())
                })
                .ok_or_else(|| {
                    error("SE Code current binding", "authenticated control is absent")
                })?,
            self.journal
                .identity
                .clone()
                .ok_or_else(|| error("SE Code current binding", "original identity is absent"))?,
        )
    }

    pub async fn persist<H: HostPort>(&mut self, host: &H, deadline: &Deadline) -> Result<()> {
        // Reconcile the exact previous bytes before later cleanup changes the
        // journal. Publication may have succeeded while its readback failed.
        self.persist_pending(host, deadline).await?;
        self.pending_save = Some(PendingSave {
            journal: self.journal.clone(),
            expected: self.digest,
        });
        self.persist_pending(host, deadline).await
    }

    pub async fn persist_pending<H: HostPort>(
        &mut self,
        host: &H,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(pending) = self.pending_save.clone() else {
            return Ok(());
        };
        let path = self.path.clone();
        let custody_deadline = deadline.clone();
        self.digest = Some(
            host.run_blocking(deadline, move || {
                pending
                    .journal
                    .save::<H>(&path, pending.expected, &custody_deadline)
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

/// Direct down/uninstall must recover auxiliary custody even if no client
/// process remains in the ordinary session inventory.
pub fn secode_recovery_required<H: HostPort>(
    home: &std::path::Path,
    deadline: &Deadline,
) -> Result<bool> {
    Ok(recovery::inventory::<H>(home, deadline)?
        .iter()
        .any(|(_, journal, _)| !journal.retired))
}

impl<H: HostPort> Coordinator<'_, H> {
    pub async fn secode_input_intent(
        &self,
        identity: &SessionIdentity,
        deadline: &Deadline,
    ) -> Result<()> {
        let slot = self
            .0
            .services()
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
        service.persist(self.0, deadline).await
    }

    pub async fn preflight_secode(
        &self,
        plan: &se_core::ops::agent_launch::LaunchPlan,
        deadline: &Deadline,
    ) -> Result<()> {
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
            return Err(se_harness::secode_process::incompatible(
                "managed SE Code currently requires --detach for its owned headless launch",
            ));
        }
        if plan.resolved.bypass && !plan.resolved.network {
            return Err(se_harness::secode_process::incompatible(
                "the named bypass profile disables the sandbox and cannot enforce offline shell access; select a sandboxed profile or explicitly enable network in that named bypass profile",
            ));
        }
        let git_write = self
            .0
            .configuration()
            .profiles
            .get(&plan.profile.named_profile)
            .is_some_and(|profile| profile.git_write);
        if !matches!(
            plan.resolved.approval,
            se_config::config_policy::Approval::Never
        ) {
            return Err(se_harness::secode_process::incompatible(
                "this headless host has no interactive approval transport; select a saved profile with approval = never",
            ));
        }
        if let Some(failure) = self
            .0
            .services()
            .1
            .lock()
            .map_err(|_| error("SE Code custody inventory", "poisoned inventory state"))?
            .as_ref()
        {
            return Err(error("SE Code custody inventory", failure));
        }
        let executable = self.0.resolve_secode_provider(deadline).await?;
        self.0
            .secode_harness()
            .probe(
                ProbeRequest {
                    kind: HarnessKind::Secode,
                    command: executable.clone(),
                },
                port::call_context(self.0.generation(), deadline)?,
            )
            .await?;
        if matches!(
            plan.resolved.sandbox,
            se_config::config_policy::EffectiveSandbox::WorkspaceWrite
        ) && !git_write
        {
            let selected = self.0.secode_harness().images(&executable)?;
            let server = self
                .0
                .run_blocking(deadline, move || {
                    selected
                        .lock()
                        .map_err(|_| error("SE Code sandbox capability", "poisoned custody"))?
                        .server_invocation()
                })
                .await?;
            se_harness::secode_process::sandbox::require_capability(server, deadline).await?;
        }
        if !plan.replayed
            && matches!(plan.conversation, se_types::Read::Present { .. })
            && !self
                .0
                .secode_harness()
                .images(&executable)?
                .lock()
                .map_err(|_| error("SE Code resume capabilities", "poisoned image registry"))?
                .resume_supported
        {
            return Err(se_harness::secode_process::incompatible(
                "the selected service has no qualified input-free release of a human-stop hold; retain the saved session, or explicitly omit --resume for a different conversation",
            ));
        }
        Ok(())
    }
}
