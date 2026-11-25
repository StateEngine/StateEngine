//! Two-phase status observation shared by CLI and hosted consumers. SQL facts
//! are copied first; native reads run only after the caller closes its snapshot.
use se_core::ops::{AgentRow, ConversationView, ResumeCommand, SessionView};
use se_harness::model::SessionIdentity;
use se_store::{ProcessIdentityRecord, SourceEvidence};
use se_types::{ProjectId, Read, Result, SeError};
use std::time::Instant;
mod approval;
mod background;
pub use background::{busy, row as background};
mod capture;
mod native;
pub mod output;
mod plan;
pub use plan::prepare_agent_observation;
pub use plan::resume_source;

pub enum RecordedExit {
    Other,
    Reboot,
}

pub struct AgentObservationPlan {
    project: ProjectId,
    /// The command home and the reader for its protected machine identity.
    command_home: Option<(std::path::PathBuf, MachineIdentity)>,
    identity: Option<SessionIdentity>,
    row: AgentRow,
    process: Read<ProcessIdentityRecord>,
    recorded_exit: RecordedExit,
    capture: Read<SourceEvidence>,
    control_failure: Option<String>,
    status_attention: bool,
    setup_expired: bool,
    setup_retryable: bool,
}
impl AgentObservationPlan {
    pub fn with_status_attention(mut self) -> Self {
        self.status_attention = true;
        self
    }
    /// Every plan's identity names the row's own recorded session.
    fn new(
        project: ProjectId,
        row: AgentRow,
        process: Read<ProcessIdentityRecord>,
        recorded_exit: RecordedExit,
        capture: Read<SourceEvidence>,
    ) -> Self {
        let identity = row
            .session
            .session_id
            .clone()
            .map(|session| SessionIdentity {
                project: project.clone(),
                agent: row.id.clone(),
                session,
            });
        Self {
            project,
            command_home: None,
            identity,
            row,
            process,
            recorded_exit,
            capture,
            control_failure: None,
            status_attention: false,
            setup_expired: false,
            setup_retryable: false,
        }
    }
    /// Scoped remote metadata already passed the grant-filtered read port.
    pub fn remote(
        project: ProjectId,
        row: AgentRow,
        process: Read<ProcessIdentityRecord>,
        recorded_exit: RecordedExit,
        session: Option<&se_store::ProjectionRecord>,
    ) -> Self {
        let capture = Read::Absent {
            checked: "remote list does not request private transcript custody".into(),
        };
        Self {
            setup_expired: session.is_some_and(se_core::ops::agent_launch::expired_attended_setup),
            setup_retryable: session
                .is_some_and(se_core::ops::agent_launch::retryable_attended_setup),
            ..Self::new(project, row, process, recorded_exit, capture)
        }
    }

    /// Home for printed commands, plus the reader for its protected machine identity.
    pub fn with_command_home(mut self, home: &std::path::Path, machine: MachineIdentity) -> Self {
        self.command_home = Some((home.to_owned(), machine));
        self
    }
}
pub struct AgentObservation {
    identity: Option<SessionIdentity>,
    agent: se_types::AgentId,
    session: SessionView,
    conversation: ConversationView,
    resume: ResumeCommand,
    pending: Option<se_core::ops::PendingFact>,
}
impl AgentObservation {
    /// Observed harness attention for status, separate from native liveness.
    pub fn pending(&self) -> Option<&se_core::ops::PendingFact> {
        self.pending.as_ref()
    }
    pub fn apply(self, row: &mut AgentRow) -> Result<()> {
        if row.id != self.agent
            || row.session.session_id.as_ref() != self.identity.as_ref().map(|id| &id.session)
        {
            degrade(
                row,
                &invalid("the exact agent and session from the observed SQL snapshot"),
            );
            return Ok(());
        }
        row.session = self.session;
        row.conversation = self.conversation;
        row.resume = self.resume;
        Ok(())
    }
}
fn launch_command(plan: &AgentObservationPlan, fresh: bool) -> Option<se_core::ops::AgentCommand> {
    match &plan.command_home {
        Some((home, _)) => {
            se_core::ops::AgentCommand::launch_in_home(&plan.row.id, home, &plan.project, fresh)
        }
        None => Some(se_core::ops::AgentCommand::launch(
            &plan.row.id,
            None,
            Some(&plan.project),
            fresh,
        )),
    }
}
fn apply_control_failure(plan: &mut AgentObservationPlan) {
    let Some(reason) = &plan.control_failure else {
        return;
    };
    plan.row.session.state = "recovery-pending".into();
    plan.row.resume.ready = false;
    plan.row.resume.mode = "reconcile".into();
    let stop = match &plan.command_home {
        Some((home, _)) => {
            se_core::ops::AgentCommand::stop_in_home(&plan.row.id, home, &plan.project)
        }
        None => Some(se_core::ops::AgentCommand::stop(
            &plan.row.id,
            None,
            Some(&plan.project),
        )),
    };
    let remedy = stop.map_or_else(
        || se_core::ops::AgentCommand::HOME_UNAVAILABLE.into(),
        |stop| {
            format!(
                "Run `{}` to reconcile exact native ownership before resuming.",
                stop.command
            )
        },
    );
    plan.row.resume.reason = Some(format!(
        "Agent {} ({}) session {}: {reason}. Preserve the original provider and session; restore its protected custody/session records. {remedy}",
        plan.row.name,
        plan.row.id,
        plan.identity
            .as_ref()
            .map(|id| id.session.as_str())
            .unwrap_or("unknown"),
    ));
    plan.row.resume.command = None;
    plan.row.resume.argv = None;
}
fn apply_resume_and_setup(plan: &mut AgentObservationPlan) {
    if plan.row.resume.argv.is_some() {
        if let Some(command) = launch_command(plan, plan.row.resume.mode == "new") {
            let command =
                command.with_detach(plan.row.session.surface.as_deref() != Some("window"));
            plan.row.resume.command = Some(command.command);
            plan.row.resume.argv = Some(command.argv);
        } else {
            plan.row.resume.ready = false;
            plan.row.resume.reason = Some(se_core::ops::AgentCommand::HOME_UNAVAILABLE.into());
            plan.row.resume.command = None;
            plan.row.resume.argv = None;
        }
    }
    let live = matches!(&plan.row.session.liveness, Read::Present { value } if value == "live");
    if plan.setup_retryable && plan.control_failure.is_none() {
        if live {
            plan.row.session.state = if plan.setup_expired {
                "setup-expired"
            } else {
                "setup-failed"
            }
            .into();
        }
        plan.row.resume.ready = false;
        plan.row.resume.mode = "new".into();
        plan.row.resume.reason = Some(if plan.setup_expired {
            "Setup took longer than 10 minutes, so this window isn't connected to StateEngine. Finish Claude's welcome, then launch this agent again; completed onboarding is retained."
        } else {
            "The replacement setup failed before connecting to StateEngine. Launch this agent again to retry; completed onboarding and existing mail holds are retained."
        }.into());
        let command = launch_command(plan, true).map(|command| command.with_detach(false));
        plan.row.resume.command = command.as_ref().map(|command| command.command.clone());
        plan.row.resume.argv = command.map(|command| command.argv);
    } else if live
        && plan.row.provider == se_config::config_policy::Provider::Claude
        && plan.row.session.surface.as_deref() == Some("window")
        && plan.row.session.recorded_state.as_deref() == Some("prepared")
    {
        plan.row.session.state = "starting".into();
        plan.row.resume.reason = Some("Waiting for Claude to connect. Complete any welcome or workspace trust prompt in its window; StateEngine is still watching the same process.".into());
        plan.row.resume.mode = "running".into();
    }
}
/// Reads the protected machine identity under a command home. The caller owns
/// the state files, so it resolves the identity for the reboot proof.
pub type MachineIdentity = fn(&std::path::Path) -> Result<se_types::MachineId>;

pub fn observe_agent(
    mut plan: AgentObservationPlan,
    deadline: Instant,
) -> Result<AgentObservation> {
    let observed = (|| {
        bound(deadline)?;
        if plan.identity.is_some() && !matches!(&plan.process, Read::Unreadable { .. }) {
            native::observe(&mut plan, deadline)?;
            capture::observe(&mut plan, deadline)?;
        }
        Ok(())
    })();
    if let Err(error) = observed {
        degrade(&mut plan.row, &error);
    }
    apply_control_failure(&mut plan);
    apply_resume_and_setup(&mut plan);
    let pending = approval::observe(&plan, deadline);
    Ok(AgentObservation {
        identity: plan.identity,
        agent: plan.row.id,
        session: plan.row.session,
        conversation: plan.row.conversation,
        resume: plan.row.resume,
        pending,
    })
}
fn invalid(reason: &str) -> SeError {
    SeError::invalid("agent session observation", reason)
}
fn unreadable<T>(subject: &str, error: impl std::fmt::Display) -> Read<T> {
    Read::Unreadable {
        source: subject.into(),
        reason: error.to_string(),
        error: None,
    }
}
fn bound(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(invalid(
            "native observations within the original read deadline",
        ));
    }
    Ok(())
}

// Keep a malformed or unreadable agent local to its row. Other agents and the
// finite page's continuation remain available to both hosted and CLI readers.
fn degrade(row: &mut AgentRow, error: &SeError) {
    row.session.state = "unknown".into();
    row.session.end_reason = None;
    row.session.process = None;
    row.session.observed_at = None;
    row.session.liveness = Read::Unreadable {
        source: "agent session observation".into(),
        reason: error.to_string(),
        error: Some(Box::new(error.body.clone())),
    };
    row.conversation.state = "unverifiable".into();
    row.resume.ready = false;
    row.resume.mode = "unavailable".into();
    row.resume.reason = Some(error.to_string());
    row.resume.command = None;
    row.resume.argv = None;
}
fn missing<T, U>(read: Read<T>) -> Read<U> {
    match read {
        Read::Present { .. } => {
            unreadable("agent session observation", "expected a non-present read")
        }
        Read::Absent { checked } => Read::Absent { checked },
        Read::Unknown { what } => Read::Unknown { what },
        Read::Unreadable {
            source,
            reason,
            error,
        } => Read::Unreadable {
            source,
            reason,
            error,
        },
    }
}
