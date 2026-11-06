//! Two-phase status observation shared by CLI and hosted consumers. SQL facts
//! are copied first; native reads run only after the caller closes its snapshot.
use se_core::ops::{AgentRow, ConversationView, ResumeCommand, SessionView};
use se_store::{ProcessIdentityRecord, SourceEvidence};
use se_types::{ProjectId, Read, Result, SeError};
use std::time::Instant;
mod approval;
mod capture;
mod native;
pub(crate) mod output;
mod plan;
pub use plan::prepare_agent_observation;
pub(crate) use plan::resume_source;

pub struct AgentObservationPlan {
    project: ProjectId,
    command_home: Option<std::path::PathBuf>,
    identity: Option<crate::SessionIdentity>,
    row: AgentRow,
    process: Read<ProcessIdentityRecord>,
    capture: Read<SourceEvidence>,
    control_failure: Option<String>,
    status_attention: bool,
}
impl AgentObservationPlan {
    pub fn with_status_attention(mut self) -> Self {
        self.status_attention = true;
        self
    }
    /// Presentation context only; native observation authority is unchanged.
    pub fn with_command_home(mut self, home: &std::path::Path) -> Self {
        self.command_home = Some(home.to_owned());
        self
    }
}
pub struct AgentObservation {
    identity: Option<crate::SessionIdentity>,
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
    if let Some(reason) = &plan.control_failure {
        plan.row.session.state = "recovery-pending".into();
        plan.row.resume.ready = false;
        plan.row.resume.mode = "reconcile".into();
        let stop = match &plan.command_home {
            Some(home) => {
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
    if plan.row.resume.argv.is_some() {
        let command = match &plan.command_home {
            Some(home) => se_core::ops::AgentCommand::launch_in_home(
                &plan.row.id,
                home,
                &plan.project,
                plan.row.resume.mode == "new",
            ),
            None => Some(se_core::ops::AgentCommand::launch(
                &plan.row.id,
                None,
                Some(&plan.project),
                plan.row.resume.mode == "new",
            )),
        };
        if let Some(command) = command {
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
