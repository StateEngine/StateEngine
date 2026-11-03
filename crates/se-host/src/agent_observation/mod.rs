//! Two-phase status observation shared by CLI and hosted consumers. SQL facts
//! are copied first; native reads run only after the caller closes its snapshot.
use se_core::ops::{AgentRow, ConversationView, ResumeCommand, SessionView};
use se_store::{ProcessIdentityRecord, SourceEvidence};
use se_types::{ProjectId, Read, Result, SeError};
use std::time::Instant;
mod capture;
mod native;
pub(crate) mod output;
mod plan;
pub use plan::prepare_agent_observation;

pub struct AgentObservationPlan {
    identity: Option<crate::SessionIdentity>,
    row: AgentRow,
    process: Read<ProcessIdentityRecord>,
    capture: Read<SourceEvidence>,
}
pub struct AgentObservation {
    identity: Option<crate::SessionIdentity>,
    agent: se_types::AgentId,
    session: SessionView,
    conversation: ConversationView,
    resume: ResumeCommand,
}
impl AgentObservation {
    pub fn apply(self, row: &mut AgentRow) -> Result<()> {
        if row.id != self.agent
            || row.session.session_id.as_ref() != self.identity.as_ref().map(|id| &id.session)
        {
            return Err(invalid(
                "the exact agent and session from the observed SQL snapshot",
            ));
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
    bound(deadline)?;
    if plan.identity.is_some() {
        native::observe(&mut plan, deadline)?;
        capture::observe(&mut plan, deadline)?;
    }
    Ok(AgentObservation {
        identity: plan.identity,
        agent: plan.row.id,
        session: plan.row.session,
        conversation: plan.row.conversation,
        resume: plan.row.resume,
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
