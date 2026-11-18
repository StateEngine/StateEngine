//! Values and transition rules for project assignments.
use crate::Actor;
use se_types::{AgentId, EventId, ProjectId};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentState {
    Open,
    Working,
    Done,
    Blocked,
    HandedBack,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub id: EventId,
    pub project: ProjectId,
    pub assignee: AgentId,
    pub state: AssignmentState,
    /// The floor event recording the current state and any blocker reason.
    pub latest_event: EventId,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentTransition {
    Accept,
    Done,
    Block,
    HandBack,
}

/// Validate a transition using authority resolved by the project store.
/// A caller must establish owner and captain against the same write transaction.
pub fn transition(
    assignment: &Assignment,
    action: &AssignmentTransition,
    actor: &Actor,
    is_owner: bool,
    captain: Option<&Actor>,
    block_reason: Option<&str>,
) -> Result<AssignmentState, &'static str> {
    let assignee = matches!(actor, Actor::Agent(id) if id == &assignment.assignee);
    let coordinator = is_owner || captain == Some(actor);
    if !matches!(
        assignment.state,
        AssignmentState::Open | AssignmentState::Working | AssignmentState::Blocked
    ) {
        return Err("assignment is no longer open");
    }
    match action {
        AssignmentTransition::Accept
            if assignee
                && matches!(
                    assignment.state,
                    AssignmentState::Open | AssignmentState::Blocked
                ) =>
        {
            Ok(AssignmentState::Working)
        }
        AssignmentTransition::Done if assignee || coordinator => Ok(AssignmentState::Done),
        AssignmentTransition::HandBack if assignee || coordinator => {
            Ok(AssignmentState::HandedBack)
        }
        AssignmentTransition::Block
            if (assignee || coordinator) && assignment.state != AssignmentState::Blocked =>
        {
            let reason = block_reason.ok_or("a blocker needs a reason")?;
            if reason.trim().is_empty() || reason.len() > se_types::MESSAGE_BODY_MAX_BYTES {
                return Err("a blocker needs a nonempty reason within the message limit");
            }
            Ok(AssignmentState::Blocked)
        }
        _ => Err("only the assignee can accept; only the assignee or coordinator can close"),
    }
}
