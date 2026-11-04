//! Commit callbacks are coalesced hints. Recipient state is always reread under
//! its verified scope; neither a queued write nor an IPC reply is delivery.
use se_store::{Actor, AtomicBatch, EventBody, Role, Scope};
use se_types::{AgentId, ProjectId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailRecipient {
    pub project: ProjectId,
    pub agent: AgentId,
}
pub(super) fn recipients(batch: &AtomicBatch) -> Vec<MailRecipient> {
    let mut result = Vec::new();
    for event in &batch.events {
        let Scope::Project(project) = &event.header.scope else {
            continue;
        };
        let agent = match &event.body {
            EventBody::MessageSent {
                recipient: Actor::Agent(agent),
                ..
            }
            | EventBody::MessageRead {
                recipient: Actor::Agent(agent),
                ..
            }
            | EventBody::MessageDismissed {
                recipient: Actor::Agent(agent),
                ..
            }
            | EventBody::SessionTurn {
                agent,
                role: Role::User,
                ..
            } => agent,
            _ => continue,
        };
        let recipient = MailRecipient {
            project: project.clone(),
            agent: agent.clone(),
        };
        if !result.contains(&recipient) {
            result.push(recipient);
        }
    }
    result
}
