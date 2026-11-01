//! Finite admitted identity reads; absence and an incomplete search remain distinct.
use crate::store_error::store_error;
use se_store::{Actor, Admission, EventBody, ReadBudget, Scope, Snapshot};
use se_types::{AgentId, Detail, PageRequest, ProjectId, Read, Result, SeError, details};
use std::{num::NonZeroU32, time::Duration};

pub fn project(admission: &Admission) -> Result<ProjectId> {
    match &admission.scope {
        Scope::Project(project) => Ok(project.clone()),
        Scope::Registry => Err(SeError::new(Detail::ProjectRequired(
            details::ProjectRequired { choices: vec![] },
        ))),
    }
}
pub fn working_agent(
    admission: &Admission,
    owner_agent: Option<&AgentId>,
    op: &str,
) -> Result<AgentId> {
    match (&admission.actor, owner_agent) {
        (Actor::Agent(agent), None) => Ok(agent.clone()),
        (Actor::Agent(agent), Some(selected)) if agent == selected => Ok(agent.clone()),
        (Actor::Agent(_), Some(_)) => Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired {
                op: format!("{op} for another agent"),
            },
        ))),
        (Actor::Human(_), Some(agent)) => Ok(agent.clone()),
        (Actor::Human(_), None) => Err(SeError::new(Detail::UsageMissingArgument(
            details::UsageMissingArgument {
                command: op.into(),
                argument: "--agent AGENT (owner inspection)".into(),
            },
        ))),
    }
}

pub fn actor_selector<R: Snapshot>(read: &mut R, selector: &str) -> Result<Actor> {
    if let Ok(id) = AgentId::from_legacy(selector.to_owned()) {
        let actor = Actor::Agent(id);
        require_present(
            read.principal(actor.clone()).map_err(|e| store_error(&e))?,
            selector,
        )?;
        return Ok(actor);
    }
    let mut after = None;
    let mut matches = Vec::new();
    // A finite bound is explicit; exhausting it is never reported as absence.
    for _ in 0..64 {
        let page = read
            .principals(ReadBudget {
                page: PageRequest {
                    after,
                    limit: NonZeroU32::new(100)
                        .ok_or_else(|| SeError::invalid("limit", "positive"))?,
                    max_bytes: NonZeroU32::new(1024 * 1024)
                        .ok_or_else(|| SeError::invalid("max_bytes", "positive"))?,
                },
                deadline: Duration::from_millis(250),
            })
            .map_err(|e| store_error(&e))?;
        for record in page.items() {
            match &record.current.body {
                EventBody::PrincipalRegistered {
                    principal, name, ..
                }
                | EventBody::PrincipalRenamed {
                    principal, name, ..
                } if name == selector
                    || (selector == "owner" && matches!(principal, Actor::Human(_))) =>
                {
                    matches.push(principal.clone())
                }
                _ => (),
            }
        }
        if let Some(next) = page.next() {
            after = Some(next.clone());
            continue;
        }
        if !page.window().complete() {
            return Err(unreadable(
                "principal lookup",
                "the finite principal read was incomplete",
            ));
        }
        return match matches.as_slice() {
            [actor] => Ok(actor.clone()),
            [] => Err(unknown(selector)),
            actors => Err(SeError::new(Detail::SelectorAmbiguous(
                details::SelectorAmbiguous {
                    kind: "principal".into(),
                    selector: selector.into(),
                    matches: actors.iter().map(actor_id).collect(),
                },
            ))),
        };
    }
    Err(unreadable(
        "principal lookup",
        "the bounded lookup exceeded 6400 principals; use an exact agent ID",
    ))
}
pub fn actor_id(actor: &Actor) -> String {
    match actor {
        Actor::Human(id) => id.to_string(),
        Actor::Agent(id) => id.to_string(),
    }
}
pub fn require_present<T>(read: Read<T>, subject: &str) -> Result<T> {
    match read {
        Read::Present { value } => Ok(value),
        Read::Absent { .. } => Err(unknown(subject)),
        Read::Unreadable { source, reason, .. } => Err(unreadable(&source, &reason)),
        Read::Unknown { what } => Err(SeError::new(Detail::TargetUnknown(
            details::TargetUnknown {
                subject: subject.into(),
                reason: what,
                next_step:
                    "Read the named source before retrying; preserve the original request identity."
                        .into(),
            },
        ))),
    }
}
pub fn unknown(subject: &str) -> SeError {
    SeError::new(Detail::TargetUnknown(details::TargetUnknown {
        subject: subject.into(),
        reason: "not present in the admitted project snapshot".into(),
        next_step: "Select an existing project principal or exact record ID.".into(),
    }))
}
pub fn unreadable(subject: &str, reason: &str) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {subject:subject.into(),reason:reason.into(),next_step:"Restore access and retry the original request identity; unreadable state is not absent.".into()}))
}
