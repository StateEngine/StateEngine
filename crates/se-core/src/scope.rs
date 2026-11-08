//! Finite admitted identity reads; absence and an incomplete search remain distinct.
use crate::store_error::store_error;
use se_store::{Actor, Admission, EventBody, ReadBudget, Scope, Snapshot};
use se_types::{AgentId, Detail, PageRequest, ProjectId, Read, Result, SeError, details};
use std::{num::NonZeroU32, time::Duration};

pub const COMMITTED_READ_RECOVERY: &str = "The write is committed. Read its committed event IDs, or replay the original request with the same --key or natural session/provider/turn identities; do not submit a new write.";

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
        (Actor::Remote(_), _) => Err(SeError::invalid(
            "local operation",
            "local human or agent authority",
        )),
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
                command: crate::ops::command_name(op),
                argument: "--agent AGENT (owner inspection)".into(),
            },
        ))),
    }
}

/// Resolve a selector and offer the owner the same scoped agent lookup on every door.
pub fn selected_actor<R: se_store::Snapshot>(
    cx: &mut crate::commit::Cx<'_, R>,
    selector: &str,
) -> Result<se_store::Actor> {
    let result = actor_selector(cx.read, selector);
    let Err(mut error) = result else {
        return result;
    };
    if matches!(cx.admission.actor, se_store::Actor::Human(_))
        && let se_types::Detail::TargetUnknown(detail) = error.body.detail()
    {
        let mut detail = detail.clone();
        if detail.reason == "not present in the admitted project snapshot" {
            detail.reason =
                "no agent with this ID or name was found in the selected project".into();
        }
        let text = "List this project's saved agents, then retry with an exact agent ID or registered name.";
        detail.next_step = text.into();
        let project = project(cx.admission)?;
        error.body = se_types::ErrorBody::new(se_types::Detail::TargetUnknown(detail)).with_remedy(
            se_types::Remedy {
                text: text.into(),
                command: Some(se_types::Cmd::Se {
                    argv: se_types::Argv::from_op(&AgentChoices(&project))?,
                }),
            },
        );
    }
    Err(error)
}

struct AgentChoices<'a>(&'a se_types::ProjectId);
impl se_types::OperationCommand for AgentChoices<'_> {
    fn cli_argv(&self) -> Vec<String> {
        vec![
            "se".into(),
            "--project".into(),
            self.0.to_string(),
            "agent".into(),
            "list".into(),
        ]
    }
}

pub fn actor_selector<R: Snapshot>(read: &mut R, selector: &str) -> Result<Actor> {
    if let Ok(id) = AgentId::from_legacy(selector.to_owned()) {
        let actor = Actor::Agent(id);
        require_present(
            read.principal(actor.clone()).map_err(|e| store_error(&e))?,
            selector,
            "Select an existing principal in this project, using its exact agent ID or registered name.",
        )?;
        return Ok(actor);
    }
    let (registered, alias) = {
        let registry = read.legacy_registry().map_err(|e| store_error(&e))?;
        let registered = if se_types::LegacyIdRegistry::contains(
            &registry,
            se_types::IdKind::AgentId,
            selector,
        )? {
            Some(AgentId::from_registered_legacy(
                selector.to_owned(),
                &registry,
            )?)
        } else {
            None
        };
        let alias = se_types::LegacyIdRegistry::resolve_alias(
            &registry,
            se_types::IdKind::AgentId,
            selector,
        )?;
        let alias = alias
            .map(|wire| {
                AgentId::from_legacy(wire.clone())
                    .or_else(|_| AgentId::from_registered_legacy(wire, &registry))
            })
            .transpose()?;
        (registered, alias)
    };
    if let Some(id) = registered {
        let actor = Actor::Agent(id);
        require_present(
            read.principal(actor.clone()).map_err(|e| store_error(&e))?,
            selector,
            "Select an exact source-registered principal in this project.",
        )?;
        return Ok(actor);
    }
    let mut after = None;
    let mut matches = Vec::new();
    if let Some(agent) = alias {
        let actor = Actor::Agent(agent);
        require_present(
            read.principal(actor.clone()).map_err(|e| store_error(&e))?,
            selector,
            "Restore the exact imported alias principal.",
        )?;
        matches.push(actor);
    }
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
                } if (selector != "owner" && name == selector)
                    || matches!(&record.original.as_deref().unwrap_or(&record.current).body,
                        EventBody::PrincipalRegistered { principal: Actor::Human(human), owner, .. }
                        if human == owner && (selector == "owner" || human.as_str() == selector)) =>
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
        matches.sort_by_key(actor_id);
        matches.dedup();
        return match matches.as_slice() {
            [actor] => Ok(actor.clone()),
            [] => Err(unknown(
                selector,
                "Select an existing principal in this project, using its exact agent ID or registered name.",
            )),
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
        Actor::Remote(id) => id.to_string(),
    }
}
/// The reader supplies recovery for its own source. This helper can run after
/// a commit, so no read failure implies that the preceding write was undone.
pub fn require_present<T>(read: Read<T>, subject: &str, next_step: &str) -> Result<T> {
    match read {
        Read::Present { value } => Ok(value),
        Read::Absent { checked } => Err(SeError::new(Detail::TargetUnknown(
            details::TargetUnknown {
                subject: subject.into(),
                reason: format!("not present; checked {checked}"),
                next_step: next_step.into(),
            },
        ))),
        Read::Unreadable { source, reason, .. } => Err(SeError::new(Detail::SourceUnreadable(
            details::SourceUnreadable {
                subject: source,
                reason,
                next_step: next_step.into(),
            },
        ))),
        Read::Unknown { what } => Err(SeError::new(Detail::TargetUnknown(
            details::TargetUnknown {
                subject: subject.into(),
                reason: what,
                next_step: next_step.into(),
            },
        ))),
    }
}
pub fn unknown(subject: &str, next_step: &str) -> SeError {
    SeError::new(Detail::TargetUnknown(details::TargetUnknown {
        subject: subject.into(),
        reason: "not present in the admitted project snapshot".into(),
        next_step: next_step.into(),
    }))
}
pub fn unreadable(subject: &str, reason: &str) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {subject:subject.into(),reason:reason.into(),next_step:"Restore access and retry the original request identity; unreadable state is not absent.".into()}))
}
