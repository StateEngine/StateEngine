//! Immutable FULL receipt reconstruction; no current head substitutes for the
//! value or prior value committed by an earlier invocation of the request key.
use super::agent_config::AgentConfigThen;
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{
    Actor, CommitReceipt, EventBody, Expected, GrantKey, Snapshot, StoredEvent, StoredText,
};
use se_types::{AgentId, ConfigPreviousSource, ConfigPreviousValue, Result};

fn subject(body: &EventBody<StoredText>) -> Result<(&AgentId, &Expected)> {
    match body {
        EventBody::ProfileSaved {
            agent, expected, ..
        } => Ok((agent, expected)),
        EventBody::GrantRecorded {
            principal: Actor::Agent(agent),
            key: GrantKey::AgentCanCreate(target),
            expected,
            ..
        } if agent == target => Ok((agent, expected)),
        _ => Err(scope::unreadable(
            "agent setting receipt",
            "immutable event is not the expected saved agent setting",
        )),
    }
}
fn checked(event: &StoredEvent, agent: &AgentId, cx: &se_store::Admission) -> Result<()> {
    if event.header.scope != cx.scope || subject(&event.body)?.0 != agent {
        return Err(scope::unreadable(
            "agent setting receipt",
            "immutable setting belongs to another scope or agent",
        ));
    }
    Ok(())
}
pub fn committed<R: Snapshot>(
    then: AgentConfigThen,
    receipt: CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::AgentConfigReceipt> {
    if receipt.request_key.as_ref() != Some(&then.request) {
        return Err(scope::unreadable(
            "agent setting receipt",
            "request key differs from continuation",
        ));
    }
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "agent setting receipt",
            "committed authority differs from continuation",
        ));
    }
    let (agent, expected) = subject(&event.body)?;
    let value = then.field.value(&event.body)?;
    let revision = match expected {
        Expected::Absent => 1,
        Expected::Revision(revision) => revision
            .value
            .get()
            .checked_add(1)
            .ok_or_else(|| scope::unreadable("agent setting revision", "revision overflow"))?,
    };
    let previous = match (&event.header.cause, expected) {
        (Some(id), Expected::Revision(_)) => {
            let prior = scope::require_present(
                cx.read
                    .event(id.clone())
                    .map_err(|error| store_error(&error))?,
                "prior agent setting event",
                scope::COMMITTED_READ_RECOVERY,
            )?;
            checked(&prior, agent, cx.admission)?;
            ConfigPreviousValue {
                value: then.field.value(&prior.body)?,
                source: ConfigPreviousSource::Stored,
            }
        }
        (None, Expected::Absent) => ConfigPreviousValue {
            value: then.field.default_value().ok_or_else(|| {
                scope::unreadable(
                    "agent setting previous value",
                    "no effective default exists for this absent stored setting",
                )
            })?,
            source: ConfigPreviousSource::Default,
        },
        _ => {
            return Err(scope::unreadable(
                "agent setting previous value",
                "commit lacks the exact prior immutable event",
            ));
        }
    };
    let current = scope::require_present(
        then.field.record(agent, cx)?,
        "current saved agent setting",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    checked(&current.current, agent, cx.admission)?;
    let current_revision = current.revision.value.get();
    if current_revision < revision {
        return Err(scope::unreadable(
            "agent setting readback",
            "snapshot predates the committed setting",
        ));
    }
    let principal = scope::require_present(
        cx.read
            .principal(Actor::Agent(agent.clone()))
            .map_err(|error| store_error(&error))?,
        "saved agent identity",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let name = match principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name
        }
        _ => {
            return Err(scope::unreadable(
                "saved agent identity",
                "current display name unavailable",
            ));
        }
    };
    Ok(super::AgentConfigReceipt{
        commit:super::receipt::write_fields(&receipt,&event)?,storage:se_types::ConfigStorage::AgentRecord,
        project:super::receipt::named_project(cx)?,agent:super::Named{id:agent.clone(),name},key:then.key,previous,value,revision,current_revision,
        authority:se_types::ReceiptAuthority{guard:then.human_only.then_some(se_types::ReceiptGuard::OwnerTerminalOutsideAgentTree),limit:"mistake/drift guard; not proof against a determined agent using the same OS account".into()},
    })
}
