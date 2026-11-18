//! Project captain designation.
use super::inputs::{Validate, bounded};
use crate::{
    commit::Cx,
    dispatch::{Kernel, admitted},
    scope,
    store_error::store_error,
};
use schemars::JsonSchema;
use se_store::{Actor, AtomicBatch, CommitReceipt, EventBody, Expected, Snapshot};
use se_types::{ActorRef, IdempotencyKey, Read, Result, SeError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptainSet {
    pub captain: String,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptainClear {
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptainShow {}
impl Validate for CaptainSet {
    fn validate(&self) -> Result<()> {
        bounded("captain", &self.captain, 256, false)
    }
}
impl Validate for CaptainClear {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
impl Validate for CaptainShow {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaptainShowOutput {
    pub captain: Option<ActorRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaptainSetOutput {
    pub captain: ActorRef,
    pub commit: se_types::WriteReceipt,
    pub current_captain: Option<ActorRef>,
    /// Current snapshot, not a historical fact about a replayed write.
    pub one_agent_project: Read<bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaptainClearOutput {
    pub commit: se_types::WriteReceipt,
    pub current_captain: Option<ActorRef>,
}
pub struct CaptainThen {
    pub key: IdempotencyKey,
    pub clear: bool,
}

pub(crate) fn actor_ref<R: Snapshot>(read: &mut R, actor: &Actor) -> Result<ActorRef> {
    match actor {
        Actor::Human(id) => Ok(ActorRef {
            kind: "owner".into(),
            id: id.to_string(),
            name: "Owner".into(),
        }),
        _ => super::receipt::actor_ref(read, actor),
    }
}

pub fn show<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<CaptainShowOutput> {
    let record = cx.read.project_captain().map_err(|e| store_error(&e))?;
    let captain = match record {
        Read::Absent { .. } => None,
        Read::Present { value } => match value.current.body {
            EventBody::ProjectCaptainChanged { captain, .. } => captain,
            _ => {
                return Err(scope::unreadable(
                    "captain",
                    "designation event has the wrong kind",
                ));
            }
        },
        other => {
            let remedy = if matches!(other, Read::Unknown { .. }) {
                "Run se up for this data home, then retry se captain show."
            } else {
                "Restore access to the project store, then retry se captain show."
            };
            scope::require_present(other, "captain", remedy)?;
            return Err(scope::unreadable(
                "captain read",
                "unexpected present value",
            ));
        }
    };
    Ok(CaptainShowOutput {
        captain: captain
            .map(|actor| actor_ref(cx.read, &actor))
            .transpose()?,
    })
}

pub fn change<R: Snapshot>(
    kernel: &Kernel,
    selector: Option<String>,
    key: IdempotencyKey,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, CaptainThen)> {
    admitted(cx)?;
    if !matches!(cx.admission.actor, Actor::Human(_)) {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "captain.set".into(),
            },
        )));
    }
    let replay = cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|e| store_error(&e))?;
    let captain = match replay {
        Read::Present { value } => {
            let event = super::receipt::committed_event(cx.read, &value)?;
            match event.body {
                EventBody::ProjectCaptainChanged { captain, .. } => captain,
                _ => {
                    return Err(SeError::new(se_types::Detail::IdempotencyKeyReused(
                        se_types::details::IdempotencyKeyReused {
                            key: key.to_string(),
                            original_event: value.primary_event,
                        },
                    )));
                }
            }
        }
        Read::Absent { .. } => match selector.as_deref() {
            None => None,
            Some("me") => Some(cx.admission.actor.clone()),
            Some(value) => match scope::selected_actor(cx, value)? {
                actor @ Actor::Agent(_) => Some(actor),
                _ => {
                    return Err(SeError::invalid(
                        "captain",
                        "a registered project agent or me",
                    ));
                }
            },
        },
        other => {
            scope::require_present(
                other,
                "captain request receipt",
                "Restore access to the project store and retry the same request key.",
            )?;
            return Err(scope::unreadable(
                "captain receipt",
                "unexpected present value",
            ));
        }
    };
    let prior = cx.read.project_captain().map_err(|e| store_error(&e))?;
    let (expected, cause) = match prior {
        Read::Absent { .. } => (Expected::Absent, None),
        Read::Present { value } => (
            Expected::Revision(value.revision),
            Some(value.current.header.event),
        ),
        other => {
            scope::require_present(
                other,
                "captain",
                "Restore access to the project store, then retry the same request key.",
            )?;
            return Err(scope::unreadable(
                "captain revision",
                "unexpected present value",
            ));
        }
    };
    let clear = selector.is_none();
    let mut event = kernel.event(
        EventBody::ProjectCaptainChanged {
            project: scope::project(cx.admission)?,
            captain,
            expected,
        },
        cx,
    )?;
    event.header.cause = cause;
    let intent = serde_json::json!({"captain": selector});
    let batch = kernel.batch(
        if clear {
            "captain.clear"
        } else {
            "captain.set"
        },
        key.clone(),
        intent,
        event,
        cx,
    )?;
    Ok((batch, CaptainThen { key, clear }))
}

pub fn step<R: Snapshot>(
    kernel: &Kernel,
    selector: Option<String>,
    key: IdempotencyKey,
    cx: &mut Cx<'_, R>,
) -> Result<crate::commit::OpStep<super::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>>
{
    let (batch, then) = change(kernel, selector, key, cx)?;
    Ok(crate::commit::OpStep::Commit {
        batch,
        then: crate::ports::Then::Captain(then),
    })
}

fn one_agent_project<R: Snapshot>(cx: &mut Cx<'_, R>) -> Read<bool> {
    let (Some(limit), Some(max_bytes)) = (
        std::num::NonZeroU32::new(64),
        std::num::NonZeroU32::new(192 * 1024),
    ) else {
        return Read::Unknown {
            what: "Principal read bounds are unavailable.".into(),
        };
    };
    let budget = se_store::ReadBudget {
        page: se_types::PageRequest {
            after: None,
            limit,
            max_bytes,
        },
        deadline: std::time::Duration::from_secs(5),
    };
    match cx.read.principals(budget) {
        Ok(page) => {
            let agents = page
                .items()
                .iter()
                .filter(|record| {
                    matches!(
                        record.current.body,
                        EventBody::PrincipalRegistered {
                            principal: Actor::Agent(_),
                            ..
                        } | EventBody::PrincipalRenamed {
                            principal: Actor::Agent(_),
                            ..
                        }
                    )
                })
                .count();
            if agents >= 2 {
                Read::Present { value: false }
            } else if page.window().complete() {
                Read::Present { value: agents == 1 }
            } else {
                Read::Unknown {
                    what: "The bounded project principal page did not establish the agent count."
                        .into(),
                }
            }
        }
        Err(error) => Read::Unreadable {
            source: "project principal count".into(),
            reason: error.to_string(),
            error: None,
        },
    }
}

pub fn committed<R: Snapshot>(
    then: CaptainThen,
    receipt: CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::AnyOutput> {
    super::receipt::receipt_key(&receipt, &then.key, "captain receipt")?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "captain receipt",
            "committed authority differs from continuation",
        ));
    }
    let commit = super::receipt::write_fields(&receipt, &event)?;
    let EventBody::ProjectCaptainChanged { captain, .. } = event.body else {
        return Err(scope::unreadable(
            "captain receipt",
            "committed event has the wrong kind",
        ));
    };
    if then.clear {
        if captain.is_some() {
            return Err(scope::unreadable(
                "captain receipt",
                "clear committed a captain",
            ));
        }
        return Ok(CaptainClearOutput {
            commit,
            current_captain: show(cx)?.captain,
        }
        .into());
    }
    let actor =
        captain.ok_or_else(|| scope::unreadable("captain receipt", "set committed no captain"))?;
    Ok(CaptainSetOutput {
        captain: actor_ref(cx.read, &actor)?,
        commit,
        current_captain: show(cx)?.captain,
        one_agent_project: one_agent_project(cx),
    }
    .into())
}
