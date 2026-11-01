//! Complete decision detail, reconstructed from authoritative exact projections
//! and a bounded ordered stream of this decision's retained transitions.
use super::{
    ActorRef, DecisionAction, DecisionRow,
    inputs::{Validate, bounded},
};
use crate::{commit::Cx, scope};
use schemars::JsonSchema;
use se_store::{EventBody, ProjectionRecord, Snapshot, StoredEvent};
use se_types::{EventId, Read, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionShow {
    pub decision_id: String,
}
impl Validate for DecisionShow {
    fn validate(&self) -> Result<()> {
        bounded("decision_id", &self.decision_id, 512, false)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionTransition {
    pub action: DecisionAction,
    pub by: ActorRef,
    pub at: String,
    pub event_id: EventId,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionDetail {
    #[serde(flatten)]
    pub row: DecisionRow,
    pub transitions: Vec<DecisionTransition>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionOutput {
    pub decision: Read<DecisionDetail>,
}

/// Exact pages share the snapshot's high-water mark and retain its scope checks.
/// The final detail is complete or explicitly unreadable, never a partial history.
pub fn read<R: Snapshot>(input: DecisionShow, cx: &mut Cx<'_, R>) -> Result<DecisionOutput> {
    input.validate()?;
    scope::project(cx.admission)?;
    let registry = cx
        .read
        .legacy_registry()
        .map_err(|e| crate::store_error::store_error(&e))?;
    let id = se_types::DecisionId::from_legacy(input.decision_id.clone())
        .or_else(|_| se_types::DecisionId::from_registered_legacy(input.decision_id, &registry))?;
    drop(registry);
    let mut after = None;
    let mut events = Vec::new();
    // At most 32 bounded pages; no project-wide scan or unbounded continuation.
    for _ in 0..32 {
        let budget = se_store::ReadBudget {
            page: se_types::PageRequest {
                after: after.clone(),
                limit: std::num::NonZeroU32::new(128)
                    .ok_or_else(|| se_types::SeError::invalid("decision limit", "nonzero"))?,
                max_bytes: std::num::NonZeroU32::new(1024 * 1024)
                    .ok_or_else(|| se_types::SeError::invalid("decision byte limit", "nonzero"))?,
            },
            deadline: std::time::Duration::from_millis(250),
        };
        let page = match read_result(cx.read.decision_transitions(id.clone(), budget))? {
            Read::Present { value } => value,
            other => {
                return Ok(DecisionOutput {
                    decision: other.map(|_| unreachable!()),
                });
            }
        };
        let complete = page.window().complete();
        let next = page.next().cloned();
        for event in page.into_items() {
            if events.len() >= 4096 {
                return Ok(incomplete(
                    "complete decision exceeds the bounded detail budget",
                ));
            }
            events.push(event);
        }
        if complete {
            let record = read_result(cx.read.decision(id))?;
            let decision = match record {
                Read::Present { value } => match detail(value, events, cx) {
                    Ok(value) => Read::Present { value },
                    Err(error) => Read::Unreadable {
                        source: "decision detail".into(),
                        reason: error.body.message(),
                        error: Some(Box::new(error.body)),
                    },
                },
                Read::Absent { .. } => {
                    return Ok(incomplete(
                        "immutable transitions exist but the decision projection is absent",
                    ));
                }
                other => other.map(|_| unreachable!()),
            };
            return Ok(DecisionOutput { decision });
        }
        match next {
            Some(next) if Some(&next) != after.as_ref() => after = Some(next),
            _ => {
                return Ok(incomplete(
                    "targeted decision history has unaccounted omissions",
                ));
            }
        }
    }
    Ok(incomplete(
        "complete decision exceeds the bounded page budget",
    ))
}
fn read_result<T>(value: se_store::StoreResult<Read<T>>) -> Result<Read<T>> {
    match value {
        Ok(value) => Ok(value),
        Err(error) => {
            use se_store::StoreErrorCode::*;
            let unavailable = matches!(
                error.code,
                Unreadable | Corrupt | ProjectionInconsistent | ReadIncomplete | ReadBudgetTooSmall
            );
            let error = crate::store_error::store_error(&error);
            if unavailable {
                Ok(Read::Unreadable {
                    source: "decision detail".into(),
                    reason: error.body.message(),
                    error: Some(Box::new(error.body)),
                })
            } else {
                Err(error)
            }
        }
    }
}
fn incomplete(reason: &str) -> DecisionOutput {
    let error = scope::unreadable("decision detail", reason);
    DecisionOutput {
        decision: Read::Unreadable {
            source: "decision detail".into(),
            reason: error.body.message(),
            error: Some(Box::new(error.body)),
        },
    }
}

pub fn detail<R: Snapshot>(
    record: ProjectionRecord,
    events: Vec<StoredEvent>,
    cx: &mut Cx<'_, R>,
) -> Result<DecisionDetail> {
    use EventBody::*;
    let original = record.original.as_deref().unwrap_or(&record.current);
    let DecisionProposed { decision: id, .. } = &original.body else {
        return Err(scope::unreadable(
            "decision detail",
            "original proposal is unavailable",
        ));
    };
    let mut row = super::decision::row(id, &record.current, cx)?;
    let mut transitions = Vec::new();
    let mut predecessor = None;
    let mut revisions = 0u64;
    let mut first = None;
    let mut last = None;
    for event in events {
        if event.header.scope != cx.admission.scope {
            return Err(scope::unreadable(
                "decision transitions",
                "event differs from the authorized project",
            ));
        }
        let incoming = matches!(&event.body, DecisionSuperseded { prior, replacement, .. } if replacement == id && prior != id);
        let (action, reason) = match &event.body {
            DecisionProposed { decision, .. } if decision == id => (DecisionAction::Propose, None),
            DecisionRatified { decision, .. } if decision == id => (DecisionAction::Ratify, None),
            DecisionRejected {
                decision, reason, ..
            } if decision == id => (DecisionAction::Reject, Some(content(reason)?)),
            DecisionRetracted {
                decision, reason, ..
            } if decision == id => (DecisionAction::Retract, Some(content(reason)?)),
            DecisionSuperseded { prior, .. } if prior == id => (DecisionAction::Supersede, None),
            DecisionSuperseded {
                prior, replacement, ..
            } if replacement == id => {
                if predecessor.replace(prior.clone()).is_some() {
                    return Err(scope::unreadable(
                        "decision predecessor",
                        "multiple effective predecessors cannot be represented as one supersedes link",
                    ));
                }
                (DecisionAction::Supersede, None)
            }
            _ => {
                return Err(scope::unreadable(
                    "decision transitions",
                    "targeted stream contains an unrelated event",
                ));
            }
        };
        if !incoming {
            revisions += 1;
            if event.revision.value.get() != revisions {
                return Err(scope::unreadable(
                    "decision transitions",
                    "retained revisions are missing, duplicated or out of order",
                ));
            }
            first.get_or_insert(event.header.event.clone());
            last = Some(event.header.event.clone());
        }
        transitions.push(DecisionTransition {
            action,
            by: super::receipt::actor_ref(cx.read, &event.header.actor)?,
            at: super::receipt::timestamp(event.recorded_at_us)?,
            event_id: event.header.event,
            reason,
        });
    }
    if revisions != record.revision.value.get()
        || first.as_ref() != Some(&original.header.event)
        || last.as_ref() != Some(&record.current.header.event)
    {
        return Err(scope::unreadable(
            "decision transitions",
            "stream does not account for the exact original and current retained revisions",
        ));
    }
    if let Some(prior) = predecessor {
        row.supersedes = Some(prior);
    }
    Ok(DecisionDetail { row, transitions })
}
fn content(value: &se_store::StoredText) -> Result<String> {
    match value {
        se_store::StoredText::Present(value) => Ok(value.clone()),
        _ => Err(scope::unreadable(
            "decision transition reason",
            "original reason was erased or is unavailable",
        )),
    }
}
