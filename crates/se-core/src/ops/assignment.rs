//! Bounded reads of durable project assignments.
use crate::{commit::Cx, ops::inputs::Validate, scope, store_error::store_error};
use schemars::JsonSchema;
use se_store::{EventBody, ReadBudget, Snapshot};
use se_types::{AgentId, Cursor, EventId, Page, PageRequest, Result, SeError};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU32, time::Duration};

pub(crate) fn require_closed<R: Snapshot>(cx: &mut Cx<'_, R>, subject: &str) -> Result<()> {
    let budget = se_store::ReadBudget {
        page: se_types::PageRequest {
            after: None,
            limit: std::num::NonZeroU32::new(1)
                .ok_or_else(|| SeError::invalid("assignment limit", "positive"))?,
            max_bytes: std::num::NonZeroU32::new(192 * 1024)
                .ok_or_else(|| SeError::invalid("assignment bytes", "positive"))?,
        },
        deadline: std::time::Duration::from_secs(5),
    };
    let page = cx
        .read
        .open_assignments(budget)
        .map_err(|error| store_error(&error))?;
    if !page.items().is_empty() {
        return Err(SeError::invalid(
            subject,
            "finish or hand back open and blocked assignments first",
        ));
    }
    if !page.window().complete() {
        return Err(scope::unreadable(
            subject,
            "the bounded check did not establish that all assignments are closed",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssignmentList {
    #[serde(default = "default_limit")]
    pub limit: u16,
    #[serde(default)]
    pub cursor: Option<Cursor>,
}
fn default_limit() -> u16 {
    20
}
impl Validate for AssignmentList {
    fn validate(&self) -> Result<()> {
        if !(1..=100).contains(&self.limit) {
            return Err(SeError::invalid("limit", "1..100 assignments per page"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AssignmentRow {
    pub id: EventId,
    pub assignee: AgentId,
    pub state: String,
    pub revision: u64,
    pub latest_event: EventId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AssignmentPage {
    pub project: se_types::Named<se_types::ProjectId>,
    pub consistency: String,
    #[serde(flatten)]
    pub page: Page<AssignmentRow>,
}
pub fn list<R: Snapshot>(input: AssignmentList, cx: &mut Cx<'_, R>) -> Result<AssignmentPage> {
    input.validate()?;
    let budget = ReadBudget {
        page: PageRequest {
            after: input.cursor,
            limit: NonZeroU32::new(u32::from(input.limit))
                .ok_or_else(|| SeError::invalid("limit", "positive"))?,
            max_bytes: NonZeroU32::new(192 * 1024)
                .ok_or_else(|| SeError::invalid("assignment bytes", "positive"))?,
        },
        deadline: Duration::from_secs(5),
    };
    let page = cx
        .read
        .open_assignments(budget)
        .map_err(|e| store_error(&e))?;
    let window = page.window().clone();
    let next = page.next().cloned();
    let mut rows = Vec::new();
    for record in page.into_items() {
        let original = record.original.as_deref().unwrap_or(&record.current);
        let EventBody::AssignmentOpened {
            assignment,
            assignee,
            ..
        } = &original.body
        else {
            return Err(scope::unreadable(
                "assignment",
                "opening event has the wrong kind",
            ));
        };
        let state = match &record.current.body {
            EventBody::AssignmentOpened { .. } => "open",
            EventBody::AssignmentTransitioned {
                action: se_store::assignment::AssignmentTransition::Accept,
                ..
            } => "working",
            EventBody::AssignmentTransitioned {
                action: se_store::assignment::AssignmentTransition::Block,
                ..
            } => "blocked",
            _ => {
                return Err(scope::unreadable(
                    "assignment",
                    "open projection has the wrong event",
                ));
            }
        };
        rows.push(AssignmentRow {
            id: assignment.clone(),
            assignee: assignee.clone(),
            state: state.into(),
            revision: record.revision.value.get(),
            latest_event: record.current.header.event,
        });
    }
    Ok(AssignmentPage {
        project: super::receipt::named_project(cx)?,
        consistency: "live-keyset".into(),
        page: Page::new(rows, window, next)?,
    })
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentAction {
    Open,
    Accept,
    Done,
    Block,
    HandBack,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssignmentWrite {
    pub action: AssignmentAction,
    #[serde(default)]
    pub assignment: Option<EventId>,
    #[serde(default)]
    pub assignee: Option<String>,
    pub body: String,
    pub idempotency_key: se_types::IdempotencyKey,
}
impl Validate for AssignmentWrite {
    fn validate(&self) -> Result<()> {
        if self.body.trim().is_empty() || self.body.len() > se_types::MESSAGE_BODY_MAX_BYTES {
            return Err(SeError::invalid(
                "body",
                "a nonempty assignment message within the message limit",
            ));
        }
        match (&self.action, &self.assignment, &self.assignee) {
            (AssignmentAction::Open, None, Some(name)) if !name.is_empty() && name.len() <= 256 => {
                Ok(())
            }
            (
                AssignmentAction::Accept
                | AssignmentAction::Done
                | AssignmentAction::Block
                | AssignmentAction::HandBack,
                Some(_),
                None,
            ) => Ok(()),
            _ => Err(SeError::invalid(
                "assignment",
                "an assignee for open, or an assignment ID for a transition",
            )),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AssignmentWriteOutput {
    pub assignment: EventId,
    pub state: String,
    pub commit: se_types::WriteReceipt,
}
pub struct AssignmentThen {
    pub key: se_types::IdempotencyKey,
}

pub(crate) fn current_captain<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<se_store::Actor> {
    match cx.read.project_captain().map_err(|e| store_error(&e))? {
        se_types::Read::Present { value } => match value.current.body {
            EventBody::ProjectCaptainChanged {
                captain: Some(actor),
                ..
            } => Ok(actor),
            EventBody::ProjectCaptainChanged { captain: None, .. } => Err(SeError::invalid(
                "captain",
                "set a project captain with se captain set, or specify a recipient",
            )),
            _ => Err(scope::unreadable(
                "captain",
                "designation event has the wrong kind",
            )),
        },
        se_types::Read::Absent { .. } => Err(SeError::invalid(
            "captain",
            "set a project captain with se captain set, or specify a recipient",
        )),
        other => {
            scope::require_present(
                other,
                "captain",
                "Run se up or restore access to the project store, then retry.",
            )?;
            Err(scope::unreadable("captain", "unexpected present value"))
        }
    }
}
fn existing<R: Snapshot>(cx: &mut Cx<'_, R>, id: EventId) -> Result<(AgentId, se_store::Expected)> {
    let record = scope::require_present(
        cx.read.assignment(id).map_err(|e| store_error(&e))?,
        "assignment",
        "Check the assignment ID and project, then retry.",
    )?;
    let original = record.original.as_deref().unwrap_or(&record.current);
    let EventBody::AssignmentOpened { assignee, .. } = &original.body else {
        return Err(scope::unreadable(
            "assignment",
            "opening event has the wrong kind",
        ));
    };
    Ok((
        assignee.clone(),
        se_store::Expected::Revision(record.revision),
    ))
}

pub fn write<R: Snapshot>(
    kernel: &crate::dispatch::Kernel,
    input: AssignmentWrite,
    cx: &mut Cx<'_, R>,
) -> Result<crate::commit::OpStep<super::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>>
{
    use crate::commit::OpStep;
    input.validate()?;
    crate::dispatch::admitted(cx)?;
    let intent = serde_json::json!({"action": input.action, "assignment": input.assignment, "assignee": input.assignee, "body": input.body});
    let identity =
        kernel.request_identity("assignment.write", input.idempotency_key.clone(), &intent)?;
    match cx
        .read
        .resolve_request(&identity)
        .map_err(|e| store_error(&e))?
    {
        se_types::Read::Present { value } => {
            return Ok(OpStep::Complete(committed(
                AssignmentThen {
                    key: input.idempotency_key,
                },
                value,
                cx,
            )?));
        }
        se_types::Read::Absent { .. } => {}
        other => {
            scope::require_present(
                other,
                "assignment receipt",
                "Restore access to the store and retry the same key.",
            )?;
            return Err(scope::unreadable(
                "assignment receipt",
                "unexpected present value",
            ));
        }
    }
    let captain = current_captain(cx)?;
    build_write(kernel, input, cx, captain, identity)
}

fn authorize_action(
    action: AssignmentAction,
    actor: &se_store::Actor,
    captain: &se_store::Actor,
    assignee: &AgentId,
) -> Result<()> {
    let is_owner = matches!(actor, se_store::Actor::Human(_));
    let is_assignee = matches!(actor, se_store::Actor::Agent(id) if id == assignee);
    let is_captain = actor == captain;
    let allowed = match action {
        AssignmentAction::Open => is_owner || is_captain,
        AssignmentAction::Accept => is_assignee,
        AssignmentAction::Done | AssignmentAction::Block | AssignmentAction::HandBack => {
            is_owner || is_captain || is_assignee
        }
    };
    if allowed {
        return Ok(());
    }
    let next = match action {
        AssignmentAction::Open => "Ask the project captain or owner to open the assignment.",
        AssignmentAction::Accept => "Ask the assigned agent to accept the assignment.",
        _ => "Ask the assigned agent, project captain, or owner to record the outcome.",
    };
    Err(SeError::new(se_types::Detail::CapabilityInvalid(
        se_types::details::CapabilityInvalid {
            subject: "assignment action".into(),
            reason: "the admitted actor cannot perform this assignment action".into(),
            next_step: next.into(),
        },
    )))
}

fn action_parts(
    action: AssignmentAction,
) -> (
    se_types::WorkAction,
    &'static str,
    Option<se_store::assignment::AssignmentTransition>,
) {
    match action {
        AssignmentAction::Open => (se_types::WorkAction::Assign, "task", None),
        AssignmentAction::Accept => (
            se_types::WorkAction::Notify,
            "note",
            Some(se_store::assignment::AssignmentTransition::Accept),
        ),
        AssignmentAction::Done => (
            se_types::WorkAction::Notify,
            "done",
            Some(se_store::assignment::AssignmentTransition::Done),
        ),
        AssignmentAction::Block => (
            se_types::WorkAction::Notify,
            "blocker",
            Some(se_store::assignment::AssignmentTransition::Block),
        ),
        AssignmentAction::HandBack => (
            se_types::WorkAction::Return,
            "handoff",
            Some(se_store::assignment::AssignmentTransition::HandBack),
        ),
    }
}

fn build_write<R: Snapshot>(
    kernel: &crate::dispatch::Kernel,
    input: AssignmentWrite,
    cx: &mut Cx<'_, R>,
    captain: se_store::Actor,
    identity: se_store::RequestIdentity,
) -> Result<crate::commit::OpStep<super::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>>
{
    let facts = kernel.facts()?;
    let (assignee, assignment, expected) = match &input.action {
        AssignmentAction::Open => {
            let selector = input
                .assignee
                .as_deref()
                .ok_or_else(|| SeError::invalid("assignee", "a project agent"))?;
            let se_store::Actor::Agent(agent) = scope::selected_actor(cx, selector)? else {
                return Err(SeError::invalid("assignee", "a registered project agent"));
            };
            (agent, facts.event.clone(), se_store::Expected::Absent)
        }
        _ => {
            let id = input
                .assignment
                .clone()
                .ok_or_else(|| SeError::invalid("assignment", "an assignment ID"))?;
            let (assignee, expected) = existing(cx, id.clone())?;
            (assignee, id, expected)
        }
    };
    authorize_action(input.action, &cx.admission.actor, &captain, &assignee)?;
    let mut addressees = vec![assignee.clone()];
    if let se_store::Actor::Agent(agent) = &captain
        && !addressees.contains(agent)
    {
        addressees.push(agent.clone());
    }
    let (work_action, kind, transition) = action_parts(input.action);
    let refs = if transition.is_some() {
        vec![assignment.clone()]
    } else {
        vec![]
    };
    let floor = kernel.event(
        EventBody::WorkMessageSent {
            message: facts.message.clone(),
            work: se_types::WorkAddressing {
                action: work_action,
                addressees,
            },
            kind: kind.into(),
            body: se_store::InputText::Inline(input.body.clone()),
            refs: refs.clone(),
            reply_to: None,
            quiet: false,
        },
        cx,
    )?;
    let body = match transition {
        None => EventBody::AssignmentOpened {
            project: scope::project(cx.admission)?,
            assignment: assignment.clone(),
            assignee,
            captain: captain.clone(),
            floor_event: facts.event.clone(),
            expected,
        },
        Some(action) => EventBody::AssignmentTransitioned {
            assignment: assignment.clone(),
            action,
            captain: captain.clone(),
            floor_event: facts.event.clone(),
            expected,
        },
    };
    let mut record = kernel.event(body, cx)?;
    record.header.event = facts.profile_event.clone();
    let mut batch = kernel.batch_with_identity(identity, floor, cx)?;
    batch.events.push(record);
    if matches!(kind, "done" | "blocker" | "handoff")
        && matches!(captain, se_store::Actor::Human(_))
    {
        let mut direct = kernel.event(
            EventBody::MessageSent {
                message: facts.notification_message.clone(),
                recipient: captain,
                kind: kind.into(),
                body: se_store::InputText::Inline(input.body),
                refs,
                reply_to: None,
                quiet: false,
            },
            cx,
        )?;
        direct.header.event = facts.notification_event.clone();
        batch.events.push(direct);
    }
    Ok(crate::commit::OpStep::Commit {
        batch,
        then: crate::ports::Then::Assignment(AssignmentThen {
            key: input.idempotency_key,
        }),
    })
}

pub fn committed<R: Snapshot>(
    then: AssignmentThen,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::AnyOutput> {
    super::receipt::receipt_key(&receipt, &then.key, "assignment receipt")?;
    let primary = super::receipt::committed_event(cx.read, &receipt)?;
    let commit = super::receipt::write_fields(&receipt, &primary)?;
    let mut result = None;
    for id in &receipt.events {
        let event = scope::require_present(
            cx.read.event(id.clone()).map_err(|e| store_error(&e))?,
            "assignment event",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        let pair = match event.body {
            EventBody::AssignmentOpened { assignment, .. } => Some((assignment, "open")),
            EventBody::AssignmentTransitioned {
                assignment, action, ..
            } => {
                use se_store::assignment::AssignmentTransition::*;
                Some((
                    assignment,
                    match action {
                        Accept => "working",
                        Done => "done",
                        Block => "blocked",
                        HandBack => "handed_back",
                    },
                ))
            }
            _ => None,
        };
        if let Some(pair) = pair
            && result.replace(pair).is_some()
        {
            return Err(scope::unreadable(
                "assignment receipt",
                "multiple assignment events",
            ));
        }
    }
    let (assignment, state) = result
        .ok_or_else(|| scope::unreadable("assignment receipt", "missing assignment event"))?;
    Ok(AssignmentWriteOutput {
        assignment,
        state: state.into(),
        commit,
    }
    .into())
}
