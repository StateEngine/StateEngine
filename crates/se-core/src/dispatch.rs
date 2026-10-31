//! Owned planning facts and typed continuations; no writer, clock, RNG or read lease is retained.
use crate::{commit::*, ops::inputs::Validate, scope, store_error::store_error};
use se_store::{
    Actor, AtomicBatch, CommitReceipt, Door, EventBody, EventHeader, Expected, InputText,
    IntentDigest, NewEvent, RequestIdentity, Revision, Snapshot,
};
use se_types::{EventId, IdempotencyKey, MessageId, Result, SeError};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

/// The adapter allocates fresh IDs/time per invocation, before entering the pure planner.
/// These observations are excluded from the normalized intent digest.
#[derive(Clone)]
pub struct CallFacts {
    pub event: EventId,
    pub message: MessageId,
    pub occurred_at_us: i64,
    pub door: Door,
}
pub struct Kernel {
    facts: CallFacts,
}
impl Kernel {
    pub fn new(facts: CallFacts) -> Result<Self> {
        if facts.occurred_at_us < 0 {
            return Err(SeError::invalid(
                "occurred_at",
                "nonnegative Unix microseconds",
            ));
        }
        Ok(Self { facts })
    }
    fn event<R: Snapshot>(&self, body: EventBody<InputText>, cx: &Cx<'_, R>) -> NewEvent {
        NewEvent {
            header: EventHeader {
                event: self.facts.event.clone(),
                scope: cx.admission.scope.clone(),
                actor: cx.admission.actor.clone(),
                session: cx.admission.session.clone(),
                origin: cx.read.info().id,
                door: self.facts.door,
                occurred_at_us: self.facts.occurred_at_us,
                cause: None,
                supersedes: None,
            },
            body,
        }
    }
    fn batch<R: Snapshot>(
        &self,
        operation: &'static str,
        key: IdempotencyKey,
        intent: serde_json::Value,
        event: NewEvent,
        cx: &Cx<'_, R>,
    ) -> Result<AtomicBatch> {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"operation":operation,"codec_version":1,"arguments":intent}),
        )
        .map_err(|e| scope::unreadable("normalized operation intent", &e.to_string()))?;
        Ok(AtomicBatch {
            expected_incarnation: cx.read.info().incarnation,
            admission: cx.admission.clone(),
            request: Some(RequestIdentity {
                key,
                intent: IntentDigest {
                    operation,
                    codec_version: 1,
                    sha256: Sha256::digest(bytes).into(),
                },
            }),
            events: vec![event],
            import_checkpoint: None,
        })
    }
}
fn admitted<R: Snapshot>(cx: &Cx<'_, R>) -> Result<()> {
    scope::project(cx.admission)?;
    match (&cx.admission.actor, &cx.admission.session) {
        (Actor::Agent(_), Some(_)) | (Actor::Human(_), None) => Ok(()),
        _ => Err(scope::unreadable(
            "admitted write",
            "actor and session binding disagree",
        )),
    }
}
fn receipt_key(receipt: &CommitReceipt, expected: &IdempotencyKey) -> Result<()> {
    if receipt.request_key.as_ref() != Some(expected)
        || !receipt.events.contains(&receipt.primary_event)
    {
        return Err(scope::unreadable(
            "commit receipt",
            "request identity or primary event does not match the continuation",
        ));
    }
    Ok(())
}
impl CoreOps for Kernel {
    fn message_send<R: Snapshot>(
        &self,
        input: MessageSend,
        cx: &mut Cx<'_, R>,
    ) -> Result<OpStep<MessageSendOutput, MessageSendThen>> {
        input.validate()?;
        admitted(cx)?;
        let recipient = scope::actor_selector(cx.read, &input.to)?;
        let registry = cx.read.legacy_registry().map_err(|e| store_error(&e))?;
        let refs = input
            .refs
            .iter()
            .map(|id| {
                EventId::from_legacy(id.clone())
                    .or_else(|_| EventId::from_registered_legacy(id.clone(), &registry))
            })
            .collect::<Result<Vec<_>>>()?;
        drop(registry);
        let kind = serde_json::to_value(&input.kind)
            .map_err(|e| scope::unreadable("message kind", &e.to_string()))?;
        let intent = serde_json::json!({"recipient":scope::actor_id(&recipient),"kind":kind,"body":input.body,"refs":refs,"reply_to":input.reply_to});
        let key = input.idempotency_key;
        let event = self.event(
            EventBody::MessageSent {
                message: self.facts.message.clone(),
                recipient,
                kind: kind
                    .as_str()
                    .ok_or_else(|| SeError::invalid("message kind", "registered string"))?
                    .into(),
                body: InputText::Inline(input.body),
                refs,
                reply_to: input.reply_to,
            },
            cx,
        );
        let batch = self.batch("message.send", key.clone(), intent, event, cx)?;
        Ok(OpStep::Commit {
            batch,
            then: MessageSendThen { request: key },
        })
    }
    fn message_committed<R: Snapshot>(
        &self,
        then: MessageSendThen,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<MessageSendOutput> {
        receipt_key(&receipt, &then.request)?;
        let event = scope::require_present(
            cx.read
                .event(receipt.primary_event.clone())
                .map_err(|e| store_error(&e))?,
            "committed message event",
        )?;
        if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
            return Err(scope::unreadable(
                "committed message",
                "receipt resolved outside the admitted scope/actor",
            ));
        }
        match event.body {
            EventBody::MessageSent { message, .. } => Ok(MessageSendOutput {
                message,
                commit: receipt,
            }),
            _ => Err(scope::unreadable(
                "message receipt",
                "primary event is not message.sent",
            )),
        }
    }
    fn working_state_set<R: Snapshot>(
        &self,
        input: WorkingStateSet,
        cx: &mut Cx<'_, R>,
    ) -> Result<OpStep<WorkingStateSetOutput, WorkingStateSetThen>> {
        input.validate()?;
        admitted(cx)?;
        let agent = scope::working_agent(
            cx.admission,
            input.owner_agent.as_ref(),
            "working_state.set",
        )?;
        let expected = match input.expect {
            ExpectedRevision::Absent(_) => Expected::Absent,
            ExpectedRevision::Revision(revision) => Expected::Revision(Revision {
                value: NonZeroU64::new(revision)
                    .ok_or_else(|| SeError::invalid("expect", "a positive revision"))?,
            }),
        };
        let key = input.idempotency_key;
        let intent = serde_json::json!({"agent":agent,"text":input.text,"expect":input.expect});
        let event = self.event(
            EventBody::WorkingStateSet {
                agent: agent.clone(),
                text: InputText::Inline(input.text),
                expected,
            },
            cx,
        );
        let batch = self.batch("working_state.set", key.clone(), intent, event, cx)?;
        Ok(OpStep::Commit {
            batch,
            then: WorkingStateSetThen {
                request: key,
                agent,
            },
        })
    }
    fn working_state_committed<R: Snapshot>(
        &self,
        then: WorkingStateSetThen,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<WorkingStateSetOutput> {
        receipt_key(&receipt, &then.request)?;
        let event = scope::require_present(
            cx.read
                .event(receipt.primary_event.clone())
                .map_err(|e| store_error(&e))?,
            "committed working-state event",
        )?;
        if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
            return Err(scope::unreadable(
                "committed working state",
                "receipt resolved outside the admitted scope/actor",
            ));
        }
        match event.body {
            EventBody::WorkingStateSet { agent, .. } if agent == then.agent => {
                Ok(WorkingStateSetOutput {
                    agent,
                    commit: receipt,
                })
            }
            _ => Err(scope::unreadable(
                "working-state receipt",
                "primary event is not this agent's working_state.set",
            )),
        }
    }
}

impl Kernel {
    /// The host releases the finite snapshot/worker after this returns, awaits
    /// only the store completion, then opens a fresh admitted continuation read.
    pub fn plan<R: Snapshot>(
        &self,
        op: crate::ops::AnyOp,
        cx: &mut Cx<'_, R>,
        terminal: &crate::admission::HumanTerminal,
    ) -> Result<OpStep<crate::ops::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>> {
        use crate::{
            ops::AnyOp,
            ports::{CustodyPlan, Then},
        };
        if let Some(output) = crate::ops::metadata_output(&op)? {
            return Ok(OpStep::Complete(output));
        }
        op.validate()?;
        crate::admission::authorize(op.meta(), cx.admission, terminal)?;
        Ok(match op {
            AnyOp::MessageSend(input) => match self.message_send(input, cx)? {
                OpStep::Complete(raw) => {
                    OpStep::Complete(crate::ops::receipt::message(raw, cx)?.into())
                }
                OpStep::Commit { batch, then } => OpStep::Commit {
                    batch,
                    then: Then::MessageSend(then),
                },
                OpStep::Custody(never) => match never {},
            },
            AnyOp::WorkingStateSet(input) => match self.working_state_set(input, cx)? {
                OpStep::Complete(raw) => {
                    OpStep::Complete(crate::ops::receipt::working_state(raw, cx)?.into())
                }
                OpStep::Commit { batch, then } => OpStep::Commit {
                    batch,
                    then: Then::WorkingStateSet(then),
                },
                OpStep::Custody(never) => match never {},
            },
            AnyOp::WorkingStateGet(input) => OpStep::Complete(
                crate::ops::receipt::working_state_get(
                    scope::working_agent(
                        cx.admission,
                        input.owner_agent.as_ref(),
                        "working_state.get",
                    )?,
                    cx,
                )?
                .into(),
            ),
            AnyOp::MessageList(input) => {
                OpStep::Complete(crate::ops::message::list(input, cx)?.into())
            }
            AnyOp::ProjectInit(input) => OpStep::Custody(CustodyPlan::Initialize(input)),
            AnyOp::ProjectStatus(input) => OpStep::Custody(CustodyPlan::ObserveStatus(input)),
            AnyOp::RuntimeUp(input) => OpStep::Custody(CustodyPlan::RuntimeUp(input)),
            AnyOp::RuntimeDown(input) => OpStep::Custody(CustodyPlan::RuntimeDown(input)),
            AnyOp::Uninstall(input) => OpStep::Custody(CustodyPlan::Uninstall(input)),
            AnyOp::MetaVersion(_) | AnyOp::MetaHelp(_) | AnyOp::MetaSchema(_) => {
                return Err(scope::unreadable(
                    "metadata dispatch",
                    "registered metadata produced no output",
                ));
            }
        })
    }
    pub fn committed<R: Snapshot>(
        &self,
        then: crate::ports::Then,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<crate::ops::AnyOutput> {
        use crate::ports::Then;
        match then {
            Then::MessageSend(then) => {
                let raw = self.message_committed(then, receipt, cx)?;
                Ok(crate::ops::receipt::message(raw, cx)?.into())
            }
            Then::WorkingStateSet(then) => {
                let raw = self.working_state_committed(then, receipt, cx)?;
                Ok(crate::ops::receipt::working_state(raw, cx)?.into())
            }
        }
    }
}
