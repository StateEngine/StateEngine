//! `CoreOps` trait implementation and its `PlanStep` bridges for message send
//! and working-state updates.
use super::{Kernel, PlanStep, admitted};
use crate::{
    commit::*,
    ops::{inputs::Validate, receipt::receipt_key},
    scope,
    store_error::store_error,
};
use se_store::{CommitReceipt, EventBody, Expected, InputText, Revision, Snapshot};
use se_types::{Result, SeError};
use std::num::NonZeroU64;

impl CoreOps for Kernel {
    fn message_send<R: Snapshot>(
        &self,
        input: MessageSend,
        cx: &mut Cx<'_, R>,
    ) -> Result<OpStep<MessageSendOutput, MessageSendThen>> {
        crate::ops::message_send_plan::send(self, input, cx)
    }
    fn message_committed<R: Snapshot>(
        &self,
        then: MessageSendThen,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<MessageSendOutput> {
        receipt_key(&receipt, &then.request, "commit receipt")?;
        let event = scope::require_present(
            cx.read
                .event(receipt.primary_event.clone())
                .map_err(|e| store_error(&e))?,
            "committed message event",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
            return Err(scope::unreadable(
                "committed message",
                "receipt resolved outside the admitted scope/actor",
            ));
        }
        match event.body {
            EventBody::MessageSent { message, .. } | EventBody::WorkMessageSent { message, .. } => {
                Ok(MessageSendOutput {
                    message,
                    commit: receipt,
                })
            }
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
        )?;
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
        receipt_key(&receipt, &then.request, "commit receipt")?;
        let event = scope::require_present(
            cx.read
                .event(receipt.primary_event.clone())
                .map_err(|e| store_error(&e))?,
            "committed working-state event",
            scope::COMMITTED_READ_RECOVERY,
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

pub(super) fn message_send_step<R: Snapshot>(
    kernel: &Kernel,
    input: MessageSend,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(match kernel.message_send(input, cx)? {
        OpStep::Complete(raw) => OpStep::Complete(crate::ops::receipt::message(raw, cx)?.into()),
        OpStep::Commit { batch, then } => OpStep::Commit {
            batch,
            then: crate::ports::Then::MessageSend(then),
        },
        OpStep::Custody(never) => match never {},
    })
}

pub(super) fn working_state_set_step<R: Snapshot>(
    kernel: &Kernel,
    input: WorkingStateSet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(match kernel.working_state_set(input, cx)? {
        OpStep::Complete(raw) => {
            OpStep::Complete(crate::ops::receipt::working_state(raw, cx)?.into())
        }
        OpStep::Commit { batch, then } => OpStep::Commit {
            batch,
            then: crate::ports::Then::WorkingStateSet(then),
        },
        OpStep::Custody(never) => match never {},
    })
}
