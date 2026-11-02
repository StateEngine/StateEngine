//! Owned planning facts and typed continuations; no writer, clock, RNG or read lease is retained.
use crate::{
    commit::*,
    ops::{inputs::Validate, receipt::receipt_key},
    scope,
    store_error::store_error,
};
use se_store::{
    Actor, AtomicBatch, CommitReceipt, Door, EventBody, EventHeader, Expected, InputText,
    IntentDigest, NewEvent, RequestIdentity, Revision, Snapshot,
};
use se_types::{AgentId, EventId, IdempotencyKey, MessageId, Result, SeError};
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

/// The adapter allocates fresh IDs/time per invocation, before entering the pure planner.
/// These observations are excluded from the normalized intent digest.
#[derive(Clone)]
pub struct CallFacts {
    pub event: EventId,
    pub message: MessageId,
    pub agent: AgentId,
    pub profile_event: EventId,
    pub occurred_at_us: i64,
    pub door: Door,
}
pub struct Kernel {
    facts: Option<CallFacts>,
    configuration: Option<crate::config_policy::ConfigFile>,
}
impl Kernel {
    pub fn new(facts: CallFacts) -> Result<Self> {
        if facts.occurred_at_us < 0 {
            return Err(SeError::invalid(
                "occurred_at",
                "nonnegative Unix microseconds",
            ));
        }
        Ok(Self {
            facts: Some(facts),
            configuration: None,
        })
    }
    pub const fn read_only() -> Self {
        Self {
            facts: None,
            configuration: None,
        }
    }
    /// Already resolved file policy from the admitted native route. This is not
    /// a model-facing operation argument or a fallback to ambient defaults.
    pub fn with_configuration(
        mut self,
        configuration: crate::config_policy::ConfigFile,
    ) -> Result<Self> {
        configuration.validate()?;
        self.configuration = Some(configuration);
        Ok(self)
    }
    pub(crate) fn facts(&self) -> Result<&CallFacts> {
        self.facts.as_ref().ok_or_else(|| {
            SeError::invalid(
                "write allocation",
                "fresh adapter-provided IDs and time before planning a mutation",
            )
        })
    }
    pub(crate) fn event<R: Snapshot>(
        &self,
        body: EventBody<InputText>,
        cx: &Cx<'_, R>,
    ) -> Result<NewEvent> {
        let facts = self.facts()?;
        Ok(NewEvent {
            header: EventHeader {
                event: facts.event.clone(),
                scope: cx.admission.scope.clone(),
                actor: cx.admission.actor.clone(),
                session: cx.admission.session.clone(),
                origin: cx.read.info().id,
                door: facts.door,
                occurred_at_us: facts.occurred_at_us,
                cause: None,
                supersedes: None,
            },
            body,
        })
    }
    pub(crate) fn batch<R: Snapshot>(
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
pub(crate) fn admitted<R: Snapshot>(cx: &Cx<'_, R>) -> Result<()> {
    scope::project(cx.admission)?;
    match (&cx.admission.actor, &cx.admission.session) {
        (Actor::Agent(_), Some(_)) | (Actor::Human(_), None) => Ok(()),
        _ => Err(scope::unreadable(
            "admitted write",
            "actor and session binding disagree",
        )),
    }
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
                message: self.facts()?.message.clone(),
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
        )?;
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
        crate::admission::authorize(op.meta(), cx.admission)?;
        // Direct and hosted adapters provide native observations; enforce the
        // presence policy once here, before any batch or custody plan exists.
        if op.requires_human_terminal()? {
            crate::admission::require_human_terminal(op.meta().name, cx.admission, terminal)?;
        }
        Ok(match op {
            AnyOp::AgentList(input) => {
                OpStep::Complete(crate::ops::listing::agents(input, cx)?.into())
            }
            AnyOp::AgentLaunch(input) => {
                let configuration = self.configuration.as_ref().ok_or_else(|| {
                    scope::unreadable(
                        "launch configuration",
                        "adapter-resolved ConfigFile is not bound",
                    )
                })?;
                OpStep::Custody(CustodyPlan::Launch(Box::new(
                    crate::ops::process_plan::launch(self, input, configuration, cx)?,
                )))
            }
            AnyOp::AgentStop(input) => OpStep::Custody(CustodyPlan::Stop(Box::new(
                crate::ops::stop_plan::plan(input, cx)?,
            ))),
            AnyOp::ProjectRemove(input) => OpStep::Custody(CustodyPlan::Remove(Box::new(
                crate::ops::project_remove::plan(input, cx)?,
            ))),
            AnyOp::AgentShow(input) => {
                OpStep::Complete(crate::ops::agent_status::show(input, cx)?.into())
            }
            AnyOp::ConfigGet(input) => {
                OpStep::Complete(crate::ops::agent_config::get(input, cx)?.into())
            }
            AnyOp::ConfigSet(input) => {
                let configuration=self.configuration.as_ref().ok_or_else(||scope::unreadable("saved agent configuration","adapter-resolved ConfigFile must be bound using Kernel::with_configuration"))?;
                let (batch, then) = crate::ops::agent_config::set(self, input, configuration, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::AgentConfig(then),
                }
            }
            AnyOp::AgentCreate(input) => {
                let configuration = self.configuration.as_ref().ok_or_else(|| {
                    SeError::new(se_types::Detail::Internal(se_types::details::Internal {
                        report_id: "agent-configuration-not-bound".into(),
                        location: "Kernel::with_configuration".into(),
                    }))
                })?;
                let (batch, then) = crate::ops::agent::create(self, input, configuration, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::AgentCreate(then),
                }
            }
            AnyOp::DecisionPropose(input) => {
                let (batch, then) = crate::ops::decision::propose(self, input, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::Decision(then),
                }
            }
            AnyOp::DecisionRatify(input) => {
                let (batch, then) = crate::ops::decision::ratify(self, input, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::Decision(then),
                }
            }
            AnyOp::DecisionReject(input) => {
                let (batch, then) = crate::ops::decision::reject(self, input, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::Decision(then),
                }
            }
            AnyOp::DecisionRetract(input) => {
                let (batch, then) = crate::ops::decision::retract(self, input, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::Decision(then),
                }
            }
            AnyOp::DecisionSupersede(input) => {
                let (batch, then) = crate::ops::decision::supersede(self, input, cx)?;
                OpStep::Commit {
                    batch,
                    then: Then::Decision(then),
                }
            }
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
            AnyOp::DecisionShow(input) => {
                OpStep::Complete(crate::ops::decision_show::read(input, cx)?.into())
            }
            AnyOp::HistoryList(input) => {
                OpStep::Complete(crate::ops::history::list(input, cx)?.into())
            }
            AnyOp::EventRead(input) => OpStep::Complete(crate::ops::event::read(input, cx)?.into()),
            AnyOp::MessageList(input) => {
                OpStep::Complete(crate::ops::message::list(input, cx)?.into())
            }
            AnyOp::ProjectInit(input) => OpStep::Custody(CustodyPlan::Initialize(input)),
            AnyOp::ProjectStatus(input) => OpStep::Custody(CustodyPlan::ObserveStatus(input)),
            AnyOp::RuntimeUp(input) => OpStep::Custody(CustodyPlan::RuntimeUp(input)),
            AnyOp::RuntimeDown(input) => OpStep::Custody(CustodyPlan::RuntimeDown(input)),
            AnyOp::Uninstall(input) => OpStep::Custody(CustodyPlan::Uninstall(input)),
            AnyOp::HookClaude(input) => OpStep::Custody(CustodyPlan::ClaudeHook(input)),
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
        let maintenance_pending = receipt.maintenance_pending;
        let output: Result<crate::ops::AnyOutput> = match then {
            Then::AgentConfig(then) => {
                Ok(crate::ops::agent_config_receipt::committed(then, receipt, cx)?.into())
            }
            Then::AgentCreate(then) => Ok(crate::ops::agent::committed(then, receipt, cx)?.into()),
            Then::Decision(then) => Ok(crate::ops::decision::committed(then, receipt, cx)?.into()),
            Then::Capture(then) => Ok(crate::ops::hook::committed(then, receipt, cx)?.into()),
            Then::MessageSend(then) => {
                let raw = self.message_committed(then, receipt, cx)?;
                Ok(crate::ops::receipt::message(raw, cx)?.into())
            }
            Then::WorkingStateSet(then) => {
                let raw = self.working_state_committed(then, receipt, cx)?;
                Ok(crate::ops::receipt::working_state(raw, cx)?.into())
            }
        };
        output.map(|value| value.with_maintenance_pending(maintenance_pending))
    }
}
