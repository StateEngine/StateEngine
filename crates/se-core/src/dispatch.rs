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
    pub notification_event: EventId,
    pub notification_message: MessageId,
    pub occurred_at_us: i64,
    pub door: Door,
}
pub struct Kernel {
    facts: Option<CallFacts>,
    configuration: Option<se_config::config_policy::ConfigFile>,
    config_origin: Option<String>,
    read_at: Option<se_types::UnixMicros>,
    command_home: Option<std::path::PathBuf>,
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
            config_origin: None,
            read_at: None,
            command_home: None,
        })
    }
    pub const fn read_only() -> Self {
        Self {
            facts: None,
            configuration: None,
            config_origin: None,
            read_at: None,
            command_home: None,
        }
    }
    pub fn read_only_at(at: se_types::UnixMicros) -> Self {
        Self {
            facts: None,
            configuration: None,
            config_origin: None,
            read_at: Some(at),
            command_home: None,
        }
    }
    /// Adapter-resolved presentation scope, never a model-supplied selector.
    pub fn with_command_home(mut self, home: &std::path::Path) -> Self {
        self.command_home = Some(home.to_owned());
        self
    }
    fn observed_at(&self) -> Result<se_types::UnixMicros> {
        match (self.read_at, self.facts.as_ref()) {
            (Some(at), _) => Ok(at),
            (_, Some(facts)) => {
                se_types::UnixMicros::new(u64::try_from(facts.occurred_at_us).map_err(|_| {
                    SeError::invalid("observation clock", "nonnegative Unix microseconds")
                })?)
            }
            _ => Err(SeError::invalid(
                "continuity clock",
                "an adapter-supplied observation time on this read-only kernel",
            )),
        }
    }
    /// Already resolved file policy from the admitted native route. This is not
    /// a model-facing operation argument or a fallback to ambient defaults.
    pub fn with_configuration(
        mut self,
        configuration: se_config::config_policy::ConfigFile,
    ) -> Result<Self> {
        configuration.validate()?;
        self.configuration = Some(configuration);
        Ok(self)
    }
    /// Adapter-resolved origin of the bound configuration. Adapters that do
    /// not carry one leave it absent; origins are never invented.
    pub fn with_config_origin(mut self, origin: String) -> Self {
        self.config_origin = Some(origin);
        self
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
    pub(crate) fn request_identity(
        &self,
        operation: &'static str,
        key: IdempotencyKey,
        intent: &serde_json::Value,
    ) -> Result<RequestIdentity> {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"operation":operation,"codec_version":1,"arguments":intent}),
        )
        .map_err(|e| scope::unreadable("normalized operation intent", &e.to_string()))?;
        Ok(RequestIdentity {
            key,
            intent: IntentDigest {
                operation,
                codec_version: 1,
                sha256: Sha256::digest(bytes).into(),
            },
        })
    }
    pub(crate) fn batch_with_identity<R: Snapshot>(
        &self,
        identity: RequestIdentity,
        event: NewEvent,
        cx: &Cx<'_, R>,
    ) -> Result<AtomicBatch> {
        Ok(AtomicBatch {
            expected_incarnation: cx.read.info().incarnation,
            admission: cx.admission.clone(),
            request: Some(identity),
            events: vec![event],
            import_checkpoint: None,
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
        let identity = self.request_identity(operation, key, &intent)?;
        self.batch_with_identity(identity, event, cx)
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

impl Kernel {
    /// The host releases the finite snapshot/worker after this returns, awaits
    /// only the store completion, then opens a fresh admitted continuation read.
    pub fn plan<R: Snapshot>(
        &self,
        op: crate::ops::AnyOp,
        cx: &mut Cx<'_, R>,
        terminal: &crate::admission::HumanTerminal,
    ) -> Result<OpStep<crate::ops::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>> {
        use crate::{ops::AnyOp, ports::CustodyPlan};
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
        match op {
            AnyOp::AtlasFind(input) => plan_atlas_read(crate::ops::AtlasRead::Find(input)),
            AnyOp::AtlasRefs(input) => plan_atlas_read(crate::ops::AtlasRead::Refs(input)),
            AnyOp::AtlasImpact(input) => plan_atlas_read(crate::ops::AtlasRead::Impact(input)),
            AnyOp::AtlasChanges(input) => plan_atlas_read(crate::ops::AtlasRead::Changes(input)),
            AnyOp::AtlasOutline(input) => plan_atlas_read(crate::ops::AtlasRead::Outline(input)),
            AnyOp::ClientWatch(_)
            | AnyOp::RemotePrepareSend(_)
            | AnyOp::RemoteList(_)
            | AnyOp::RemoteWatch(_)
            | AnyOp::RemoteSend(_)
            | AnyOp::RemoteLaunch(_) => Err(remote_refused()),
            AnyOp::Resume(input) => plan_resume(self, input, cx),
            AnyOp::HandoffExport(input) => {
                complete_step(crate::ops::continuity::handoff::export(input, cx))
            }
            AnyOp::SessionContext(input) => plan_session_context(self, input, cx),
            AnyOp::AgentList(input) => plan_agent_list(input, cx),
            AnyOp::AgentLaunch(input) => plan_agent_launch(self, input, cx),
            AnyOp::AgentStop(input) => plan_agent_stop(input, cx),
            AnyOp::AgentWake(input) => plan_agent_wake(input, cx),
            AnyOp::DelegateStart(i) => {
                crate::delegate::step_start(self, i, self.configuration.as_ref(), cx)
            }
            AnyOp::DelegateCancel(i) => crate::delegate::step_cancel(i, cx),
            AnyOp::ProjectRemove(input) => plan_project_remove(input, cx),
            AnyOp::AgentShow(input) => plan_agent_show(input, cx),
            AnyOp::AssignmentWrite(input) => crate::ops::assignment::write(self, input, cx),
            AnyOp::AssignmentList(input) => plan_assignment_list(input, cx),
            AnyOp::CaptainShow(_) => complete_step(crate::ops::captain::show(cx)),
            AnyOp::CaptainSet(input) => plan_captain_set(self, input, cx),
            AnyOp::CaptainClear(input) => plan_captain_clear(self, input, cx),
            AnyOp::ConfigGet(input) => plan_config_get(input, cx),
            AnyOp::ConfigSet(input) => plan_config_set(self, input, cx),
            AnyOp::ConfigList(input) => plan_config_list(self, input),
            AnyOp::AgentCreate(input) => plan_agent_create(self, input, cx),
            AnyOp::AgentRename(input) => plan_agent_rename(self, input, cx),
            AnyOp::MessageRead(input) => plan_message_read(self, input, cx),
            AnyOp::MessageAck(input) => plan_message_ack(self, input, cx),
            AnyOp::MessageDismiss(input) => plan_message_dismiss(self, input, cx),
            AnyOp::MessageSend(input) => message_send_step(self, input, cx),
            AnyOp::WorkingStateSet(input) => working_state_set_step(self, input, cx),
            AnyOp::WorkingStateGet(input) => plan_working_state_get(input, cx),
            AnyOp::IdentityWhoami(input) => plan_identity_whoami(input, cx),
            AnyOp::HistoryList(input) => plan_history_list(input, cx),
            AnyOp::HistorySearch(input) => plan_history_search(input, cx),
            AnyOp::EventRead(input) => complete_step(crate::ops::event::read(input, cx)),
            AnyOp::MessageList(input) => plan_message_list(input, cx),
            AnyOp::MessageInbox(input) => plan_message_inbox(input, cx),
            AnyOp::DiagnosticBundle(_) | AnyOp::StoreRestore(_) => Err(home_owner_refused()),
            AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_) => Err(doctor_refused()),
            AnyOp::ProjectInit(input) => Ok(OpStep::Custody(CustodyPlan::Initialize(input))),
            // The owner CLI route performs the native git identity proof and
            // commits the roots revision directly; the kernel never plans it.
            AnyOp::ProjectMove(_) => Err(project_move_refused()),
            #[cfg(feature = "import")]
            AnyOp::ImportNode(input) => Ok(OpStep::Custody(CustodyPlan::ImportNode(input))),
            AnyOp::StoreForget(input) => Ok(OpStep::Custody(CustodyPlan::Forget(input))),
            AnyOp::ProjectStatus(input) => Ok(OpStep::Custody(CustodyPlan::ObserveStatus(input))),
            AnyOp::RuntimeUp(input) => Ok(OpStep::Custody(CustodyPlan::RuntimeUp(input))),
            AnyOp::RuntimeDown(input) => Ok(OpStep::Custody(CustodyPlan::RuntimeDown(input))),
            AnyOp::Uninstall(input) => Ok(OpStep::Custody(CustodyPlan::Uninstall(input))),
            AnyOp::AtlasAugment(input) => Ok(OpStep::Custody(CustodyPlan::AtlasAugment(input))),
            AnyOp::HookClaude(input) => Ok(OpStep::Custody(CustodyPlan::ClaudeHook(input))),
            AnyOp::MetaVersion(_)
            | AnyOp::MetaHelp(_)
            | AnyOp::MetaGuide(_)
            | AnyOp::MetaSchema(_) => Err(metadata_refused()),
        }
    }
    pub fn committed<R: Snapshot>(
        &self,
        then: crate::ports::Then,
        receipt: CommitReceipt,
        cx: &mut Cx<'_, R>,
    ) -> Result<crate::ops::AnyOutput> {
        use crate::ports::Then;
        let maintenance_failed = receipt.maintenance_failed;
        let output: Result<crate::ops::AnyOutput> = match then {
            Then::Assignment(then) => crate::ops::assignment::committed(then, receipt, cx),
            Then::Captain(then) => crate::ops::captain::committed(then, receipt, cx),
            Then::AgentConfig(then) => {
                Ok(crate::ops::agent_config_receipt::committed(then, receipt, cx)?.into())
            }
            Then::ProjectMove(then) => {
                Ok(crate::ops::project::move_committed(then, receipt, cx)?.into())
            }
            Then::AgentCreate(then) => Ok(crate::ops::agent::committed(then, receipt, cx)?.into()),
            Then::AgentRename(then) => {
                Ok(crate::ops::agent::rename_committed(then, receipt, cx)?.into())
            }
            Then::Capture(then) => Ok(crate::ops::hook::committed(then, receipt, cx)?.into()),
            Then::MessageMark(then) => crate::ops::message_mark::committed(cx, then, receipt),
            Then::MessageSend(then) => {
                let raw = self.message_committed(then, receipt, cx)?;
                Ok(crate::ops::receipt::message(raw, cx)?.into())
            }
            Then::WorkingStateSet(then) => {
                let raw = self.working_state_committed(then, receipt, cx)?;
                Ok(crate::ops::receipt::working_state(raw, cx)?.into())
            }
        };
        output.map(|value| value.with_maintenance_pending(maintenance_failed))
    }
}

/// The step, continuation and custody plan shared by every dispatched operation.
type PlanStep = OpStep<crate::ops::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>;

fn complete_step<T>(result: Result<T>) -> Result<PlanStep>
where
    T: Into<crate::ops::AnyOutput>,
{
    result.map(|value| OpStep::Complete(value.into()))
}

fn plan_atlas_read(read: crate::ops::AtlasRead) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::AtlasRead(
        Box::new(read),
    )))
}

fn remote_refused() -> SeError {
    SeError::invalid(
        "remote execution",
        "the protected source host broker; no direct store or Owner fallback",
    )
}

fn plan_resume<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::Resume,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::continuity::resume_at_home(
            input,
            kernel.observed_at()?,
            kernel.command_home.as_deref(),
            cx,
        )?
        .into(),
    ))
}

fn plan_session_context<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::SessionContextRequest,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::continuity::context_at_home(
            input,
            kernel.observed_at()?,
            kernel.command_home.as_deref(),
            cx,
        )?
        .into(),
    ))
}

fn plan_agent_list<R: Snapshot>(
    input: crate::ops::AgentList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::listing::agents(input, cx)?.into(),
    ))
}

fn plan_agent_launch<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::AgentLaunch,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        scope::unreadable(
            "launch configuration",
            "adapter-resolved ConfigFile is not bound",
        )
    })?;
    Ok(OpStep::Custody(crate::ports::CustodyPlan::Launch(
        Box::new(crate::ops::process_plan::launch(
            kernel,
            input,
            configuration,
            cx,
        )?),
    )))
}

fn plan_agent_stop<R: Snapshot>(
    input: crate::ops::AgentStop,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::Stop(Box::new(
        crate::ops::stop_plan::plan(input, cx)?,
    ))))
}

fn plan_agent_wake<R: Snapshot>(
    input: crate::ops::AgentWake,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::AgentWake(
        crate::ops::agent_wake::plan(input, cx)?,
    )))
}

fn plan_project_remove<R: Snapshot>(
    input: crate::ops::ProjectRemove,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Custody(crate::ports::CustodyPlan::Remove(
        Box::new(crate::ops::project_remove::plan(input, cx)?),
    )))
}

fn plan_agent_show<R: Snapshot>(
    input: crate::ops::AgentShow,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::agent_status::show(input, cx)?.into(),
    ))
}

fn plan_assignment_list<R: Snapshot>(
    input: crate::ops::AssignmentList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::assignment::list(input, cx)?.into(),
    ))
}

fn plan_captain_set<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::CaptainSet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::captain::step(kernel, Some(input.captain), input.idempotency_key, cx)
}

fn plan_captain_clear<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::CaptainClear,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::captain::step(kernel, None, input.idempotency_key, cx)
}

fn plan_config_get<R: Snapshot>(
    input: crate::ops::ConfigGet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::agent_config::get(input, cx)?.into(),
    ))
}

fn plan_config_set<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::ConfigSet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        scope::unreadable(
            "saved agent configuration",
            "adapter-resolved ConfigFile must be bound using Kernel::with_configuration",
        )
    })?;
    let (batch, then) = crate::ops::agent_config::set(kernel, input, configuration, cx)?;
    Ok(OpStep::Commit {
        batch,
        then: crate::ports::Then::AgentConfig(then),
    })
}

fn plan_config_list(kernel: &Kernel, input: crate::ops::ConfigList) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        scope::unreadable(
            "configuration",
            "adapter-resolved ConfigFile must be bound using Kernel::with_configuration",
        )
    })?;
    Ok(OpStep::Complete(
        crate::ops::config_listing::list(configuration, kernel.config_origin.as_deref(), input)?
            .into(),
    ))
}

fn plan_agent_create<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::AgentCreate,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let configuration = kernel.configuration.as_ref().ok_or_else(|| {
        SeError::new(se_types::Detail::Internal(se_types::details::Internal {
            report_id: "agent-configuration-not-bound".into(),
            location: "Kernel::with_configuration".into(),
        }))
    })?;
    let (batch, then) = crate::ops::agent::create(kernel, input, configuration, cx)?;
    Ok(OpStep::Commit {
        batch,
        then: crate::ports::Then::AgentCreate(then),
    })
}

fn plan_agent_rename<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::AgentRename,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    let (batch, then) = crate::ops::agent::rename(kernel, input, cx)?;
    Ok(OpStep::Commit {
        batch,
        then: crate::ports::Then::AgentRename(then),
    })
}

fn plan_message_read<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::MessageRead,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::message_mark::map_mark(crate::ops::message_mark::read(kernel, cx, input)?)
}

fn plan_message_ack<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::MessageAck,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::message_mark::map_mark(crate::ops::message_mark::plan(
        kernel,
        cx,
        input.msg_id,
        crate::ops::message_mark::Mark::Read,
        None,
    )?)
}

fn plan_message_dismiss<R: Snapshot>(
    kernel: &Kernel,
    input: crate::ops::MessageDismiss,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    crate::ops::message_mark::map_mark(crate::ops::message_mark::plan(
        kernel,
        cx,
        input.msg_id,
        crate::ops::message_mark::Mark::Dismiss,
        None,
    )?)
}

fn message_send_step<R: Snapshot>(
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

fn working_state_set_step<R: Snapshot>(
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

fn plan_working_state_get<R: Snapshot>(
    input: crate::ops::WorkingStateGet,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::receipt::working_state_get(
            scope::working_agent(
                cx.admission,
                input.owner_agent.as_ref(),
                "working_state.get",
            )?,
            cx,
        )?
        .into(),
    ))
}

fn plan_identity_whoami<R: Snapshot>(
    input: crate::ops::IdentityWhoami,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::identity::whoami(input, cx)?.into(),
    ))
}

fn plan_history_list<R: Snapshot>(
    input: crate::ops::HistoryList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::history::list(input, cx)?.into(),
    ))
}

fn plan_history_search<R: Snapshot>(
    input: crate::ops::HistorySearch,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::history::search(input, cx)?.into(),
    ))
}

fn plan_message_list<R: Snapshot>(
    input: crate::ops::MessageList,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(
        crate::ops::message::list(input, cx)?.into(),
    ))
}

fn plan_message_inbox<R: Snapshot>(
    input: crate::ops::MessageInbox,
    cx: &mut Cx<'_, R>,
) -> Result<PlanStep> {
    Ok(OpStep::Complete(crate::ops::inbox::read(input, cx)?.into()))
}

// Home-wide owner work: a diagnostic bundle or a store restore.
fn home_owner_refused() -> SeError {
    SeError::invalid(
        "home-wide owner adapter",
        "the installed owner CLI; home-wide work is not a project-session tool",
    )
}

fn doctor_refused() -> SeError {
    SeError::invalid(
        "doctor adapter",
        "the installed owner CLI with current native observations",
    )
}

fn project_move_refused() -> SeError {
    SeError::invalid(
        "project move adapter",
        "the owner CLI with the native git identity observation",
    )
}

fn metadata_refused() -> SeError {
    scope::unreadable(
        "metadata dispatch",
        "registered metadata produced no output",
    )
}
