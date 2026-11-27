//! Owned planning facts and typed continuations; no writer, clock, RNG or read lease is retained.
use crate::{commit::*, scope};
use se_store::{
    Actor, AtomicBatch, CommitReceipt, Door, EventBody, EventHeader, InputText, IntentDigest,
    NewEvent, RequestIdentity, Snapshot,
};
use se_types::{AgentId, EventId, IdempotencyKey, MessageId, Result, SeError};
use sha2::{Digest, Sha256};

mod agents;
mod core_ops;
mod queries;
mod refusals;

use agents::*;
use core_ops::*;
use queries::*;
use refusals::*;

/// The step, continuation and custody plan shared by every dispatched operation.
type PlanStep = OpStep<crate::ops::AnyOutput, crate::ports::Then, crate::ports::CustodyPlan>;

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

    /// The host releases the finite snapshot/worker after this returns, awaits
    /// only the store completion, then opens a fresh admitted continuation read.
    pub fn plan<R: Snapshot>(
        &self,
        op: crate::ops::AnyOp,
        cx: &mut Cx<'_, R>,
        terminal: &crate::admission::HumanTerminal,
    ) -> Result<PlanStep> {
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
                crate::ops::delegate::step_start(self, i, self.configuration.as_ref(), cx)
            }
            AnyOp::DelegateCancel(i) => crate::ops::delegate::step_cancel(i, cx),
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
            AnyOp::DiagnosticBundle(_) | AnyOp::StoreRestore(_) | AnyOp::HarnessAdd(_) => {
                Err(home_owner_refused())
            }
            AnyOp::DoctorInspect(_) | AnyOp::DoctorRepair(_) => Err(doctor_refused()),
            AnyOp::ProjectInit(input) => Ok(OpStep::Custody(CustodyPlan::Initialize(input))),
            // The owner CLI route performs the native git identity proof and
            // commits the roots revision directly; the kernel never plans it.
            AnyOp::ProjectMove(_) => Err(project_move_refused()),
            // The CLI route runs the non-following link guard and deletes the
            // local linked worktree directly without touching the store.
            AnyOp::WorktreeRemove(_) => Err(worktree_remove_refused()),
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

fn complete_step<T>(result: Result<T>) -> Result<PlanStep>
where
    T: Into<crate::ops::AnyOutput>,
{
    result.map(|value| OpStep::Complete(value.into()))
}
