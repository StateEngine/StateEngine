//! Native hook custody and the trusted pinned-source capture seam. Raw provider
//! payloads never supply admission, consent, a source binding or a cursor.
use super::{inputs::Validate, outputs::Writer};
use crate::{
    commit::{Cx, OpStep},
    ports::Then,
    scope,
    store_error::store_error,
};
use schemars::JsonSchema;
use se_store::{
    Actor, AtomicBatch, CommitReceipt, Consent, Door, EventBody, EventHeader, Expected, InputText,
    NewEvent, Provider, RecordId, Revision, Role, Snapshot, SourceEvidence, StoredText,
};
use se_types::{
    Body, Detail, EventId, ProviderSessionId, Read, Result, SeError, SessionId, details,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub(crate) mod replay;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HookEvent {
    SessionStart,
    Prompt,
    Stop,
    StopFailure,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookClaude {
    pub event: HookEvent,
}
impl Validate for HookClaude {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
/// Internal family; the native wrapper emits only stdout and bounded failure
/// diagnostics. Stop and stop-failure always have empty provider stdout.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookResult {
    pub stdout: String,
    pub captured: Read<EventId>,
    pub failure: Option<se_types::ErrorBody>,
    pub receipt: Option<TurnReceipt>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnReceipt {
    pub result: CaptureResult,
    pub session_id: SessionId,
    pub turn_id: String,
    pub role: String,
    pub bytes: u64,
    pub event_id: EventId,
    pub writer: Writer,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CaptureResult {
    Captured,
    Duplicate,
}

/// Supplied only by the host's authenticated, pinned-source reader. It has no
/// Deserialize implementation and cannot be created from hook payload JSON.
pub struct CaptureRequest {
    /// Trusted coordinator only, after outside native exit/empty-scope proof.
    pub recovery_owner: Option<se_types::HumanId>,
    pub source: RecordId,
    pub expected: Revision,
    pub conversation: ProviderSessionId,
    pub provider: Provider,
    pub vendor_turn: String,
    pub role: Role,
    pub text: Body,
    pub evidence: SourceEvidence,
    pub new_offset: u64,
    pub metadata: Vec<CaptureMetadata>,
}
pub struct CaptureMetadata {
    pub record: super::transcript::Record,
    pub vendor_turn: String,
    pub turn: RecordId,
    pub event: EventId,
}
/// Allocated before first submission and retained across an uncertain result.
/// Native chat identity is bound conversation/provider/vendor_turn, not these
/// allocated event/turn identifiers, and replay resolves its original members.
pub struct CaptureFacts {
    pub turn: RecordId,
    pub turn_event: EventId,
    pub progress_event: EventId,
    pub occurred_at_us: i64,
}
pub struct CaptureThen {
    session: SessionId,
    source: RecordId,
    vendor_turn: String,
    provider: Provider,
    text_sha256: [u8; 32],
    metadata: Vec<(String, [u8; 32])>,
}
/// The host releases this snapshot before awaiting the canonical writer. A
/// continuation subsequently opens a fresh snapshot through Kernel::committed.
pub fn plan<R: Snapshot>(
    mut input: CaptureRequest,
    facts: CaptureFacts,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<super::AnyOutput, Then>> {
    let project = scope::project(cx.admission)?;
    let (Actor::Agent(agent), Some(session)) = (&cx.admission.actor, &cx.admission.session) else {
        return Err(SeError::new(Detail::SessionRequired(
            details::SessionRequired {
                op: "hook.claude".into(),
            },
        )));
    };
    let session = session.clone();
    let agent = agent.clone();
    super::inputs::bounded(
        "vendor turn",
        &input.vendor_turn,
        if input.provider == Provider::Codex {
            4096
        } else {
            512
        },
        false,
    )?;
    if input.role == Role::System {
        let notice = super::transcript::Record::decode(input.text.as_str())?;
        notice.validate_evidence(&input.evidence)?;
        if let Some(tool) = &notice.captured_tool {
            tool.validate_binding(
                &session,
                &agent,
                input.provider,
                input.source,
                &input.evidence,
            )?;
        }
        if !input
            .vendor_turn
            .starts_with(se_store::TRANSCRIPT_EVENT_PREFIX)
        {
            return Err(SeError::invalid(
                "provider metadata",
                "the native metadata identity",
            ));
        }
        replay::canonicalize_tool(&mut input, cx)?;
    }
    if input.metadata.len() > 32 {
        return Err(SeError::invalid(
            "capture metadata batch",
            "at most 32 counted kinds",
        ));
    }
    let mut metadata = Vec::new();
    for item in input.metadata {
        item.record.validate_evidence(&input.evidence)?;
        if let Some(tool) = &item.record.captured_tool {
            tool.validate_binding(
                &session,
                &agent,
                input.provider,
                input.source,
                &input.evidence,
            )?;
        }
        super::inputs::bounded("metadata identity", &item.vendor_turn, 512, false)?;
        if item.record.count.is_none()
            && item.record.queued_input.is_none()
            && item.record.captured_tool.is_none()
            || !item
                .vendor_turn
                .starts_with(se_store::TRANSCRIPT_EVENT_PREFIX)
        {
            return Err(SeError::invalid(
                "capture metadata batch",
                "counted native metadata",
            ));
        }
        metadata.push((item.turn, item.event, item.vendor_turn, item.record.body()?));
    }
    if !matches!(
        input.role,
        Role::System | Role::User | Role::Assistant | Role::Tool
    ) || facts.occurred_at_us < 0
        || facts.turn_event == facts.progress_event
    {
        return Err(SeError::invalid(
            "capture facts",
            "a provider role, nonnegative timestamp and distinct event IDs",
        ));
    }
    let end = input
        .evidence
        .offset
        .checked_add(input.evidence.length)
        .ok_or_else(|| SeError::invalid("capture source range", "no offset overflow"))?;
    if input.evidence.length == 0
        || end != input.new_offset
        || end > i64::MAX as u64
        || input.evidence.incarnation.is_empty()
        || input.evidence.sha256.is_none()
    {
        return Err(SeError::invalid(
            "capture source range",
            "a complete nonempty verified source range, incarnation and digest",
        ));
    }
    let bound = scope::require_present(
        cx.read
            .session(session.clone())
            .map_err(|e| store_error(&e))?,
        "capture session",
        "Restore access to the original active session binding before repeating capture with the same session/provider/turn identities; preserve the saved cursor.",
    )?;
    let (commit_admission, capture_door) =
        replay::admission(input.recovery_owner.as_ref(), &bound, cx)?;
    let prepared = bound.original.as_ref().map(|v| &v.body).ok_or_else(|| {
        scope::unreadable("capture session", "original session binding is missing")
    })?;
    let reference = super::session_reference::read(cx.read, &bound)?;
    match prepared {
        EventBody::SessionPrepared {
            session: recorded,
            agent: recorded_agent,
            provider,
            consent: Consent::Capture,
            ..
        } if recorded == &session
            && recorded_agent == &agent
            && provider == &input.provider
            && matches!(&reference, Read::Present { value } if value == &input.conversation) => {}
        EventBody::SessionPrepared {
            consent: Consent::Suppressed,
            ..
        } => {
            return Err(SeError::new(Detail::CaptureConsentMissing(
                details::CaptureConsentMissing { session },
            )));
        }
        _ => {
            return Err(scope::unreadable(
                "capture session",
                "provider conversation differs from the original admitted session binding",
            ));
        }
    }
    let source = scope::require_present(
        cx.read
            .capture_source(input.source)
            .map_err(|e| store_error(&e))?,
        "capture source",
        "Restore access to the original trusted capture source binding before repeating capture with the same session/provider/turn identities; preserve the saved cursor.",
    )?;
    let original = source.original.as_deref().unwrap_or(&source.current);
    match &original.body {
        EventBody::CaptureSource {
            source,
            session: recorded,
            consent: Consent::Capture,
            incarnation,
            ..
        } if source == &input.source
            && recorded == &session
            && incarnation == &input.evidence.incarnation => {}
        EventBody::CaptureSource {
            consent: Consent::Suppressed,
            ..
        } => {
            return Err(SeError::new(Detail::CaptureConsentMissing(
                details::CaptureConsentMissing { session },
            )));
        }
        _ => {
            return Err(scope::unreadable(
                "capture source",
                "source/session/consent/incarnation binding differs",
            ));
        }
    }
    // Deliberately leave current cursor/revision checks to the committer, after
    // natural replay resolution. A retained retry may follow a later head.
    let header = |event| EventHeader {
        event,
        scope: se_store::Scope::Project(project.clone()),
        actor: Actor::Agent(agent.clone()),
        session: Some(session.clone()),
        origin: cx.read.info().id,
        door: capture_door,
        occurred_at_us: facts.occurred_at_us,
        cause: None,
        supersedes: None,
    };
    let then = CaptureThen {
        session: session.clone(),
        source: input.source,
        vendor_turn: input.vendor_turn.clone(),
        provider: input.provider,
        text_sha256: Sha256::digest(input.text.as_str().as_bytes()).into(),
        metadata: metadata
            .iter()
            .map(|(_, _, vendor, text)| {
                (
                    vendor.clone(),
                    Sha256::digest(text.as_str().as_bytes()).into(),
                )
            })
            .collect(),
    };
    let old_offset = input.evidence.offset;
    let incarnation = input.evidence.incarnation.clone();
    let turn_header = header(facts.turn_event);
    let progress_header = header(facts.progress_event);
    let mut events = vec![NewEvent {
        header: turn_header,
        body: EventBody::SessionTurn {
            turn: facts.turn,
            agent: agent.clone(),
            session: session.clone(),
            provider: input.provider,
            vendor_ref: input.vendor_turn,
            role: input.role,
            text: InputText::Inline(input.text.into()),
            evidence: input.evidence.clone(),
        },
    }];
    for (turn, event, vendor_ref, text) in metadata {
        events.push(NewEvent {
            header: header(event),
            body: EventBody::SessionTurn {
                turn,
                agent: agent.clone(),
                session: session.clone(),
                provider: input.provider,
                vendor_ref,
                role: Role::System,
                text: InputText::Inline(text.into()),
                evidence: input.evidence.clone(),
            },
        });
    }
    events.push(NewEvent {
        header: progress_header,
        body: EventBody::CaptureProgress {
            source: input.source,
            expected: Expected::Revision(input.expected),
            incarnation,
            old_offset,
            new_offset: input.new_offset,
            last_turn: facts.turn,
            replay_evidence: None,
        },
    });
    Ok(OpStep::Commit {
        batch: AtomicBatch {
            expected_incarnation: cx.read.info().incarnation,
            admission: commit_admission,
            request: None,
            events,
            import_checkpoint: None,
        },
        then: Then::Capture(then),
    })
}

pub fn committed<R: Snapshot>(
    then: CaptureThen,
    receipt: CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<HookResult> {
    if receipt.request_key.is_some()
        || receipt.events.len() != 2 + then.metadata.len()
        || !receipt.events.contains(&receipt.primary_event)
        || !matches!(
            se_store::WriterModeValue::kind(&receipt.writer),
            se_store::WriterKind::Host { .. }
        )
    {
        return Err(scope::unreadable(
            "capture receipt",
            "expected the original capture batch natural receipt from the host writer",
        ));
    }
    let event = scope::require_present(
        cx.read
            .event(receipt.primary_event.clone())
            .map_err(|e| store_error(&e))?,
        "captured turn",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    let resumed = event.header.session.as_ref() != Some(&then.session);
    if resumed {
        let original = scope::require_present(
            cx.read
                .native_turn(then.session.clone(), then.provider, &then.vendor_turn)
                .map_err(|e| store_error(&e))?,
            "resumed native item",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if !matches!(then.provider, Provider::Claude | Provider::Codex)
            || original.header.event != event.header.event
        {
            return Err(scope::unreadable(
                "captured turn",
                "receipt differs from the bound native conversation item",
            ));
        }
    }
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "captured turn",
            "receipt resolved outside the admitted session",
        ));
    }
    let (turn, bytes, role) = match event.body {
        EventBody::SessionTurn {
            turn,
            session,
            vendor_ref,
            role,
            text: StoredText::Present(text),
            ..
        } if event.header.session.as_ref() == Some(&session)
            && vendor_ref == then.vendor_turn
            && <[u8; 32]>::from(Sha256::digest(text.as_bytes())) == then.text_sha256 =>
        {
            (turn, text.len() as u64, role)
        }
        _ => {
            return Err(scope::unreadable(
                "captured turn",
                "immutable turn content is erased, unreadable or different",
            ));
        }
    };
    let progress_id = receipt
        .events
        .last()
        .ok_or_else(|| scope::unreadable("capture receipt", "missing cursor member"))?;
    let progress = scope::require_present(
        cx.read
            .event(progress_id.clone())
            .map_err(|e| store_error(&e))?,
        "captured source cursor",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    if progress.header.scope != cx.admission.scope
        || progress.header.actor != cx.admission.actor
        || progress.header.session.as_ref() != Some(&then.session)
        || !matches!(progress.body,EventBody::CaptureProgress{source,last_turn,..} if source==then.source && last_turn==turn)
    {
        return Err(scope::unreadable(
            "capture receipt",
            "cursor member does not advance the original captured turn",
        ));
    }
    for ((vendor, digest), id) in then
        .metadata
        .iter()
        .zip(&receipt.events[1..receipt.events.len() - 1])
    {
        let event = scope::require_present(
            cx.read.event(id.clone()).map_err(|e| store_error(&e))?,
            "captured metadata",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if event.header.scope != cx.admission.scope
            || event.header.actor != cx.admission.actor
            || event.header.session.as_ref() != Some(&then.session)
            || !matches!(event.body, EventBody::SessionTurn {session, role: Role::System, vendor_ref, text: StoredText::Present(text), ..}
                if session == then.session && vendor_ref == *vendor && <[u8;32]>::from(Sha256::digest(text.as_bytes())) == *digest)
        {
            return Err(scope::unreadable(
                "capture receipt",
                "counted metadata differs from its original batch",
            ));
        }
    }
    Ok(HookResult {
        stdout: String::new(),
        captured: Read::Present {
            value: receipt.primary_event.clone(),
        },
        failure: None,
        receipt: Some(TurnReceipt {
            result: if !resumed && receipt.state == se_store::CommitState::Committed {
                CaptureResult::Captured
            } else {
                CaptureResult::Duplicate
            },
            session_id: then.session,
            turn_id: then.vendor_turn,
            role: match role {
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Tool => "tool",
                Role::System => "system",
            }
            .into(),
            bytes,
            event_id: receipt.primary_event.clone(),
            writer: super::receipt::writer(&receipt),
        }),
    })
}
