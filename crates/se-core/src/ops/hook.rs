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
    pub source: RecordId,
    pub expected: Revision,
    pub conversation: ProviderSessionId,
    pub provider: Provider,
    pub vendor_turn: String,
    pub role: Role,
    pub text: Body,
    pub evidence: SourceEvidence,
    pub new_offset: u64,
}
/// Allocated before first submission and retained across an uncertain result.
/// The store's natural identity is bound session/provider/vendor_turn, not these
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
    text_sha256: [u8; 32],
}
/// The host releases this snapshot before awaiting the canonical writer. A
/// continuation subsequently opens a fresh snapshot through Kernel::committed.
pub fn plan<R: Snapshot>(
    input: CaptureRequest,
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
    super::inputs::bounded("vendor turn", &input.vendor_turn, 512, false)?;
    if input.role == Role::System {
        let notice = super::transcript::Record::decode(input.text.as_str())?;
        if notice.position.length == 0
            || notice.position.offset < input.evidence.offset
            || notice.position.offset.checked_add(notice.position.length) != Some(input.new_offset)
            || !input
                .vendor_turn
                .starts_with(se_store::TRANSCRIPT_EVENT_PREFIX)
        {
            return Err(SeError::invalid(
                "provider metadata",
                "an exact bounded source position and native metadata identity",
            ));
        }
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
    if !matches!(bound.current.body, EventBody::SessionActivated { .. }) {
        return Err(scope::unreadable(
            "capture session",
            "session is not active; no capture or cursor advancement planned",
        ));
    }
    let prepared = bound.original.as_ref().map(|v| &v.body).ok_or_else(|| {
        scope::unreadable("capture session", "original session binding is missing")
    })?;
    match prepared {
        EventBody::SessionPrepared {
            session: recorded,
            agent: recorded_agent,
            provider,
            native_ref,
            consent: Consent::Capture,
            ..
        } if recorded == &session
            && recorded_agent == &agent
            && provider == &input.provider
            && native_ref == input.conversation.as_str() => {}
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
        door: Door::Hook,
        occurred_at_us: facts.occurred_at_us,
        cause: None,
        supersedes: None,
    };
    let then = CaptureThen {
        session: session.clone(),
        source: input.source,
        vendor_turn: input.vendor_turn.clone(),
        text_sha256: Sha256::digest(input.text.as_str().as_bytes()).into(),
    };
    let old_offset = input.evidence.offset;
    let incarnation = input.evidence.incarnation.clone();
    let turn_header = header(facts.turn_event);
    let progress_header = header(facts.progress_event);
    let events = vec![
        NewEvent {
            header: turn_header,
            body: EventBody::SessionTurn {
                turn: facts.turn,
                agent,
                session,
                provider: input.provider,
                vendor_ref: input.vendor_turn,
                role: input.role,
                text: InputText::Inline(input.text.into()),
                evidence: input.evidence,
            },
        },
        NewEvent {
            header: progress_header,
            body: EventBody::CaptureProgress {
                source: input.source,
                expected: Expected::Revision(input.expected),
                incarnation,
                old_offset,
                new_offset: input.new_offset,
                last_turn: facts.turn,
            },
        },
    ];
    Ok(OpStep::Commit {
        batch: AtomicBatch {
            expected_incarnation: cx.read.info().incarnation,
            admission: cx.admission.clone(),
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
        || receipt.events.len() != 2
        || !receipt.events.contains(&receipt.primary_event)
        || !matches!(
            se_store::WriterModeValue::kind(&receipt.writer),
            se_store::WriterKind::Host { .. }
        )
    {
        return Err(scope::unreadable(
            "capture receipt",
            "expected the original two-member natural receipt from the host writer",
        ));
    }
    let event = scope::require_present(
        cx.read
            .event(receipt.primary_event.clone())
            .map_err(|e| store_error(&e))?,
        "captured turn",
        scope::COMMITTED_READ_RECOVERY,
    )?;
    if event.header.scope != cx.admission.scope
        || event.header.actor != cx.admission.actor
        || event.header.session.as_ref() != Some(&then.session)
    {
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
        } if session == then.session
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
        .iter()
        .find(|id| **id != receipt.primary_event)
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
    Ok(HookResult {
        stdout: String::new(),
        captured: Read::Present {
            value: receipt.primary_event.clone(),
        },
        failure: None,
        receipt: Some(TurnReceipt {
            result: if receipt.state == se_store::CommitState::Committed {
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
