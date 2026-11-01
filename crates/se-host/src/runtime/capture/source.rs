//! Validate the protected binding in a finite snapshot, close it, then read
//! only the retained native pin. No SQL read lease survives native file work.
use super::*;
use se_core::{admission::read_scope, scope, store_error::store_error};
use se_store::{Consent, EventBody, ReadStore, Snapshot};
use sha2::{Digest, Sha256};
const CHUNK: usize = 256 * 1024;
const LINE: usize = 4 * 1024 * 1024;
struct Cursor {
    revision: se_store::Revision,
    offset: u64,
    previous: Option<(u64, u64)>,
    evidence: Option<se_store::SourceEvidence>,
}
pub fn next(
    context: &ExecutionContext,
    admission: &se_store::Admission,
    source: &mut BoundTranscript,
    hook: &crate::ClaudeHookInput,
    deadline: &Deadline,
    replay: bool,
) -> Result<Option<(TrustedCapture, bool)>> {
    deadline.remaining()?;
    super::super::executor::check_generation(&context.reader, context.generation)?;
    check_scope(admission, &source.binding)?;
    if hook.conversation != source.binding.conversation {
        return Err(SeError::invalid(
            "hook conversation",
            "the previously bound provider conversation",
        ));
    }
    let claimed = hook.claimed_transcript.to_local()?;
    if claimed != source.pin.path() {
        return Err(SeError::invalid(
            "claimed transcript",
            "the exact previously bound source path",
        ));
    }
    source.pin.validate_path(&claimed).map_err(native_error)?;
    let cursor = cursor(context, admission, source)?;
    verify_prefix(source, cursor.evidence.as_ref(), deadline)?;
    if matches!(hook.kind, crate::ClaudeHookKind::SessionStart) {
        return Ok(None);
    }
    if let Some(request) = scan(source, cursor.revision, cursor.offset, deadline)? {
        return Ok(Some((request, false)));
    }
    if replay && let Some((from, to)) = cursor.previous {
        let request = scan(source, cursor.revision, from, deadline)?.ok_or_else(|| {
            scope::unreadable(
                "captured source range",
                "the original captured text record no longer decodes",
            )
        })?;
        if request.request.new_offset != to {
            return Err(scope::unreadable(
                "captured source range",
                "the original committed range differs; preserve its cursor",
            ));
        }
        return Ok(Some((request, true)));
    }
    Ok(None)
}
fn check_scope(admission: &se_store::Admission, pin: &crate::TranscriptPin) -> Result<()> {
    if admission.scope != se_store::Scope::Project(pin.identity.project.clone())
        || admission.actor != se_store::Actor::Agent(pin.identity.agent.clone())
        || admission.session.as_ref() != Some(&pin.identity.session)
    {
        return Err(SeError::invalid(
            "transcript binding",
            "this exact admitted project, agent and session",
        ));
    }
    Ok(())
}
fn cursor(
    context: &ExecutionContext,
    admission: &se_store::Admission,
    source: &BoundTranscript,
) -> Result<Cursor> {
    let mut read = context
        .reader
        .snapshot(read_scope(admission))
        .map_err(|error| store_error(&error))?;
    let result = (|| {
        let session = scope::require_present(
            read.session(source.binding.identity.session.clone())
                .map_err(|error| store_error(&error))?,
            "capture session",
            "Restore access to the original active session binding before repeating capture with the same session/provider/turn identities; preserve the saved cursor.",
        )?;
        if !matches!(session.current.body, EventBody::SessionActivated { .. }) {
            return Err(scope::unreadable(
                "capture session",
                "the admitted session is not active",
            ));
        }
        if matches!(
            session.original.as_ref().map(|event| &event.body),
            Some(EventBody::SessionPrepared {
                consent: Consent::Suppressed,
                ..
            })
        ) {
            return Err(SeError::new(se_types::Detail::CaptureConsentMissing(
                se_types::details::CaptureConsentMissing {
                    session: source.binding.identity.session.clone(),
                },
            )));
        }
        if !matches!(session.original.as_ref().map(|event| &event.body),
            Some(EventBody::SessionPrepared {session,agent,provider:se_store::Provider::Claude,native_ref,consent:Consent::Capture,..})
            if session==&source.binding.identity.session && agent==&source.binding.identity.agent && native_ref==source.binding.conversation.as_str())
        {
            return Err(scope::unreadable(
                "capture session",
                "provider, conversation or capture consent differs from the trusted binding",
            ));
        }
        let record = scope::require_present(
            read.capture_source(source.source)
                .map_err(|error| store_error(&error))?,
            "capture source",
            "Restore access to the original trusted capture source binding before repeating capture with the same session/provider/turn identities; preserve the saved cursor.",
        )?;
        let original = record.original.as_deref().unwrap_or(&record.current);
        if matches!(
            &original.body,
            EventBody::CaptureSource {
                consent: Consent::Suppressed,
                ..
            }
        ) {
            return Err(SeError::new(se_types::Detail::CaptureConsentMissing(
                se_types::details::CaptureConsentMissing {
                    session: source.binding.identity.session.clone(),
                },
            )));
        }
        if !matches!(&original.body, EventBody::CaptureSource {source:id,session,consent:Consent::Capture,incarnation,..}
            if id==&source.source && session==&source.binding.identity.session && incarnation.as_slice()==source.pin.identity())
        {
            return Err(scope::unreadable(
                "capture source",
                "source/session/consent/native identity binding differs",
            ));
        }
        let mut evidence = None;
        let (offset, previous) = match &record.current.body {
            EventBody::CaptureSource { .. } => (0, None),
            EventBody::CaptureProgress {
                source: id,
                incarnation,
                old_offset,
                new_offset,
                last_turn,
                ..
            } if id == &source.source && incarnation.as_slice() == source.pin.identity() => {
                let turn = scope::require_present(
                    read.turn(*last_turn).map_err(|error| store_error(&error))?,
                    "last committed capture turn",
                    "Read the last committed turn for this original capture source; preserve its session/provider/turn identities and saved cursor.",
                )?;
                match turn.body {
                    EventBody::SessionTurn {
                        turn: id,
                        agent,
                        session,
                        evidence: prior,
                        text: se_store::StoredText::Present(_),
                        ..
                    } if id == *last_turn
                        && agent == source.binding.identity.agent
                        && session == source.binding.identity.session
                        && prior.path == source.binding.path
                        && prior.incarnation.as_slice() == source.pin.identity()
                        && prior.offset == *old_offset
                        && prior.offset.checked_add(prior.length) == Some(*new_offset)
                        && prior.sha256.is_some() =>
                    {
                        evidence = Some(prior)
                    }
                    _ => {
                        return Err(scope::unreadable(
                            "committed capture prefix",
                            "last turn is erased, unreadable or differs from the exact cursor/source/session binding",
                        ));
                    }
                }
                (*new_offset, Some((*old_offset, *new_offset)))
            }
            _ => {
                return Err(scope::unreadable(
                    "capture cursor",
                    "no exact current progress observation is available",
                ));
            }
        };
        Ok(Cursor {
            revision: record.revision,
            offset,
            previous,
            evidence,
        })
    })();
    super::super::executor::close_read(result, read.close())
}
fn scan(
    source: &mut BoundTranscript,
    revision: se_store::Revision,
    offset: u64,
    deadline: &Deadline,
) -> Result<Option<TrustedCapture>> {
    let mut position = offset;
    let mut consumed = offset;
    let mut line = Vec::new();
    let mut digest = Sha256::new();
    loop {
        deadline.remaining()?;
        let chunk = source.pin.read_at(position, CHUNK).map_err(native_error)?;
        for byte in chunk.bytes {
            consumed = consumed.checked_add(1).ok_or_else(|| {
                SeError::invalid("capture offset", "a representable source range")
            })?;
            line.push(byte);
            if line.len() > LINE {
                return Err(SeError::too_large(
                    "provider transcript line",
                    LINE,
                    line.len(),
                ));
            }
            if byte == b'\n' {
                digest.update(&line);
                if let Some(record) = super::claude::decode(&line, &source.binding.conversation)? {
                    return Ok(Some(TrustedCapture {
                        request: se_core::ops::hook::CaptureRequest {
                            source: source.source,
                            expected: revision,
                            conversation: source.binding.conversation.clone(),
                            provider: se_store::Provider::Claude,
                            vendor_turn: record.vendor_turn,
                            role: record.role,
                            text: record.text,
                            evidence: se_store::SourceEvidence {
                                path: source.binding.path.clone(),
                                incarnation: source.pin.identity().to_vec(),
                                offset,
                                length: consumed - offset,
                                sha256: Some(digest.finalize().into()),
                            },
                            new_offset: consumed,
                        },
                        facts: facts()?,
                    }));
                }
                line.clear();
            }
        }
        position = chunk.next_offset;
        if chunk.end_of_file || position == consumed && position == offset {
            // Incomplete EOF remains pending until a real provider hook/signal;
            // neither metadata nor a partial final line advances the cursor.
            return Ok(None);
        }
    }
}
fn facts() -> Result<se_core::ops::hook::CaptureFacts> {
    use se_store::RecordIdentity;
    let first = super::super::start::allocate_facts()?;
    let second = super::super::start::allocate_facts()?;
    let mut random = [0; 10];
    getrandom::fill(&mut random)
        .map_err(|error| scope::unreadable("capture entropy", &error.to_string()))?;
    Ok(se_core::ops::hook::CaptureFacts {
        turn: se_store::RecordId::from_parts(first.occurred_at_us as u64 / 1000, random)
            .map_err(|error| store_error(&error))?,
        turn_event: first.event,
        progress_event: second.event,
        occurred_at_us: first.occurred_at_us,
    })
}

pub(super) fn validate(
    context: &ExecutionContext,
    source: &mut BoundTranscript,
    deadline: &Deadline,
) -> Result<()> {
    let admission = se_store::Admission {
        scope: se_store::Scope::Project(source.binding.identity.project.clone()),
        actor: se_store::Actor::Agent(source.binding.identity.agent.clone()),
        session: Some(source.binding.identity.session.clone()),
        generation: context.generation.get(),
    };
    let current = cursor(context, &admission, source)?;
    verify_prefix(source, current.evidence.as_ref(), deadline)
}
/// All SQL reads are closed before these bounded native reads. Verify the last
/// committed raw range before scanning beyond it, including after cold reopen.
fn verify_prefix(
    source: &mut BoundTranscript,
    evidence: Option<&se_store::SourceEvidence>,
    deadline: &Deadline,
) -> Result<()> {
    let Some(evidence) = evidence else {
        return Ok(());
    };
    let end = evidence
        .offset
        .checked_add(evidence.length)
        .ok_or_else(|| SeError::invalid("capture range", "a representable committed end"))?;
    let mut position = evidence.offset;
    let mut digest = Sha256::new();
    while position < end {
        deadline.remaining()?;
        let chunk = source
            .pin
            .read_at(position, ((end - position) as usize).min(CHUNK))
            .map_err(native_error)?;
        if chunk.bytes.is_empty() || chunk.next_offset > end {
            return Err(scope::unreadable(
                "committed capture prefix",
                "source truncated or changed within the committed range",
            ));
        }
        digest.update(&chunk.bytes);
        position = chunk.next_offset;
    }
    if Some(digest.finalize().into()) != evidence.sha256 {
        return Err(scope::unreadable(
            "committed capture prefix",
            "the previously captured byte range changed; preserve its cursor and require a trusted new incarnation",
        ));
    }
    Ok(())
}
