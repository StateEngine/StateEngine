//! Durable observation of user-owned provider sessions. No process control,
//! machine permission or provider sandbox override is created here.
use crate::{commit::Cx, dispatch::Kernel, scope, store_error::store_error};
use se_store::{AtomicBatch, Consent, ContainmentFact, EventBody, Expected, Snapshot};
use se_types::{AgentId, IdempotencyKey, ProviderSessionId, Read, Result, SessionId};
use std::num::NonZeroU64;

pub struct Binding {
    pub agent: AgentId,
    pub session: SessionId,
    pub conversation: ProviderSessionId,
    pub incarnation: Vec<u8>,
}
pub fn bind<R: Snapshot>(
    kernel: &Kernel,
    binding: Binding,
    cx: &mut Cx<'_, R>,
) -> Result<Option<AtomicBatch>> {
    scope::project(cx.admission)?;
    if !matches!(cx.admission.actor, se_store::Actor::Human(_)) || cx.admission.session.is_some() {
        return Err(se_types::SeError::invalid(
            "provider adoption",
            "native owner admission without an inherited session",
        ));
    }
    match cx
        .read
        .session(binding.session.clone())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } => {
            if !matches!(
                value.current.body,
                EventBody::SessionActivated {
                    process: None,
                    containment: ContainmentFact::NotLaunched,
                    ..
                }
            ) {
                return Err(se_types::SeError::invalid(
                    "provider adoption",
                    "the same active observed session",
                ));
            }
            return Ok(None);
        }
        Read::Absent { .. } => (),
        other => {
            scope::require_present(
                other,
                "adoption session",
                "Restore the original saved session; unreadable is not absent.",
            )?;
        }
    }
    let source = super::process_commit::session_credential_id(&binding.session, "capture-source")?;
    let key: IdempotencyKey = format!("observe-{}", binding.session).parse()?;
    let intent = serde_json::json!({"agent":binding.agent,"session":binding.session,"conversation":binding.conversation,"incarnation":binding.incarnation});
    let bodies = vec![
        super::session_commit::prepare(super::session_commit::SessionPreparation {
            agent: binding.agent,
            session: binding.session.clone(),
            provider: se_store::Provider::Claude,
            surface: Some(se_store::SessionSurface::Observed),
            native_ref: binding.conversation.to_string(),
            consent: Consent::Capture,
            generation: cx.admission.generation,
            expected: Expected::Absent,
        })?,
        super::session_commit::activate(super::session_commit::SessionActivation {
            session: binding.session.clone(),
            expected: Expected::Revision(se_store::Revision {
                value: NonZeroU64::MIN,
            }),
            incumbent: None,
            process: None,
            containment: ContainmentFact::NotLaunched,
            witnesses: vec![],
        })?,
        EventBody::CaptureSource {
            source,
            session: binding.session,
            consent: Consent::Capture,
            native_ref: binding.conversation.to_string(),
            incarnation: binding.incarnation,
            expected: Expected::Absent,
        },
    ];
    super::process_commit::batch(kernel, "session.observe", key, intent, bodies, cx).map(Some)
}
pub fn end<R: Snapshot>(
    kernel: &Kernel,
    session: SessionId,
    cx: &mut Cx<'_, R>,
) -> Result<Option<AtomicBatch>> {
    let record = scope::require_present(
        cx.read
            .session(session.clone())
            .map_err(|e| store_error(&e))?,
        "observed session",
        "Restore the original observed session.",
    )?;
    if matches!(
        record.current.body,
        EventBody::SessionEnded { .. } | EventBody::SessionRevoked { .. }
    ) {
        return Ok(None);
    }
    if !matches!(
        record.original.as_deref().map(|e| &e.body),
        Some(EventBody::SessionPrepared {
            surface: Some(se_store::SessionSurface::Observed),
            ..
        })
    ) {
        return Err(se_types::SeError::invalid(
            "observed session retirement",
            "an observed user-owned provider session",
        ));
    }
    super::process_commit::batch(
        kernel,
        "session.observe",
        format!("observe-end-{session}").parse()?,
        serde_json::json!({"session":session,"phase":"end"}),
        vec![EventBody::SessionEnded {
            session,
            expected: Expected::Revision(record.revision),
            reason: se_store::InputText::Inline(
                "provider signalled session end; observation detached without signalling a provider process or claiming final flush".into(),
            ),
            final_turn: None,
            final_cursor: None,
        }],
        cx,
    )
    .map(Some)
}
