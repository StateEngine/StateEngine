//! Sealed native protocol facts enter the existing immutable capture writer.
use super::*;
use crate::{client::lease::Deadline, harness::acp::bound};
use se_core::{
    commit::OpStep,
    ops::{hook, transcript::Position},
};
use se_store::{EventBody, RecordIdentity, Snapshot, StoredText};
use se_types::Read;
use sha2::{Digest, Sha256};

fn identity() -> Result<(se_store::RecordId, se_types::EventId, i64)> {
    let facts = crate::runtime::start::allocate_facts()?;
    let mut entropy = [0; 10];
    se_proc::fill_entropy(&mut entropy).map_err(|e| error("ACP capture identity", e))?;
    let id = se_store::RecordId::from_parts(facts.occurred_at_us as u64 / 1000, entropy)
        .map_err(|e| se_core::store_error::store_error(&e))?;
    Ok((id, facts.event, facts.occurred_at_us))
}
impl LaunchCoordinator {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(in crate::process) async fn capture_acp(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let binding = bound(work.binding.as_ref().ok_or_else(|| {
            error(
                "ACP capture",
                "original live protocol source unavailable; retain its incomplete capture",
            )
        })?)?
        .clone();
        let observation = binding.session.observe()?;
        let conversation = se_types::ProviderSessionId::new(
            observation
                .conversation
                .ok_or_else(|| error("ACP capture", "conversation absent"))?,
        )?;
        let source = work
            .capture_source
            .ok_or_else(|| error("ACP capture", "original source absent"))?;
        let incarnation = binding.source()?;
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.meta.project.id.clone()),
            actor: se_store::Actor::Agent(work.meta.agent.id.clone()),
            session: Some(work.meta.session.clone()),
            generation: self.store.generation.get(),
        };
        for request in observation.completed {
            let mut offset = binding.offset();
            for item in binding.items(request)? {
                let length = item.bytes.len() as u64;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| error("ACP capture", "source range overflow"))?;
                let position = Position { offset, length };
                let text = item.body(position.clone())?;
                let digest: [u8; 32] = Sha256::digest(&item.bytes).into();
                let session = work.meta.session.clone();
                let native_identity = binding.identity.clone();
                let conversation = conversation.clone();
                let expected_incarnation = incarnation.clone();
                let recovery_owner = (work.process_retired
                    || work.native_already_reconciled
                    || work.session_retired)
                    .then(|| work.meta.owner.clone());
                let result = super::super::mail::commit::step(
                    &self.store,
                    admission.clone(),
                    deadline,
                    move |_, cx| {
                        let row = se_core::scope::require_present(
                            cx.read.capture_source(source).map_err(store_error)?,
                            "ACP capture source",
                            "Preserve the original native binding and cursor.",
                        )?;
                        let saved =
                            bound_cursor(&row, &session, &conversation, &expected_incarnation)?;
                        let mut metadata = Vec::new();
                        for fact in &item.facts {
                            let record = fact.record(
                                &native_identity,
                                se_store::Provider::Acp,
                                source,
                                position.clone(),
                            )?;
                            let vendor = fact.vendor(&session);
                            if end <= saved {
                                let prior = se_core::scope::require_present(
                                    cx.read
                                        .native_turn(
                                            session.clone(),
                                            se_store::Provider::Acp,
                                            &vendor,
                                        )
                                        .map_err(store_error)?,
                                    "ACP captured tool",
                                    "Restore the original immutable tool fact.",
                                )?;
                                verify_tool(&prior, record.body()?.as_str())?;
                            }
                            let (turn, event, _) = identity()?;
                            metadata.push(hook::CaptureMetadata {
                                record,
                                vendor_turn: vendor,
                                turn,
                                event,
                            });
                        }
                        let evidence = se_store::SourceEvidence {
                            path: None,
                            incarnation: expected_incarnation,
                            offset,
                            length,
                            sha256: Some(digest),
                        };
                        if end <= saved {
                            let prior = se_core::scope::require_present(
                                cx.read
                                    .native_turn(session, se_store::Provider::Acp, &item.vendor)
                                    .map_err(store_error)?,
                                "ACP captured prefix",
                                "Restore the original immutable item.",
                            )?;
                            verify_prefix(&prior, item.role, text.as_str(), &evidence)?;
                            return Ok(OpStep::Complete(None));
                        }
                        if saved != offset {
                            return Err(error(
                                "ACP capture",
                                "original structured source prefix no longer aligns",
                            ));
                        }
                        let (turn, turn_event, occurred_at_us) = identity()?;
                        let (_, progress_event, _) = identity()?;
                        let facts = hook::CaptureFacts {
                            turn,
                            turn_event,
                            progress_event,
                            occurred_at_us,
                        };
                        let input = hook::CaptureRequest {
                            recovery_owner,
                            source,
                            expected: row.revision,
                            conversation,
                            provider: se_store::Provider::Acp,
                            vendor_turn: item.vendor,
                            role: item.role,
                            text,
                            evidence,
                            new_offset: end,
                            metadata,
                        };
                        match hook::plan(input, facts, cx)? {
                            OpStep::Complete(_) => Ok(OpStep::Complete(None)),
                            OpStep::Commit { batch, then } => Ok(OpStep::Commit { batch, then }),
                            OpStep::Custody(never) => match never {},
                        }
                    },
                    |kernel, cx, then, receipt| {
                        let se_core::ops::AnyOutput::HookClaude(output) =
                            kernel.committed(then, receipt, cx)?
                        else {
                            return Err(error("ACP capture", "unexpected writer result"));
                        };
                        match output.value.captured {
                            Read::Present { value } => Ok(Some(value)),
                            Read::Absent { .. } => Ok(None),
                            Read::Unreadable { reason, .. } => {
                                Err(error("ACP capture readback", reason))
                            }
                            Read::Unknown { what } => Err(error("ACP capture readback", what)),
                        }
                    },
                )
                .await?;
                if let Some(event) = result {
                    work.last_capture = Some(event);
                }
                offset = end;
            }
            // The canonical writer continuation has read back every exact item.
            binding.acknowledge(request, offset)?;
        }
        if let Some(failure) = observation.failure {
            return Err(failure.into());
        }
        if work.process_retired || work.native_already_reconciled || work.session_retired {
            if observation.active_input.is_some() || observation.cancelling {
                return Err(error(
                    "ACP final capture",
                    "original prompt is unsettled after native exit",
                ));
            }
            binding
                .session
                .drain(&super::super::launch_util::call(
                    self.store.generation,
                    deadline,
                )?)
                .await?;
        }
        Ok(())
    }
}

fn store_error(error: Box<se_store::StoreError>) -> se_types::SeError {
    se_core::store_error::store_error(&error)
}
fn bound_cursor(
    row: &se_store::ProjectionRecord,
    session: &se_types::SessionId,
    conversation: &se_types::ProviderSessionId,
    expected_incarnation: &[u8],
) -> Result<u64> {
    let original = row.original.as_deref().unwrap_or(&row.current);
    let EventBody::CaptureSource {
        session: found,
        native_ref,
        incarnation,
        ..
    } = &original.body
    else {
        return Err(error("ACP capture", "original source unavailable"));
    };
    if found != session
        || native_ref != conversation.as_str()
        || incarnation != expected_incarnation
    {
        return Err(error(
            "ACP capture",
            "original native conversation binding differs",
        ));
    }
    match &row.current.body {
        EventBody::CaptureSource { .. } => Ok(0),
        EventBody::CaptureProgress { new_offset, .. } => Ok(*new_offset),
        _ => Err(error("ACP capture", "original cursor unavailable")),
    }
}
fn verify_tool(prior: &se_store::StoredEvent, expected: &str) -> Result<()> {
    match &prior.body {
        EventBody::SessionTurn {
            role: se_store::Role::System,
            text: StoredText::Present(found),
            ..
        } if found == expected => Ok(()),
        _ => Err(error("ACP capture", "captured tool differs or was erased")),
    }
}
fn verify_prefix(
    prior: &se_store::StoredEvent,
    role: se_store::Role,
    text: &str,
    evidence: &se_store::SourceEvidence,
) -> Result<()> {
    match &prior.body {
        EventBody::SessionTurn {
            role: found_role,
            text: StoredText::Present(found_text),
            evidence: found,
            ..
        } if *found_role == role
            && found_text == text
            && found.sha256 == evidence.sha256
            && found.offset == evidence.offset
            && found.length == evidence.length
            && found.incarnation == evidence.incarnation =>
        {
            Ok(())
        }
        _ => Err(error(
            "ACP capture",
            "captured facts differ or were erased; preserve the source cursor",
        )),
    }
}
