//! Complete turns and explicitly interrupted prefixes enter immutable capture.
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
        .map_err(store_error)?;
    Ok((id, facts.event, facts.occurred_at_us))
}
struct AcpItemPlan {
    source: se_store::RecordId,
    session: se_types::SessionId,
    conversation: se_types::ProviderSessionId,
    recovery_owner: Option<se_types::HumanId>,
    vendor: String,
    role: se_store::Role,
    text: se_types::Body,
    evidence: se_store::SourceEvidence,
    tool_facts: Vec<(se_core::ops::transcript::Record, String)>,
}
fn plan_acp_item<S: Snapshot>(
    plan: AcpItemPlan,
    cx: &mut se_core::commit::Cx<'_, S>,
) -> Result<OpStep<Option<se_types::EventId>, se_core::ports::Then>> {
    let end = plan.evidence.offset + plan.evidence.length;
    let row = se_core::scope::require_present(
        cx.read.capture_source(plan.source).map_err(store_error)?,
        "ACP capture source",
        "Preserve the original native binding and cursor.",
    )?;
    let saved = bound_cursor(
        &row,
        &plan.session,
        &plan.conversation,
        &plan.evidence.incarnation,
    )?;
    let mut metadata = Vec::new();
    for (record, vendor) in plan.tool_facts {
        if end <= saved {
            let prior = se_core::scope::require_present(
                cx.read
                    .native_turn(plan.session.clone(), se_store::Provider::Acp, &vendor)
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
    if end <= saved {
        let prior = se_core::scope::require_present(
            cx.read
                .native_turn(plan.session, se_store::Provider::Acp, &plan.vendor)
                .map_err(store_error)?,
            "ACP captured prefix",
            "Restore the original immutable item.",
        )?;
        verify_prefix(&prior, plan.role, plan.text.as_str(), &plan.evidence)?;
        return Ok(OpStep::Complete(None));
    }
    if saved != plan.evidence.offset {
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
        recovery_owner: plan.recovery_owner,
        source: plan.source,
        expected: row.revision,
        conversation: plan.conversation,
        provider: se_store::Provider::Acp,
        vendor_turn: plan.vendor,
        role: plan.role,
        text: plan.text,
        evidence: plan.evidence,
        new_offset: end,
        metadata,
    };
    match hook::plan(input, facts, cx)? {
        OpStep::Complete(_) => Ok(OpStep::Complete(None)),
        OpStep::Commit { batch, then } => Ok(OpStep::Commit { batch, then }),
        OpStep::Custody(never) => match never {},
    }
}

fn readback_acp_capture<S: Snapshot>(
    kernel: &se_core::dispatch::Kernel,
    cx: &mut se_core::commit::Cx<'_, S>,
    then: se_core::ports::Then,
    receipt: se_store::CommitReceipt,
) -> Result<Option<se_types::EventId>> {
    let se_core::ops::AnyOutput::HookClaude(output) = kernel.committed(then, receipt, cx)? else {
        return Err(error("ACP capture", "unexpected writer result"));
    };
    match output.value.captured {
        Read::Present { value } => Ok(Some(value)),
        Read::Absent { .. } => Ok(None),
        Read::Unreadable { reason, .. } => Err(error("ACP capture readback", reason)),
        Read::Unknown { what } => Err(error("ACP capture readback", what)),
    }
}

fn finish_acp_observation(
    observation: se_harness::acp::Observation,
    final_capture: bool,
    incomplete: bool,
) -> Result<()> {
    if let Some(failure) = observation.failure {
        return Err(failure.into());
    }
    if final_capture && incomplete {
        return Err(error(
            "ACP final capture",
            "The native provider exited without completing the original prompt. Observed partial input, replies and tool updates are saved as incomplete diagnostics, not a completed turn or proof of input acceptance. Preserve this history and use se launch <agent> to start a separate conversation without replaying the interrupted input.",
        ));
    }
    if final_capture && (observation.active_input.is_some() || observation.cancelling) {
        return Err(error(
            "ACP final capture",
            "Original protocol input or cancellation remains unsettled after native exit; no completion is claimed.",
        ));
    }
    Ok(())
}
impl LaunchCoordinator {
    async fn drain_acp_binding(
        &self,
        work: &owned::Work,
        final_capture: bool,
        deadline: &Deadline,
    ) -> Result<std::sync::Arc<crate::harness::acp::Binding>> {
        let binding = bound(work.binding.as_ref().ok_or_else(|| {
            error(
                "ACP capture",
                "original live protocol source unavailable; retain its incomplete capture",
            )
        })?)?
        .clone();
        if final_capture {
            if work.last_witness.is_none() {
                return Err(error(
                    "ACP final capture",
                    "original native exit witness is absent",
                ));
            }
            binding
                .session
                .drain_stream(&super::super::launch_util::call(
                    self.store.generation,
                    deadline,
                )?)
                .await?;
        }
        Ok(binding)
    }
    pub(in crate::process) async fn capture_acp(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let final_capture =
            work.process_retired || work.native_already_reconciled || work.session_retired;
        let binding = self
            .drain_acp_binding(work, final_capture, deadline)
            .await?;
        let observation = binding.session.observe()?;
        let conversation = se_types::ProviderSessionId::new(
            observation
                .conversation
                .clone()
                .ok_or_else(|| error("ACP capture", "conversation absent"))?,
        )?;
        let source = work
            .capture_source
            .ok_or_else(|| error("ACP capture", "original source absent"))?;
        let incarnation = binding.source()?;
        let admission = self.session_admission(work);
        let mut groups = observation
            .completed
            .iter()
            .map(|request| Ok((Some(*request), binding.items(*request)?)))
            .collect::<Result<Vec<_>>>()?;
        let interrupted = final_capture
            .then(|| binding.interrupted_items())
            .transpose()?
            .flatten();
        let incomplete = interrupted.is_some();
        if let Some(items) = interrupted {
            groups.push((None, items));
        }
        for (request, items) in groups {
            let mut offset = binding.offset();
            for item in items {
                let length = item.bytes.len() as u64;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| error("ACP capture", "source range overflow"))?;
                let position = Position { offset, length };
                let mut tool_facts = Vec::with_capacity(item.facts.len());
                for fact in &item.facts {
                    let record = fact.record(
                        &binding.identity,
                        se_store::Provider::Acp,
                        source,
                        position.clone(),
                    )?;
                    tool_facts.push((record, fact.vendor(&work.meta.session)));
                }
                let text = item.body(position)?;
                let plan = AcpItemPlan {
                    source,
                    session: work.meta.session.clone(),
                    conversation: conversation.clone(),
                    recovery_owner: final_capture.then(|| work.meta.owner.clone()),
                    vendor: item.vendor,
                    role: item.role,
                    text,
                    evidence: se_store::SourceEvidence {
                        path: None,
                        incarnation: incarnation.clone(),
                        offset,
                        length,
                        sha256: Some(Sha256::digest(&item.bytes).into()),
                    },
                    tool_facts,
                };
                let result = super::super::mail::commit::step(
                    &self.store,
                    admission.clone(),
                    deadline,
                    move |_, cx| plan_acp_item(plan, cx),
                    readback_acp_capture,
                )
                .await?;
                if let Some(event) = result {
                    work.last_capture = Some(event);
                }
                offset = end;
            }
            // The canonical writer continuation has read back every exact item.
            match request {
                Some(request) => binding.acknowledge(request, offset)?,
                None => binding.acknowledge_interrupted(offset),
            }
        }
        finish_acp_observation(observation, final_capture, incomplete)
    }
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
