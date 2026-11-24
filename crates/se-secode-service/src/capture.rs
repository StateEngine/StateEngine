//! Canonical authenticated messages, not JSONL, feed the existing capture
//! cursor and immutable native-turn deduplication. No transcript file is made.
use super::*;
use se_core::commit::OpStep;
use se_core::ops::hook;
use se_core::store_error::store_error;
use se_harness::secode_process::{CanonicalMessage, CaptureRow};
use se_store::{EventBody, Snapshot};
use se_types::Read;
use serde_json::Value;
use sha2::{Digest, Sha256};

struct CaptureTarget<'a> {
    admission: &'a se_store::Admission,
    source: se_store::RecordId,
    session: &'a se_types::SessionId,
    managed: &'a Prepared,
    recovery_owner: Option<se_types::HumanId>,
}

impl<H: HostPort> Coordinator<'_, H> {
    pub async fn capture_secode(
        &self,
        work: &mut impl SecodeWork,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.capture_enabled() || !work.activated() {
            return Ok(());
        }
        if self.observe_secode_service_loss(work, deadline).await? {
            return Err(self.secode_loss_error(work));
        }
        let managed = work.secode().cloned().ok_or_else(|| {
            error(
                "SE Code capture",
                "original authenticated service binding absent",
            )
        })?;
        // Transport may change; the immutable source below still verifies the
        // original service/process and every previously captured message.
        let qualified = managed.current()?;
        qualified.binding(&managed.session, deadline).await?;
        let source = work
            .capture_source()
            .ok_or_else(|| error("SE Code capture", "original capture source absent"))?;
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.project_id().clone()),
            actor: se_store::Actor::Agent(work.agent_id().clone()),
            session: Some(work.session().clone()),
            generation: self.0.generation().get(),
        };
        let retired =
            work.process_retired() || work.native_already_reconciled() || work.session_retired();
        let session = work.session().clone();
        let target = CaptureTarget {
            admission: &admission,
            source,
            session: &session,
            managed: &managed,
            recovery_owner: retired.then(|| work.owner().clone()),
        };
        let mut cursor = None;
        let mut cursors = std::collections::BTreeSet::new();
        let mut offset = 0_u64;
        let mut rows = 0_u64;
        loop {
            let page = qualified
                .control
                .messages(&managed.session, cursor.as_deref(), deadline)
                .await?;
            qualified.binding(&managed.session, deadline).await?;
            let data = page["data"]
                .as_array()
                .ok_or_else(|| error("SE Code canonical messages", "data array absent"))?;
            if data.len() > 100 {
                return Err(error(
                    "SE Code canonical messages",
                    "page exceeds requested row bound",
                ));
            }
            for row in data {
                rows += 1;
                if rows > 10000 {
                    return Err(error(
                        "SE Code capture",
                        "ten-thousand message read bound reached; original cursor remains retained",
                    ));
                }
                let message = match CaptureRow::read(row, offset)? {
                    CaptureRow::Ready(message) => message,
                    CaptureRow::Pending { kind } => {
                        if retired {
                            return Err(error(
                                "SE Code final capture",
                                format!(
                                    "a {kind} message remains incomplete after client exit and execution settlement"
                                ),
                            ));
                        }
                        return Ok(());
                    }
                };
                let end = message.end;
                if let Some(event) = self
                    .commit_secode_message(&target, offset, message, deadline)
                    .await?
                {
                    work.set_last_capture(Some(event));
                }
                offset = end;
            }
            let Some(next) = next_page_cursor(&page, &mut cursors)? else {
                qualified.binding(&managed.session, deadline).await?;
                self.0
                    .verify_captured_end(admission.clone(), source, offset, deadline)
                    .await?;
                return Ok(());
            };
            cursor = Some(next);
        }
    }
    async fn commit_secode_message(
        &self,
        target: &CaptureTarget<'_>,
        offset: u64,
        message: CanonicalMessage,
        deadline: &Deadline,
    ) -> Result<Option<se_types::EventId>> {
        let CanonicalMessage {
            bytes,
            end,
            role,
            text,
            vendor,
        } = message;
        let length = bytes.len() as u64;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let session = target.session.clone();
        let conversation = se_types::ProviderSessionId::new(target.managed.session.clone())?;
        let expected = target.managed.clone();
        let recovery_owner = target.recovery_owner.clone();
        let source = target.source;
        self.0
            .commit_step(
                target.admission.clone(),
                deadline,
                move |_, cx| {
                    let source_row = se_core::scope::require_present(
                        cx.read
                            .capture_source(source)
                            .map_err(|e| store_error(&e))?,
                        "SE Code capture source",
                        "Preserve the original source and cursor.",
                    )?;
                    let original = source_row
                        .original
                        .as_deref()
                        .unwrap_or(&source_row.current);
                    let (incarnation, saved) = verify_secode_capture_source(
                        &original.body,
                        &source_row.current.body,
                        &session,
                        &expected,
                    )?;
                    // Prefixes are reread to verify immutable native items.
                    // Hook replay deduplication preserves the original turn.
                    if end <= saved {
                        let prior = se_core::scope::require_present(
                            cx.read
                                .native_turn(session, se_store::Provider::SeCode, &vendor)
                                .map_err(|e| store_error(&e))?,
                            "SE Code captured prefix",
                            "Restore the original immutable native item.",
                        )?;
                        verify_secode_captured_prefix(&prior.body, role, text.as_str(), digest)?;
                        return Ok(OpStep::Complete(None));
                    }
                    if saved != offset {
                        return Err(error(
                            "SE Code capture cursor",
                            "history no longer aligns with the original canonical prefix",
                        ));
                    }
                    let facts = allocate_capture_facts::<H>()?;
                    let input = hook::CaptureRequest {
                        recovery_owner,
                        source,
                        expected: source_row.revision,
                        conversation,
                        provider: se_store::Provider::SeCode,
                        vendor_turn: vendor,
                        role,
                        text,
                        evidence: se_store::SourceEvidence {
                            path: None,
                            incarnation,
                            offset,
                            length,
                            sha256: Some(digest),
                        },
                        new_offset: end,
                        metadata: Vec::new(),
                    };
                    match hook::plan(input, facts, cx)? {
                        OpStep::Complete(_) => Ok(OpStep::Complete(None)),
                        OpStep::Commit { batch, then } => Ok(OpStep::Commit { batch, then }),
                        OpStep::Custody(never) => match never {},
                    }
                },
                |kernel, cx, then, receipt| {
                    let output = kernel.committed(then, receipt, cx)?;
                    let se_core::ops::AnyOutput::HookClaude(output) = output else {
                        return Err(error("SE Code capture commit", "unexpected output family"));
                    };
                    match output.value.captured {
                        Read::Present { value } => Ok(Some(value)),
                        Read::Absent { .. } => Ok(None),
                        Read::Unknown { what } => Err(error("SE Code capture readback", what)),
                        Read::Unreadable { reason, .. } => {
                            Err(error("SE Code capture readback", reason))
                        }
                    }
                },
            )
            .await
    }
}

fn verify_secode_capture_source(
    original: &EventBody<se_store::StoredText>,
    current: &EventBody<se_store::StoredText>,
    session: &se_types::SessionId,
    expected: &Prepared,
) -> Result<(Vec<u8>, u64)> {
    let incarnation = match original {
        EventBody::CaptureSource {
            session: found,
            native_ref,
            incarnation,
            ..
        } if found == session && native_ref == &expected.session => {
            let binding: se_core::ops::SecodeBindingView = serde_json::from_slice(incarnation)
                .map_err(|e| error("SE Code capture source", e))?;
            if binding.schema != "se.secode-binding/v1"
                || binding.service_profile != expected.profile
                || binding.session_id != expected.session
                || binding.initial_input_id != expected.initial_input
                || binding.service_process != expected.process
                || binding.incarnation != expected.service.incarnation
                || binding.service_instance != expected.service.service_instance
                || binding.generation != expected.service.generation
                || binding.registration_version != expected.service.registration_version
            {
                return Err(error(
                    "SE Code capture source",
                    "original authenticated service binding differs",
                ));
            }
            incarnation.clone()
        }
        _ => return Err(error("SE Code capture source", "original session differs")),
    };
    let saved = match current {
        EventBody::CaptureSource { .. } => 0,
        EventBody::CaptureProgress { new_offset, .. } => *new_offset,
        _ => return Err(error("SE Code capture cursor", "cursor unavailable")),
    };
    Ok((incarnation, saved))
}

fn verify_secode_captured_prefix(
    body: &EventBody<se_store::StoredText>,
    role: se_store::Role,
    text: &str,
    digest: [u8; 32],
) -> Result<()> {
    if !matches!(
        body,
        EventBody::SessionTurn {
            role: found,
            text: se_store::StoredText::Present(found_text),
            evidence,
            ..
        } if *found == role && found_text == text && evidence.sha256 == Some(digest)
    ) {
        return Err(error(
            "SE Code captured prefix",
            "canonical message changed after capture; preserve its cursor",
        ));
    }
    Ok(())
}

fn allocate_capture_facts<H: HostPort>() -> Result<hook::CaptureFacts> {
    use se_store::RecordIdentity;
    let first = H::allocate_facts()?;
    let second = H::allocate_facts()?;
    let mut entropy = [0; 10];
    se_proc::fill_entropy(&mut entropy).map_err(|e| error("SE Code capture identity", e))?;
    Ok(hook::CaptureFacts {
        turn: se_store::RecordId::from_parts(first.occurred_at_us as u64 / 1000, entropy)
            .map_err(|e| store_error(&e))?,
        turn_event: first.event,
        progress_event: second.event,
        occurred_at_us: first.occurred_at_us,
    })
}

fn next_page_cursor(
    page: &Value,
    cursors: &mut std::collections::BTreeSet<String>,
) -> Result<Option<String>> {
    let page_cursor = page
        .get("cursor")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            error(
                "SE Code message page",
                "required cursor object absent or malformed",
            )
        })?;
    let next = page_cursor.get("next");
    // The supported page writer omits next at EOF; older readers
    // also accept its explicit nullable form. Missing page metadata
    // above remains unreadable instead of becoming an empty history.
    if next.is_none_or(Value::is_null) {
        return Ok(None);
    }
    let next = next
        .and_then(Value::as_str)
        .filter(|next| !next.is_empty() && next.len() <= 1024)
        .ok_or_else(|| error("SE Code message page", "next cursor malformed"))?
        .to_owned();
    if !cursors.insert(next.clone()) || cursors.len() > 100 {
        return Err(error(
            "SE Code message pagination",
            "repeated or oversized page traversal",
        ));
    }
    Ok(Some(next))
}
