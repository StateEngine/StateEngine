//! Canonical authenticated messages, not JSONL, feed the existing capture
//! cursor and immutable native-turn deduplication. No transcript file is made.
use super::*;
use se_core::ops::{
    hook,
    transcript::{Position, Record},
};
use se_store::{EventBody, Snapshot};
use se_types::{Body, Read};
use serde_json::Value;
use sha2::{Digest, Sha256};

impl LaunchCoordinator {
    pub(in crate::process) async fn capture_secode(
        &self,
        work: &mut owned::Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.meta.capture || !work.activated {
            return Ok(());
        }
        let managed = work.secode.clone().ok_or_else(|| {
            error(
                "SE Code capture",
                "original authenticated service binding absent",
            )
        })?;
        let service = managed.control.binding(&managed.session, deadline).await?;
        managed.service.require_same(&service.service)?;
        let source = work
            .capture_source
            .ok_or_else(|| error("SE Code capture", "original capture source absent"))?;
        let identity = crate::SessionIdentity {
            project: work.meta.project.id.clone(),
            agent: work.meta.agent.id.clone(),
            session: work.meta.session.clone(),
        };
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(identity.project.clone()),
            actor: se_store::Actor::Agent(identity.agent.clone()),
            session: Some(identity.session.clone()),
            generation: self.store.generation.get(),
        };
        let mut cursor = None;
        let mut cursors = std::collections::BTreeSet::new();
        let mut offset = 0_u64;
        let mut rows = 0_u64;
        loop {
            let page = managed
                .control
                .messages(&managed.session, cursor.as_deref(), deadline)
                .await?;
            let after_page = managed.control.binding(&managed.session, deadline).await?;
            managed.service.require_same(&after_page.service)?;
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
                let kind = row["type"]
                    .as_str()
                    .ok_or_else(|| error("SE Code message", "type absent"))?;
                if !settled(row, kind)? {
                    if work.process_retired
                        || work.native_already_reconciled
                        || work.session_retired
                    {
                        return Err(error(
                            "SE Code final capture",
                            format!(
                                "a {kind} message remains incomplete after client exit and execution settlement"
                            ),
                        ));
                    }
                    return Ok(());
                }
                let id = row["id"]
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .ok_or_else(|| error("SE Code message", "bounded native ID absent"))?;
                // Catalog estimates can change independently of a durable
                // message. Cursor bytes cover stable message facts instead.
                let mut stable = row.clone();
                if kind == "assistant"
                    && let Some(object) = stable.as_object_mut()
                {
                    object.remove("cost");
                    object.remove("costStatus");
                }
                let bytes = serde_json::to_vec(&stable)
                    .map_err(|e| error("SE Code canonical message", e))?;
                let length = bytes.len() as u64;
                let end = offset.checked_add(length).filter(|end| *end <= 32 * 1024 * 1024).ok_or_else(|| error("SE Code capture", "canonical history exceeds the 32 MiB per-read bound; no suffix was accepted"))?;
                let (role, text, vendor) = match kind {
                    "user" | "synthetic" => (
                        se_store::Role::User,
                        Body::new(
                            row["text"]
                                .as_str()
                                .ok_or_else(|| error("SE Code user input", "text absent"))?
                                .to_owned(),
                        )?,
                        id.to_owned(),
                    ),
                    "assistant" => {
                        let content = row["content"]
                            .as_array()
                            .ok_or_else(|| error("SE Code assistant", "content array absent"))?;
                        let mut text = String::new();
                        for item in content {
                            if item["type"] == "text" {
                                text.push_str(item["text"].as_str().ok_or_else(|| {
                                    error("SE Code assistant text", "text absent")
                                })?);
                            }
                        }
                        // Keep explicit tool outcomes available even when a
                        // turn has no prose. These are canonical provider facts.
                        if content.iter().any(|item| item["type"] == "tool") {
                            text.push('\n');
                            text.push_str(
                                &serde_json::to_string(content)
                                    .map_err(|e| error("SE Code tool results", e))?,
                            );
                        }
                        (se_store::Role::Assistant, Body::new(text)?, id.to_owned())
                    }
                    _ => {
                        let mut record = Record::new("secode", Some(kind));
                        record.position = Position { offset, length };
                        if kind == "system" {
                            record.message = Some(
                                row["text"]
                                    .as_str()
                                    .ok_or_else(|| error("SE Code system message", "text absent"))?
                                    .to_owned(),
                            );
                        }
                        (
                            se_store::Role::System,
                            record.body()?,
                            format!("{}secode/{id}", se_store::TRANSCRIPT_EVENT_PREFIX),
                        )
                    }
                };
                let digest = Sha256::digest(&bytes).into();
                let session = identity.session.clone();
                let conversation = se_types::ProviderSessionId::new(managed.session.clone())?;
                let expected = managed.clone();
                let recovery_owner = (work.process_retired
                    || work.native_already_reconciled
                    || work.session_retired)
                    .then(|| work.meta.owner.clone());
                let output = super::super::mail::commit::step(&self.store, admission.clone(), deadline, move |_, cx| {
                    let source_row = se_core::scope::require_present(cx.read.capture_source(source).map_err(|e| se_core::store_error::store_error(&e))?, "SE Code capture source", "Preserve the original source and cursor.")?;
                    let original = source_row.original.as_deref().unwrap_or(&source_row.current);
                    let incarnation = match &original.body {
                        EventBody::CaptureSource { session: found, native_ref, incarnation, .. } if found == &session && native_ref==&expected.session => {
                            let binding:se_core::ops::SecodeBindingView = serde_json::from_slice(incarnation).map_err(|e|error("SE Code capture source",e))?;
                            if binding.schema!="se.secode-binding/v1" || binding.service_profile!=expected.profile || binding.session_id!=expected.session || binding.initial_input_id!=expected.initial_input || binding.service_process!=expected.process || binding.incarnation!=expected.service.incarnation || binding.service_instance!=expected.service.service_instance || binding.generation!=expected.service.generation || binding.registration_version!=expected.service.registration_version {
                                return Err(error("SE Code capture source", "original authenticated service binding differs"));
                            }
                            incarnation.clone()
                        },
                        _ => return Err(error("SE Code capture source", "original session differs")),
                    };
                    let saved = match &source_row.current.body {
                        EventBody::CaptureSource { .. } => 0,
                        EventBody::CaptureProgress { new_offset, .. } => *new_offset,
                        _ => return Err(error("SE Code capture cursor", "cursor unavailable")),
                    };
                    // Prefixes are reread to verify immutable native items.
                    // Hook replay deduplication preserves the original turn.
                    if end <= saved {
                        let prior = se_core::scope::require_present(cx.read.native_turn(session, se_store::Provider::SeCode, &vendor).map_err(|e| se_core::store_error::store_error(&e))?, "SE Code captured prefix", "Restore the original immutable native item.")?;
                        if !matches!(prior.body, EventBody::SessionTurn { role: found, text: se_store::StoredText::Present(ref found_text), ref evidence, .. } if found == role && found_text == text.as_str() && evidence.sha256 == Some(digest)) { return Err(error("SE Code captured prefix", "canonical message changed after capture; preserve its cursor")); }
                        return Ok(se_core::commit::OpStep::Complete(None));
                    }
                    if saved != offset { return Err(error("SE Code capture cursor", "history no longer aligns with the original canonical prefix")); }
                    let first = crate::runtime::start::allocate_facts()?;
                    let second = crate::runtime::start::allocate_facts()?;
                    let mut entropy = [0;10];
                    se_proc::fill_entropy(&mut entropy).map_err(|e| error("SE Code capture identity", e))?;
                    use se_store::RecordIdentity;
                    let facts = hook::CaptureFacts { turn: se_store::RecordId::from_parts(first.occurred_at_us as u64 / 1000, entropy).map_err(|e| se_core::store_error::store_error(&e))?, turn_event:first.event, progress_event:second.event, occurred_at_us:first.occurred_at_us };
                    let input = hook::CaptureRequest { recovery_owner, source, expected:source_row.revision, conversation, provider:se_store::Provider::SeCode, vendor_turn:vendor, role, text, evidence:se_store::SourceEvidence { path:None, incarnation, offset, length, sha256:Some(digest) }, new_offset:end, metadata:Vec::new() };
                    match hook::plan(input, facts, cx)? {
                        se_core::commit::OpStep::Complete(_) => Ok(se_core::commit::OpStep::Complete(None)),
                        se_core::commit::OpStep::Commit { batch, then } => Ok(se_core::commit::OpStep::Commit { batch, then }),
                        se_core::commit::OpStep::Custody(never) => match never {},
                    }
                }, |kernel,cx,then,receipt| {
                    let output = kernel.committed(then,receipt,cx)?;
                    let se_core::ops::AnyOutput::HookClaude(output) = output else { return Err(error("SE Code capture commit", "unexpected output family")); };
                    match output.value.captured {
                        Read::Present { value } => Ok(Some(value)),
                        Read::Absent { .. } => Ok(None),
                        Read::Unknown { what } => Err(error("SE Code capture readback", what)),
                        Read::Unreadable { reason, .. } => Err(error("SE Code capture readback", reason)),
                    }
                }).await?;
                if let Some(event) = output {
                    work.last_capture = Some(event);
                }
                offset = end;
            }
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
                let after = managed.control.binding(&managed.session, deadline).await?;
                managed.service.require_same(&after.service)?;
                return Ok(());
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
            cursor = Some(next);
        }
    }
}
fn settled(row: &Value, kind: &str) -> Result<bool> {
    match kind {
        "assistant" => {
            if row
                .pointer("/time/completed")
                .and_then(Value::as_f64)
                .is_none()
            {
                return Ok(false);
            }
            let content = row["content"]
                .as_array()
                .ok_or_else(|| error("SE Code completed assistant", "content array absent"))?;
            for item in content.iter().filter(|item| item["type"] == "tool") {
                match item.pointer("/state/status").and_then(Value::as_str) {
                    Some("completed" | "error") => (),
                    Some("streaming" | "running") => return Ok(false),
                    _ => {
                        return Err(error(
                            "SE Code tool outcome",
                            "terminal state absent or unsupported",
                        ));
                    }
                }
            }
            Ok(true)
        }
        "shell" => match row["status"].as_str() {
            Some("running") => Ok(false),
            Some("exited" | "timeout" | "killed") => Ok(true),
            _ => Err(error(
                "SE Code shell outcome",
                "status absent or unsupported",
            )),
        },
        "compaction" => match row["status"].as_str() {
            Some("running") => Ok(false),
            Some("completed" | "failed") => Ok(true),
            _ => Err(error(
                "SE Code context outcome",
                "status absent or unsupported",
            )),
        },
        _ => Ok(true),
    }
}
