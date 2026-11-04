use super::{
    identity::Identity,
    read::{self, Gathered},
    types::*,
};
use crate::{commit::Cx, ops::receipt, scope};
use se_store::Snapshot;
use se_types::{
    Omission as WindowOmission, OmissionReason, Read, Result, SeError, UnixMicros, Window,
};
use sha2::{Digest, Sha256};

pub(super) fn resume<R: Snapshot>(
    input: Resume,
    at: UnixMicros,
    identity: Identity,
    cx: &mut Cx<'_, R>,
) -> Result<ResumeOutput> {
    let mut data = read::gather(&input, &identity, input.limit, cx)?;
    let mut result = initial(&input, at, &identity, &data)?;
    fit(&input, &identity, &mut data, &mut result, cx, |value, _| {
        wire_bytes("se.resume/v1", value)
    })?;
    // used_bytes includes its own decimal digits and the final family envelope.
    for _ in 0..8 {
        let bytes = wire_bytes("se.resume/v1", &result)?;
        if result.budget.used_bytes == bytes as u64 {
            return Ok(result);
        }
        result.budget.used_bytes = bytes as u64;
    }
    Err(scope::unreadable(
        "continuity byte accounting",
        "serialized budget did not converge",
    ))
}
pub(super) fn context<R: Snapshot>(
    input: Resume,
    at: UnixMicros,
    identity: Identity,
    cx: &mut Cx<'_, R>,
) -> Result<SessionContextOutput> {
    let mut data = read::gather(&input, &identity, input.limit, cx)?;
    let mut result = initial(&input, at, &identity, &data)?;
    fit(
        &input,
        &identity,
        &mut data,
        &mut result,
        cx,
        |value, data| {
            wire_bytes(
                "secode.session-context-v1",
                &as_context(value, &identity, &data.window, &data.failures)?,
            )
        },
    )?;
    as_context(&result, &identity, &data.window, &data.failures)
}
fn initial(
    input: &Resume,
    at: UnixMicros,
    identity: &Identity,
    data: &Gathered,
) -> Result<ResumeOutput> {
    let required_reads = data.unread.items().iter().map(|message| RequiredRead {
        kind: "message".into(),
        id: message.id.to_string(),
        why: "Unread message addressed to you; a context preview is not a committed read acknowledgment.".into(),
    }).collect();
    Ok(ResumeOutput {
        schema_version: 1,
        resume_status: "ready".into(),
        principal: identity.principal.clone(),
        generated_at: receipt::timestamp(i64::try_from(at.get()).map_err(|_| {
            SeError::invalid("continuity clock", "representable Unix microseconds")
        })?)?,
        since: input.since.clone(),
        complete: false,
        budget: Budget {
            limit_bytes: input.byte_budget,
            used_bytes: u64::MAX,
        },
        working_state: data.working.clone(),
        unread: data.unread.clone(),
        required_reads,
        decisions: data.decisions.clone(),
        recent_turns: data.turns.clone(),
        transcript: data.transcript.clone(),
        code_changes: None,
        omissions: data.omissions.clone(),
        attention: data
            .attention
            .iter()
            .cloned()
            .chain(
                data.failures
                    .iter()
                    .map(|failure| format!("Continuity source error: {}", failure.message())),
            )
            .collect(),
        cursor: data.cursor.clone(),
    })
}
fn wire_bytes<T: serde::Serialize>(schema: &str, value: &T) -> Result<usize> {
    let mut value = serde_json::to_value(value)
        .map_err(|e| scope::unreadable("continuity encoding", &e.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| scope::unreadable("continuity encoding", "object output required"))?
        .insert("schema".into(), schema.into());
    serde_json::to_vec(&value)
        .map(|v| v.len())
        .map_err(|e| scope::unreadable("continuity encoding", &e.to_string()))
}
fn refresh(result: &mut ResumeOutput, data: &Gathered) {
    let unreadable = matches!(
        result.transcript.transcript_events,
        Read::Unreadable { .. } | Read::Unknown { .. }
    ) || matches!(
        result.transcript.last_compaction,
        Read::Unreadable { .. } | Read::Unknown { .. }
    ) || !data.failures.is_empty()
        || matches!(
            result.working_state,
            Read::Unreadable { .. } | Read::Unknown { .. }
        );
    result.resume_status = if unreadable {
        "integrity_blocked"
    } else if !result.required_reads.is_empty()
        || data.unread_total > 0
        || !result.omissions.is_empty()
    {
        "needs_read"
    } else {
        "ready"
    }
    .into();
    result.complete = !unreadable
        && result.omissions.is_empty()
        && result.unread.window().complete()
        && data.window.complete();
}
fn add_omission(
    result: &mut ResumeOutput,
    section: &str,
    count: Option<u64>,
    command: String,
    tool: &str,
) {
    if let Some(old) = result
        .omissions
        .iter_mut()
        .find(|v| v.section == section && v.reason == "packet byte budget")
    {
        old.count = old.count.zip(count).and_then(|(a, b)| a.checked_add(b));
    } else {
        result.omissions.push(read::omission(
            section,
            count,
            "packet byte budget",
            command,
            tool,
        ));
    }
}
fn fit<R: Snapshot, F: Fn(&ResumeOutput, &Gathered) -> Result<usize>>(
    input: &Resume,
    identity: &Identity,
    data: &mut Gathered,
    result: &mut ResumeOutput,
    cx: &mut Cx<'_, R>,
    measure: F,
) -> Result<()> {
    for _ in 0..256 {
        refresh(result, data);
        let needed = measure(result, data)?;
        if needed <= input.byte_budget as usize {
            return Ok(());
        }
        if let Read::Present { value } = &mut result.transcript.transcript_events
            && value.pop().is_some()
        {
            if let Read::Present { value: count } = &mut result.transcript.transcript_events_omitted
            {
                *count = count.saturating_add(1);
            }
            continue;
        }
        if !result.recent_turns.is_empty() {
            let omitted = result.recent_turns.remove(0);
            add_omission(
                result,
                "recent_turns",
                Some(1),
                omitted.command,
                "stateengine_event_read",
            );
            let mut fields = data.window.fields().cloned().ok_or_else(|| {
                scope::unreadable("context window", "complete source accounting is missing")
            })?;
            // Preserve actual store-read byte accounting; model input has its
            // own exact UTF-8 byte_size after this packet selection.
            fields.returned = result.recent_turns.len() as u64;
            fields.omitted_before = match fields.omitted_before {
                WindowOmission::None => WindowOmission::Known {
                    count: std::num::NonZeroU64::MIN,
                    reason: OmissionReason::Budget,
                },
                WindowOmission::Known { count, .. } => WindowOmission::Known {
                    count: count.checked_add(1).ok_or_else(|| {
                        SeError::invalid("continuity omissions", "nonoverflowing count")
                    })?,
                    reason: OmissionReason::Budget,
                },
                WindowOmission::Unknown { .. } => WindowOmission::Unknown {
                    reason: OmissionReason::Budget,
                },
            };
            data.window = Window::new(fields)?;
            continue;
        }
        if result.decisions.governing.pop().is_some() {
            let command = read::resume_command(identity, input.governing_cursor.as_ref());
            add_omission(
                result,
                "governing_decisions",
                Some(1),
                command,
                "stateengine_resume",
            );
            continue;
        }
        if result.unread.items().len() > 1 {
            let count = (result.unread.items().len() / 2).max(1) as u16;
            let smaller = read::unread(identity, count, input.byte_budget, cx)?;
            result.unread = smaller.page;
            result.required_reads.retain(|v| v.kind != "message");
            result
                .required_reads
                .extend(result.unread.items().iter().map(|m| RequiredRead {
                    kind: "message".into(),
                    id: m.id.to_string(),
                    why: "Unread message addressed to you; listing does not acknowledge it.".into(),
                }));
            result.omissions.retain(|v| v.section != "unread");
            result.omissions.push(read::omission(
                "unread",
                Some(
                    data.unread_total
                        .saturating_sub(result.unread.items().len() as u64),
                ),
                "packet byte budget",
                read::mail_command(identity),
                "stateengine_msg_list",
            ));
            continue;
        }
        if input.byte_budget <= DEFAULT_BYTES && super::compact::recovery(result)? {
            continue;
        }
        if input.byte_budget <= DEFAULT_BYTES
            && result
                .omissions
                .iter()
                .any(|item| item.section == "working_state")
            && super::compact::expanded(
                result,
                read::resume_command(identity, input.governing_cursor.as_ref()),
            )?
        {
            continue;
        }
        if let Read::Present { value } = &mut result.working_state
            && !value.value.text.is_empty()
        {
            if value.value.text.len() <= 256
                && value.command.is_some()
                && result
                    .omissions
                    .iter()
                    .any(|item| item.section == "recovery_commands")
            {
                // With unusually long IDs, use the shared recovery command
                // before sacrificing the last useful fragment of saved work.
                value.command = None;
                value.argv = None;
                continue;
            }
            let existing = result
                .omissions
                .iter()
                .position(|item| item.section == "working_state");
            if existing.is_none() {
                // Account for the recovery metadata before choosing a text cut.
                // Otherwise adding the remedy after clipping can erase the note.
                let command = format!(
                    "se --project {} working-state --agent {}",
                    identity.principal.project.id, identity.principal.agent.id
                );
                let mut omitted = read::omission(
                    "working_state",
                    Some(0),
                    "packet byte budget",
                    command,
                    "stateengine_working_state_get",
                );
                omitted.unit = Some("UTF-8 bytes".into());
                value.command = Some(omitted.command.clone());
                value.argv = Some(omitted.argv.clone());
                if input.byte_budget <= DEFAULT_BYTES {
                    omitted.argv.clear();
                }
                result.omissions.push(omitted);
                value.complete = false;
                continue;
            }
            let mut limit = value
                .value
                .text
                .len()
                .saturating_sub(needed - input.byte_budget as usize + 8);
            if value.command.is_some() && input.byte_budget <= DEFAULT_BYTES {
                limit = limit.max(value.value.text.len().min(256));
            }
            if limit < value.value.text.len() {
                value.value.text = read::clip(&value.value.text, limit).into();
                value.complete = false;
                if let Some(index) = existing {
                    result.omissions[index].count =
                        Some(value.bytes.saturating_sub(value.value.text.len() as u64));
                }
                continue;
            }
        }
        return Err(SeError::too_large(
            &format!(
                "continuity structural metadata and first unread item (retry with --budget {needed})"
            ),
            input.byte_budget as usize,
            needed,
        ));
    }
    Err(scope::unreadable(
        "continuity budget",
        "finite packet reduction did not converge",
    ))
}
fn model_input(value: &ResumeOutput) -> Result<String> {
    let state = serde_json::json!({"principal":value.principal,"working_state":value.working_state,"unread":value.unread,"required_reads":value.required_reads,"decisions":value.decisions,"recent_turns":value.recent_turns,"omissions":value.omissions,"attention":value.attention,"complete":value.complete,"resume_status":value.resume_status,"cursor":value.cursor});
    serde_json::to_string(&state)
        .map_err(|e| scope::unreadable("assembled model input", &e.to_string()))
}
fn as_context(
    value: &ResumeOutput,
    identity: &Identity,
    window: &Window,
    failures: &[se_types::ErrorBody],
) -> Result<SessionContextOutput> {
    let text = model_input(value)?;
    let mut warnings = value.attention.clone();
    for omission in &value.omissions {
        warnings.push(format!(
            "{} omitted ({}): {}",
            omission.section, omission.reason, omission.command
        ));
    }
    if identity.model.is_some() {
        warnings.push("Model metadata is the saved profile; the verified harness binding remains authoritative for the actual provider model.".into());
    }
    Ok(SessionContextOutput {
        schema_version: 1,
        contract: "secode.session-context-v1".into(),
        packet_id: format!("{:x}", Sha256::digest(text.as_bytes())),
        project_id: identity.principal.project.id.clone(),
        agent_id: identity.principal.agent.id.clone(),
        session_id: identity.principal.session_id.clone().ok_or_else(|| {
            SeError::invalid(
                "session context",
                "a bound session; owner preview uses se resume --preview",
            )
        })?,
        source_cli: identity.harness.clone(),
        generated_at: value.generated_at.clone(),
        identity: ContextDisplayIdentity {
            agent_id: identity.principal.agent.id.clone(),
            display_name: Some(identity.principal.agent.name.clone()),
            role: identity.role.clone(),
            neutral: false,
        },
        harness: identity.harness.clone(),
        model: identity.model.clone(),
        conversation: identity.conversation.clone().ok_or_else(|| {
            scope::unreadable(
                "session context",
                "bound session has no saved provider conversation",
            )
        })?,
        byte_size: text.len() as u64,
        truncated: !value.complete,
        assembled_model_input: text,
        continuity: window.clone(),
        continuity_summary: ContinuitySummary {
            rows: value.recent_turns.len() as u64,
            latest_ts: value.recent_turns.last().map(|v| v.at.clone()),
        },
        warnings,
        failures: failures.to_vec(),
        cursor: value.cursor.clone(),
    })
}
