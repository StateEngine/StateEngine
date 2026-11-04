use super::{identity::Identity, types::*};
use crate::{
    commit::Cx,
    ops::{
        inputs::{MessageBox, MessageList, MessageView},
        message, receipt,
    },
    scope,
    store_error::store_error,
};
use se_store::{Actor, EventBody, ReadBudget, Snapshot, StoredText};
use se_types::{OmissionReason, PageRequest, Read, Result, SeError, Window};
use std::{num::NonZeroU32, time::Duration};

pub(super) struct Gathered {
    pub working: Read<ContinuityWorkingState>,
    pub unread: se_types::Page<crate::ops::MessageRow>,
    pub unread_total: u64,
    pub decisions: Decisions,
    pub turns: Vec<RecentTurn>,
    pub transcript: super::super::transcript::View,
    pub window: Window,
    pub cursor: se_types::Cursor,
    pub omissions: Vec<Omission>,
    pub attention: Vec<String>,
    pub failures: Vec<se_types::ErrorBody>,
}
pub(super) fn budget(limit: u32) -> Result<ReadBudget> {
    Ok(ReadBudget {
        page: PageRequest {
            after: None,
            limit: NonZeroU32::new(limit)
                .ok_or_else(|| SeError::invalid("continuity limit", "positive"))?,
            max_bytes: NonZeroU32::new(256 * 1024)
                .ok_or_else(|| SeError::invalid("continuity bytes", "positive"))?,
        },
        deadline: Duration::from_millis(250),
    })
}
pub(super) fn unread<R: Snapshot>(
    identity: &Identity,
    limit: u16,
    byte_budget: u32,
    cx: &mut Cx<'_, R>,
) -> Result<crate::ops::MessagePage> {
    message::list(
        MessageList {
            cli_list: identity.principal.preview,
            view: MessageView::Unread,
            mailbox: MessageBox::Inbox,
            from: None,
            kind: None,
            full: false,
            limit,
            preview_chars: Some(if byte_budget <= DEFAULT_BYTES {
                100
            } else {
                400
            }),
            cursor: None,
            owner_to: identity
                .principal
                .preview
                .then(|| identity.principal.agent.id.to_string()),
        },
        cx,
    )
}
pub(super) fn gather<R: Snapshot>(
    input: &Resume,
    identity: &Identity,
    limit: u16,
    cx: &mut Cx<'_, R>,
) -> Result<Gathered> {
    let agent = &identity.principal.agent.id;
    let purpose = se_store::PositionPurpose::Continuity(agent.clone());
    let since = input
        .since
        .as_ref()
        .map(|cursor| cx.read.cursor_position(cursor, purpose.clone()))
        .transpose()
        .map_err(|e| store_error(&e))?;
    // The store's global head may be another agent's private event. The
    // target's resume head advances with its own turns, state, sessions and
    // mail, and is the admitted checkpoint for this target-bound cursor.
    let head = scope::require_present(
        cx.read
            .resume_head(Actor::Agent(agent.clone()))
            .map_err(|e| store_error(&e))?,
        "continuity checkpoint",
        "Restore the selected agent's registered resume head before retrying context.",
    )?
    .through;
    let cursor = cx
        .read
        .position_cursor(&head, purpose)
        .map_err(|e| store_error(&e))?;
    let mut attention = Vec::new();
    match cx
        .read
        .cursor(agent.clone(), "continuity".into())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } if value.acknowledged.is_none() => attention.push(
            "The previous issued context window is not acknowledged. This read does not acknowledge a packet or mark mail read.".into(),
        ),
        Read::Present { .. } | Read::Absent { .. } => (),
        other => {
            scope::require_present(
                other,
                "continuity cursor head",
                "Restore its issuing and acknowledgment facts; issuance alone is not a read.",
            )?;
        }
    }
    let working = receipt::working_state_get(agent.clone(), cx)?
        .value
        .map(|value| ContinuityWorkingState {
            bytes: value.text.len() as u64,
            value,
            complete: true,
            command: None,
            argv: None,
        });
    let mail = unread(identity, limit, input.byte_budget, cx)?;
    let unread_total = mail.unread_total.ok_or_else(|| {
        scope::unreadable(
            "continuity unread count",
            "the exact matching count was not supplied",
        )
    })?;
    if unread_total > 0 {
        attention.push(format!("{unread_total} unread message(s) require reading; listing and context construction do not mark them read."));
    }
    let pending = cx.read.decision_count(true).map_err(|e| store_error(&e))?;
    let mut omissions = Vec::new();
    let mut failures = Vec::new();
    match &working {
        Read::Unknown { what } => failures.push(scope::unreadable("working state", what).body),
        Read::Unreadable { source, reason, .. } => {
            failures.push(scope::unreadable(source, reason).body)
        }
        Read::Present { .. } | Read::Absent { .. } => (),
    }
    let mut governing_budget = budget(u32::from(limit))?;
    governing_budget.page.after = input.governing_cursor.clone();
    let mut governing_next = None;
    let governing_command = resume_command(identity, input.governing_cursor.as_ref());
    let governing = match cx.read.governing_decisions(governing_budget) {
        Ok(page) => {
            governing_next = page.next().cloned();
            window_omission(
                "governing_decisions",
                page.window(),
                &resume_command(identity, governing_next.as_ref()),
                "stateengine_resume",
                &mut omissions,
            );
            page.into_items()
        }
        Err(error) => {
            let failure = store_error(&error);
            failures.push(failure.body);
            omissions.push(omission(
                "governing_decisions",
                None,
                "governing source refused; exact omitted count is unavailable",
                governing_command.clone(),
                "stateengine_resume",
            ));
            Vec::new()
        }
    };
    let mut decisions = Vec::new();
    for head in governing {
        match super::rulings::decode(head, &cx.admission.scope) {
            Ok(decision) => decisions.push(decision),
            Err(error) => {
                let message = error.body.message();
                if !failures.iter().any(|known| known.message() == message) {
                    failures.push(error.body);
                }
                if let Some(old) = omissions.iter_mut().find(|item| {
                    item.section == "governing_decisions"
                        && item.reason == "a governing statement could not be reconstructed"
                }) {
                    old.count = old.count.and_then(|count| count.checked_add(1));
                } else {
                    omissions.push(omission(
                        "governing_decisions",
                        Some(1),
                        "a governing statement could not be reconstructed",
                        governing_command.clone(),
                        "stateengine_resume",
                    ));
                }
            }
        }
    }
    let transcript = super::super::transcript::read(agent, None, cx);
    if let Read::Present { value } = &transcript.last_compaction {
        attention.push(format!(
            "Provider compaction recorded at native transcript byte {} (event {}).",
            value.record.position.offset, value.event_id
        ));
    }
    let turns = cx
        .read
        .recent_turns(agent.clone(), since, budget(u32::from(limit))?)
        .map_err(|e| store_error(&e))?;
    window_omission(
        "recent_turns",
        turns.window(),
        &format!(
            "se --project {} history --kind session.turn",
            identity.principal.project.id
        ),
        "stateengine_event_read",
        &mut omissions,
    );
    let mut window = turns.window().clone();
    let mut recent = Vec::new();
    let mut unreadable_turns = 0;
    let mut previewed_turns = 0;
    for event in turns.into_items() {
        let EventBody::SessionTurn {
            agent: target,
            text,
            role,
            ..
        } = event.body
        else {
            return Err(scope::unreadable(
                "recent turns",
                "the targeted turn read returned another kind",
            ));
        };
        if target != *agent || event.header.scope != cx.admission.scope {
            return Err(scope::unreadable(
                "recent turns",
                "the targeted read returned another agent or project",
            ));
        }
        let StoredText::Present(text) = text else {
            unreadable_turns += 1;
            failures.push(
                scope::unreadable(
                    "recent turn",
                    "captured content was erased; the packet is incomplete",
                )
                .body,
            );
            continue;
        };
        let preview = clip(&text, 1600).to_owned();
        if preview.len() != text.len() {
            previewed_turns += 1;
        }
        let argv = vec![
            "se".into(),
            "--project".into(),
            identity.principal.project.id.to_string(),
            "history".into(),
            "--event".into(),
            event.header.event.to_string(),
        ];
        recent.push(RecentTurn {
            event_id: event.header.event,
            at: receipt::timestamp(event.header.occurred_at_us)?,
            role: match role {
                se_store::Role::System => "system",
                se_store::Role::User => "user",
                se_store::Role::Assistant => "assistant",
                se_store::Role::Tool => "tool",
            }
            .into(),
            complete: preview.len() == text.len(),
            bytes: text.len() as u64,
            preview,
            command: argv.join(" "),
            argv,
        });
    }
    if unreadable_turns > 0 {
        let mut fields = window.fields().cloned().ok_or_else(|| {
            scope::unreadable("continuity window", "source accounting is missing")
        })?;
        fields.returned = recent.len() as u64;
        fields.unreadable += unreadable_turns;
        window = Window::new(fields)?;
    }
    if previewed_turns > 0 {
        omissions.push(omission(
            "recent_turn_content",
            Some(previewed_turns),
            "UTF-8 content preview",
            format!(
                "se --project {} history --kind session.turn",
                identity.principal.project.id
            ),
            "stateengine_event_read",
        ));
    }
    window_omission(
        "unread",
        mail.page.window(),
        &mail_command(identity),
        "stateengine_msg_list",
        &mut omissions,
    );
    Ok(Gathered {
        working,
        unread: mail.page,
        unread_total,
        decisions: Decisions {
            next_cursor: governing_next,
            governing: decisions,
            pending,
        },
        turns: recent,
        transcript,
        window,
        cursor,
        omissions,
        attention,
        failures,
    })
}
pub(super) fn clip(text: &str, maximum: usize) -> &str {
    let mut end = maximum.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
pub(super) fn omission(
    section: &str,
    count: Option<u64>,
    reason: &str,
    command: String,
    tool: &str,
) -> Omission {
    Omission {
        section: section.into(),
        count,
        unit: None,
        reason: reason.into(),
        tool: tool.into(),
        argv: command.split(' ').map(str::to_owned).collect(),
        command,
    }
}
fn window_omission(
    section: &str,
    window: &Window,
    command: &str,
    tool: &str,
    out: &mut Vec<Omission>,
) {
    if !window.complete() {
        let reason = match window.omitted().reason {
            Some(OmissionReason::Budget) => "source byte budget",
            Some(OmissionReason::Limit) => "source row limit",
            Some(OmissionReason::Unreadable) => "source unreadable",
            _ => "source incomplete",
        };
        out.push(omission(
            section,
            window.omitted().count,
            reason,
            command.into(),
            tool,
        ));
    }
}

pub(super) fn mail_command(identity: &Identity) -> String {
    let command = format!(
        "se --project {} msg list --full",
        identity.principal.project.id
    );
    if identity.principal.preview {
        format!("{command} --to {}", identity.principal.agent.id)
    } else {
        command
    }
}

pub(super) fn resume_command(identity: &Identity, governing: Option<&se_types::Cursor>) -> String {
    let mut command = format!(
        "se --project {} resume --budget 1048576",
        identity.principal.project.id
    );
    if identity.principal.preview {
        command.push_str(&format!(" --preview {}", identity.principal.agent.id));
    }
    if let Some(cursor) = governing {
        command.push_str(&format!(" --governing-cursor {cursor}"));
    }
    command
}

struct BudgetRecovery<'a> {
    identity: &'a Identity,
    input: &'a Resume,
    needed: usize,
}
impl se_types::OperationCommand for BudgetRecovery<'_> {
    fn cli_argv(&self) -> Vec<String> {
        let mut argv = vec![
            "se".into(),
            "--project".into(),
            self.identity.principal.project.id.to_string(),
            "resume".into(),
            "--limit".into(),
            self.input.limit.to_string(),
            "--budget".into(),
            self.needed.to_string(),
        ];
        if self.identity.principal.preview {
            argv.extend([
                "--preview".into(),
                self.identity.principal.agent.id.to_string(),
            ]);
        }
        for (flag, cursor) in [
            ("--since", self.input.since.as_ref()),
            ("--governing-cursor", self.input.governing_cursor.as_ref()),
        ] {
            if let Some(cursor) = cursor {
                argv.extend([flag.into(), cursor.to_string()]);
            }
        }
        argv
    }
}
pub(super) fn budget_refusal(
    identity: &Identity,
    input: &Resume,
    needed: usize,
) -> Result<SeError> {
    let mut error = SeError::too_large(
        &format!(
            "continuity structural metadata and first unread item (retry with --budget {needed})"
        ),
        input.byte_budget as usize,
        needed,
    );
    error.body = error.body.with_remedy(se_types::Remedy {
        text: format!("Retry with --budget {needed} using the same selected agent and cursor."),
        command: Some(se_types::Cmd::Se {
            argv: se_types::Argv::from_op(&BudgetRecovery {
                identity,
                input,
                needed,
            })?,
        }),
    });
    Ok(error)
}
