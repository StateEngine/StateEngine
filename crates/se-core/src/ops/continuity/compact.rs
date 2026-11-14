//! Fit previews while preserving scoped recovery and source counts.
use super::types::ResumeOutput;

pub(super) fn unread_preview(value: &mut ResumeOutput, excess: usize) -> bool {
    let Some(row) = value.unread.items_mut().first_mut() else {
        return false;
    };
    if row.body.complete || row.body.text.is_empty() {
        return false;
    }
    // Already-partial mail keeps its byte count, required ID and recovery.
    let limit = row.body.text.len().saturating_sub(excess.saturating_add(8));
    let limit = super::read::clip(&row.body.text, limit).len();
    row.body.text.truncate(limit);
    true
}

pub(super) fn recovery(value: &mut ResumeOutput) -> bool {
    let mut changed = false;
    let shared = value
        .omissions
        .iter()
        .any(|item| item.section == "recovery_commands");
    for omitted in &mut value.omissions {
        if shared && omitted.section != "recovery_commands" && !omitted.command.is_empty() {
            omitted.command.clear();
            omitted.argv.clear();
            changed = true;
        }
        if omitted.reason == "packet byte budget" {
            omitted.reason = "byte budget".into();
            changed = true;
        }
    }
    if shared
        && let se_types::Read::Present { value: state } = &mut value.working_state
        && state.command.take().is_some()
    {
        state.argv = None;
        changed = true;
    }
    // The unread omission already keeps one scoped, paged full-mail read.
    // Repeating that same recovery on every preview can make even one unread
    // item exceed the MCP wire budget after JSON escaping and framing.
    if value
        .omissions
        .iter()
        .any(|item| item.section == "unread" && !item.command.is_empty() && !item.argv.is_empty())
    {
        for row in value.unread.items_mut() {
            changed |= row.body.command.take().is_some();
            changed |= row.body.argv.take().is_some();
        }
    }
    for required in &mut value.required_reads {
        if required.why.len() > 64 {
            required.why = "Unread; read this message in full.".into();
            changed = true;
        }
    }
    // The unread page and its omission count already report this exact fact.
    let previous = value.attention.len();
    value.attention.retain(|text| !text.ends_with(
        "unread message(s) require reading; listing and context construction do not mark them read.",
    ));
    changed |= previous != value.attention.len();
    changed
}

pub(super) fn expanded(value: &mut ResumeOutput, command: crate::ops::AgentCommand) -> bool {
    if value
        .omissions
        .iter()
        .any(|item| item.section == "recovery_commands")
    {
        return false;
    }
    let mut count = value
        .omissions
        .iter()
        .filter(|item| !item.command.is_empty())
        .count()
        + value
            .recent_turns
            .iter()
            .filter(|item| !item.command.is_empty())
            .count()
        + usize::from(matches!(&value.working_state,
            se_types::Read::Present { value: state } if state.command.is_some()));
    if count < 2 {
        return false;
    }
    // One target-preserving expanded read recovers all per-section commands.
    // Keep each section's count, unit, reason and tool in this small result.
    for omitted in &mut value.omissions {
        omitted.command.clear();
        omitted.argv.clear();
    }
    for turn in &mut value.recent_turns {
        turn.command.clear();
        turn.argv.clear();
    }
    if let se_types::Read::Present { value: state } = &mut value.working_state {
        state.command = None;
        state.argv = None;
    }
    // Long message IDs can make per-message commands dominate the brief.
    // Required IDs remain; the expanded read restores their full commands.
    for row in value.unread.items_mut() {
        count += usize::from(row.body.command.take().is_some());
        row.body.argv = None;
    }
    let mut omitted = super::read::omission(
        "recovery_commands",
        Some(count as u64),
        "byte budget; expand resume for commands",
        command,
        "stateengine_resume",
    );
    omitted.unit = Some("commands".into());
    value.omissions.push(omitted);
    true
}
