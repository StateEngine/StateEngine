//! Remove repeated recovery metadata before spending the saved-work preview.
use super::types::ResumeOutput;
use se_types::{Page, Result};

pub(super) fn recovery(value: &mut ResumeOutput) -> Result<bool> {
    let mut changed = false;
    for omitted in &mut value.omissions {
        if omitted.reason == "packet byte budget" {
            omitted.reason = "byte budget".into();
            changed = true;
        }
        if !omitted.argv.is_empty() {
            omitted.argv.clear();
            changed = true;
        }
    }
    if let se_types::Read::Present { value: state } = &mut value.working_state
        && state.command.is_some()
        && state.argv.take().is_some()
    {
        changed = true;
    }
    for turn in &mut value.recent_turns {
        // The exact executable command remains; its argv repeats the same
        // home, project and event identity for every captured turn.
        if !turn.argv.is_empty() {
            turn.argv.clear();
            changed = true;
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
    if value
        .unread
        .items()
        .iter()
        .any(|row| row.body.argv.is_some())
    {
        let mut rows = value.unread.items().to_vec();
        for row in &mut rows {
            row.body.argv = None; // Full command and original body byte count remain.
        }
        value.unread = Page::new(
            rows,
            value.unread.window().clone(),
            value.unread.next().cloned(),
        )?;
        changed = true;
    }
    Ok(changed)
}

pub(super) fn expanded(
    value: &mut ResumeOutput,
    command: crate::ops::AgentCommand,
) -> Result<bool> {
    if value
        .omissions
        .iter()
        .any(|item| item.section == "recovery_commands")
    {
        return Ok(false);
    }
    let mut count = value
        .omissions
        .iter()
        .filter(|item| !item.command.is_empty())
        .count();
    if count < 2 {
        return Ok(false);
    }
    // One target-preserving expanded read recovers all per-section commands.
    // Keep each section's count, unit, reason and tool in this small result.
    for omitted in &mut value.omissions {
        omitted.command.clear();
        omitted.argv.clear();
    }
    // Long message IDs can make per-message commands dominate the brief.
    // Required IDs remain; the expanded read restores their full commands.
    let mut rows = value.unread.items().to_vec();
    for row in &mut rows {
        count += usize::from(row.body.command.take().is_some());
    }
    value.unread = Page::new(
        rows,
        value.unread.window().clone(),
        value.unread.next().cloned(),
    )?;
    let mut omitted = super::read::omission(
        "recovery_commands",
        Some(count as u64),
        "byte budget; expand resume for commands",
        command,
        "stateengine_resume",
    );
    omitted.argv.clear();
    omitted.unit = Some("commands".into());
    value.omissions.push(omitted);
    Ok(true)
}
