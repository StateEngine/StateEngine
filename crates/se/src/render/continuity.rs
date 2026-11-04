use se_core::ops::continuity::ResumeOutput;
use se_types::Read;
use std::io::{self, Write};
pub fn resume(value: &ResumeOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{} in {} — {}{}",
        value.principal.agent.name,
        value.principal.project.name,
        value.resume_status,
        if value.principal.preview {
            " (owner preview; nothing acknowledged)"
        } else {
            ""
        }
    )?;
    if let Some(session) = &value.principal.session_id {
        writeln!(out, "Session: {session}")?;
    }
    match &value.working_state {
        Read::Present { value } => {
            writeln!(out, "Working state (revision {}):", value.value.revision)?;
            writeln!(out, "{}", value.value.text)?;
            if let Some(command) = &value.command {
                writeln!(out, "Full working state: {command}")?;
            }
        }
        Read::Absent { .. } => writeln!(out, "No saved working state.")?,
        Read::Unknown { what } => writeln!(out, "Working state unknown: {what}")?,
        Read::Unreadable { source, reason, .. } => {
            writeln!(out, "Working state unreadable at {source}: {reason}")?
        }
    }
    for message in value.unread.items() {
        writeln!(
            out,
            "Unread from {} [{}]: {}",
            message.from.name, message.id, message.body.text
        )?;
        if let Some(command) = &message.body.command {
            writeln!(out, "Read in full: {command}")?;
        }
    }
    if value.unread.items().is_empty() && value.unread.window().complete() {
        writeln!(out, "No unread messages in this snapshot.")?;
    }
    for decision in &value.decisions.governing {
        writeln!(
            out,
            "Governing decision {}: {}",
            decision.key, decision.statement
        )?;
    }
    writeln!(
        out,
        "Pending decisions in this authorized view: {}",
        value.decisions.pending
    )?;
    super::transcript::render(&value.transcript, out)?;
    for turn in &value.recent_turns {
        writeln!(
            out,
            "Recent {} turn at {} [{}]: {}",
            turn.role, turn.at, turn.event_id, turn.preview
        )?;
        if !turn.complete {
            writeln!(out, "Full turn: {}", turn.command)?;
        }
    }
    for required in &value.required_reads {
        writeln!(
            out,
            "Required {} read {}: {}",
            required.kind, required.id, required.why
        )?;
    }
    for omitted in &value.omissions {
        writeln!(
            out,
            "Omitted {} ({}; {}): {}",
            omitted.section,
            omitted
                .count
                .map(|count| format!("{count} item(s)"))
                .unwrap_or_else(|| "count unavailable".into()),
            omitted.reason,
            omitted.command
        )?;
    }
    for attention in &value.attention {
        writeln!(out, "Attention: {attention}")?;
    }
    writeln!(
        out,
        "Context bytes: {} of {}; complete: {}",
        value.budget.used_bytes, value.budget.limit_bytes, value.complete
    )?;
    write!(
        out,
        "Continue: se --project {} resume --since {}",
        value.principal.project.id, value.cursor
    )?;
    if value.principal.preview {
        write!(out, " --preview {}", value.principal.agent.id)?;
    }
    writeln!(out)
}
