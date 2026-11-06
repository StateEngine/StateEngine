use se_core::ops::continuity::ResumeOutput;
use se_types::Read;
use std::io::{self, Write};
pub fn resume(value: &ResumeOutput, out: &mut impl Write) -> io::Result<()> {
    resume_at(value, None, out)
}
pub(super) fn resume_at(
    value: &ResumeOutput,
    home: Option<&std::path::Path>,
    out: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        out,
        "{}",
        if value.principal.preview {
            "Saved agent context"
        } else {
            "Who am I?"
        }
    )?;
    let status = if value.principal.preview {
        match value.resume_status.as_str() {
            "ready" => "saved context available",
            "needs_read"
                if !value.unread.items().is_empty() || !value.required_reads.is_empty() =>
            {
                "saved context; unread messages below"
            }
            "needs_read" => "partial saved context; more available below",
            "integrity_blocked" => "some saved context could not be read",
            other => other,
        }
    } else {
        &value.resume_status
    };
    writeln!(
        out,
        "{} in {} — {}{}",
        value.principal.agent.name,
        value.principal.project.name,
        status,
        if value.principal.preview {
            " (owner preview; nothing acknowledged)"
        } else {
            ""
        }
    )?;
    if let Some(session) = &value.principal.session_id {
        writeln!(out, "Session: {session}")?;
    }
    writeln!(out, "\nWhat was I doing?")?;
    match &value.working_state {
        Read::Present { value } => {
            writeln!(out, "Working state (revision {}):", value.value.revision)?;
            writeln!(out, "{}", value.value.text)?;
            if let Some(command) = &value.command {
                writeln!(out, "Full working state: {command}")?;
            }
        }
        Read::Absent { .. } if value.principal.preview => {
            writeln!(out, "No separate progress notes were saved.")?;
            if !value.recent_turns.is_empty() {
                writeln!(
                    out,
                    "Saved conversation messages follow under What changed?."
                )?;
            } else if value
                .omissions
                .iter()
                .any(|item| item.section == "recent_turns")
            {
                writeln!(
                    out,
                    "Saved conversation messages are outside this context window; use the continuation below."
                )?;
            }
        }
        Read::Absent { .. } => writeln!(out, "No saved working state.")?,
        Read::Unknown { what } => writeln!(out, "Working state unknown: {what}")?,
        Read::Unreadable { source, reason, .. } => {
            writeln!(out, "Working state unreadable at {source}: {reason}")?
        }
    }
    writeln!(out, "\nWhat's waiting?")?;
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
    writeln!(out, "\nWhat changed?")?;
    if value.since.is_none() {
        writeln!(
            out,
            "Recent context; use --since with the returned cursor for later changes."
        )?;
    } else if value.since.as_ref() == Some(&value.cursor)
        && value.resume_status != "integrity_blocked"
    {
        writeln!(out, "Nothing changed since that cursor.")?;
    } else if value.recent_turns.is_empty()
        && !value
            .omissions
            .iter()
            .any(|item| item.section == "recent_turns")
    {
        writeln!(
            out,
            "No new captured turns since that cursor; pending work and omissions follow."
        )?;
    }
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
                .map(|count| format!("{count} {}", omitted.unit.as_deref().unwrap_or("item(s)")))
                .unwrap_or_else(|| "count unavailable".into()),
            omitted.reason,
            if omitted.command.is_empty() {
                "use the expanded resume command below"
            } else {
                &omitted.command
            }
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
    write!(out, "Continue: se")?;
    if let Some(home) = home {
        let home = home.display().to_string();
        #[cfg(windows)]
        let home = home.replace('\'', "''");
        #[cfg(not(windows))]
        let home = home.replace('\'', "'\"'\"'");
        write!(out, " --home '{home}'")?;
    }
    write!(
        out,
        " --project {} resume --since {}",
        value.principal.project.id, value.cursor
    )?;
    if value.principal.preview {
        write!(out, " --preview {}", value.principal.agent.id)?;
    }
    writeln!(out)
}
