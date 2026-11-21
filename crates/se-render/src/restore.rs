use se_core::ops::RestoreResult;
use std::io::{self, Write};
pub(super) fn output(value: &RestoreResult, out: &mut impl Write) -> io::Result<()> {
    match value.outcome.as_str() {
        "planned" => writeln!(out, "Restore plan: nothing has been changed yet.")?,
        "restored" => writeln!(out, "Restored history from an automatic backup.")?,
        _ => writeln!(out, "Restore refused.")?,
    }
    if let Some(backup) = &value.backup {
        writeln!(
            out,
            "Backup: {} (through event {}, {} MB)",
            backup.path,
            backup.through_sequence,
            backup.bytes.div_ceil(1_000_000)
        )?;
    }
    let tense = if value.outcome == "restored" {
        "were"
    } else {
        "will be"
    };
    match value.events_lost {
        Some(0) => writeln!(out, "No events after the backup {tense} lost.")?,
        Some(n) => writeln!(out, "{n} events recorded after the backup {tense} lost.")?,
        None if value.backup.is_some() => writeln!(
            out,
            "The live store cannot say how many events came after the backup."
        )?,
        None => (),
    }
    if let Some(preserved) = &value.preserved {
        writeln!(out, "The replaced store was kept at {preserved}")?;
    } else if value.outcome == "planned" {
        writeln!(
            out,
            "The current store will be kept beside it, not deleted."
        )?;
    }
    if !value.blocking_agents.is_empty() {
        writeln!(out, "Agents with live sessions:")?;
        for agent in &value.blocking_agents {
            writeln!(out, "  {agent}")?;
        }
    }
    if let Some(reason) = &value.reason {
        writeln!(out, "{reason}")?;
    }
    if let Some(next) = &value.next {
        writeln!(out, "{}:", next.text)?;
        writeln!(out, "  {}", next.argv.join(" "))?;
    }
    Ok(())
}
