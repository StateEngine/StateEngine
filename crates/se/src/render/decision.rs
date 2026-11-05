use se_core::ops::DecisionOutput;
use se_types::Read;
use std::io::{self, Write};

pub fn output(value: &DecisionOutput, out: &mut impl Write) -> io::Result<()> {
    match &value.decision {
        Read::Present { value } => {
            let row = &value.row;
            writeln!(out, "Decision {} ({})", row.key, row.id)?;
            writeln!(
                out,
                "State: {}; revision {}; applies to this project: {}",
                state(row.state),
                row.revision,
                if row.governing { "yes" } else { "no" }
            )?;
            writeln!(out, "{}", row.statement.text)?;
            if let Some(rationale) = &row.rationale {
                writeln!(out, "Rationale: {rationale}")?;
            }
            if let Some(reason) = &row.reason {
                writeln!(out, "Reason: {reason}")?;
            }
            if let Some(id) = &row.supersedes {
                writeln!(out, "Supersedes: {id}")?;
            }
            if let Some(id) = &row.superseded_by {
                writeln!(out, "Superseded by: {id}")?;
            }
            for transition in &value.transitions {
                let actor = &transition.by;
                writeln!(
                    out,
                    "{} by {} ({}) at {} (event {})",
                    action(transition.action),
                    actor.name,
                    actor.id,
                    transition.at,
                    transition.event_id
                )?;
                if let Some(reason) = &transition.reason {
                    writeln!(out, "Reason: {reason}")?;
                }
            }
        }
        Read::Absent { checked } => writeln!(out, "Decision absent: {checked}")?,
        Read::Unreadable { source, reason, .. } => {
            writeln!(out, "Decision unreadable at {source}: {reason}")?
        }
        Read::Unknown { what } => writeln!(out, "Decision unknown: {what}")?,
    }
    Ok(())
}

pub fn page(value: &se_core::ops::DecisionPage, out: &mut impl Write) -> io::Result<()> {
    for item in value.page.items() {
        match item {
            se_core::ops::DecisionPageRow::Present { row, .. } => {
                writeln!(
                    out,
                    "{} ({})  {}  {}  {}",
                    row.key,
                    row.id,
                    state(row.state),
                    row.proposed_by.name,
                    row.statement.text
                )?;
                if let Some(command) = &row.statement.command {
                    writeln!(out, "Full statement: {command}")?;
                }
            }
            se_core::ops::DecisionPageRow::Unreadable { unreadable, .. } => {
                writeln!(out, "Decision unreadable: {}", unreadable.reason)?
            }
        }
    }
    if value.page.items().is_empty() {
        writeln!(out, "No matching decisions.")?;
    }
    if !value.page.window().complete() {
        writeln!(out, "This page is incomplete.")?;
    }
    if let Some(cursor) = value.page.next() {
        write!(
            out,
            "Next page: se decision list --project {}",
            value.project.id
        )?;
        if let Some(id) = &value.filter.id {
            write!(out, " --id {id}")?;
        }
        if value.filter.pending {
            write!(out, " --pending")?;
        }
        if value.filter.history {
            write!(out, " --history")?;
        }
        writeln!(out, " --cursor {}", cursor.as_str())?;
    }
    Ok(())
}

fn state(value: se_types::DecisionState) -> &'static str {
    use se_types::DecisionState::*;
    match value {
        Pending => "awaiting owner decision",
        Ratified => "approved",
        Rejected => "rejected",
        Retracted => "withdrawn",
        Superseded => "replaced",
    }
}

fn action(value: se_types::DecisionAction) -> &'static str {
    use se_types::DecisionAction::*;
    match value {
        Propose => "Proposed",
        Ratify => "Approved",
        Reject => "Rejected",
        Retract => "Withdrawn",
        Supersede => "Replaced",
    }
}
