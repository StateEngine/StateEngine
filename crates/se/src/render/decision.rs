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
                "State: {:?}; revision {}; governing: {}",
                row.state, row.revision, row.governing
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
                    "{:?} by {} ({}) at {} (event {})",
                    transition.action, actor.name, actor.id, transition.at, transition.event_id
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
