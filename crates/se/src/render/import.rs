use se_core::ops::ImportReceipt;
use std::io::{self, Write};
pub(super) fn output(value: &ImportReceipt, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "History import {}. Original files retained.",
        if value.complete {
            "complete"
        } else {
            "incomplete"
        }
    )?;
    for family in &value.families {
        match family.state.as_str() {
            "present" => writeln!(
                out,
                "{}: {} source rows, {} imported, {} duplicates, {} unreadable, {} excluded by policy, {} deferred ({})",
                family.family,
                family.read,
                family.imported,
                family.duplicate,
                family.unreadable,
                family.dropped_by_policy,
                family.deferred,
                family.source
            )?,
            state => writeln!(out, "{}: {state} ({})", family.family, family.source)?,
        }
        if let Some(reason) = &family.reason {
            writeln!(out, "  {reason}")?;
        }
    }
    for reference in &value.resume {
        writeln!(
            out,
            "{} historical conversation {} for {}: {} (launch starts fresh)",
            reference.provider, reference.session, reference.agent, reference.state
        )?;
    }
    if !value.complete {
        writeln!(
            out,
            "Restore access or resolve the named source issue, then rerun the same source. Committed progress is retained."
        )?;
    }
    Ok(())
}
