use se_core::ops::doctor::{CheckState, Diagnosis, RepairOutput};
use std::io::{self, Write};
pub fn diagnosis(value: &Diagnosis, out: &mut impl Write) -> io::Result<()> {
    for check in &value.checks {
        let state = match check.state {
            CheckState::Ok => "ok",
            CheckState::Failed => "failed",
            CheckState::Warning => "warning",
            CheckState::Unmeasured => "unmeasured",
            CheckState::Skipped => "skipped",
            CheckState::NotApplicable => "not applicable",
        };
        writeln!(
            out,
            "{state}: {} [{}]: {}",
            check.title,
            check.id,
            check
                .observed
                .as_deref()
                .or(check.reason.as_deref())
                .unwrap_or("no observation")
        )?;
        if let Some(fix) = &check.fix {
            writeln!(out, "  fix: {}", fix.text)?;
            if let Some(argv) = &fix.argv {
                writeln!(
                    out,
                    "  argv: {}",
                    serde_json::to_string(argv).map_err(io::Error::other)?
                )?;
            }
        }
    }
    Ok(())
}
pub fn repair(value: &RepairOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Applied {} check: {}. Re-read: {}.",
        value.applied.len(),
        value.check_id,
        if value.complete { "ok" } else { "incomplete" }
    )?;
    for effect in &value.applied {
        writeln!(
            out,
            "{}: {} ({})",
            effect.subject, effect.outcome, effect.detail
        )?;
    }
    for check in &value.remaining_checks {
        writeln!(
            out,
            "Remaining [{}]: {}",
            check.id,
            check
                .observed
                .as_deref()
                .or(check.reason.as_deref())
                .unwrap_or("unmeasured")
        )?;
    }
    Ok(())
}
