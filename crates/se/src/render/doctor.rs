use se_core::ops::doctor::{CheckState, Diagnosis, RepairOutput, RepairPlan};
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
                match se_core::ops::AgentCommand::from_argv(argv.clone()) {
                    Some(command) => writeln!(out, "  Run: {}", command.command)?,
                    None => writeln!(
                        out,
                        "  No single-line shell command can represent this repair; inspect --json for its exact arguments."
                    )?,
                }
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
        if matches!(value.plan, RepairPlan::TightenPermissions(_)) {
            writeln!(out, "{}: {}.", effect.subject, effect.outcome)?;
        } else {
            writeln!(
                out,
                "{}: {} ({})",
                effect.subject, effect.outcome, effect.detail
            )?;
        }
    }
    for readback in &value.readbacks {
        writeln!(
            out,
            "Checked {}: {}. {}",
            readback.subject, readback.outcome, readback.detail
        )?;
    }
    if matches!(value.plan, RepairPlan::TightenPermissions(_)) {
        writeln!(out, "Use --json for full native permission details.")?;
    }
    for skipped in &value.skipped {
        writeln!(out, "{}: {}.", skipped.subject, skipped.outcome)?;
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
