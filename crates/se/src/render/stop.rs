//! Plain stop facts; the original structured receipt remains available as JSON.
use se_core::ops::{
    StopResult,
    agent_stop::{AgentStopResult, OwnershipRelease, StopCapture, StopResume, StopWitness},
};
use std::io::{self, Write};

pub(super) fn output(value: &StopResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Stop {}.",
        if value.complete {
            "complete"
        } else {
            "incomplete"
        }
    )?;
    if let Some(stops) = &value.stops {
        for row in stops {
            agent(row, out)?;
        }
    }
    if let Some(target) = &value.target {
        writeln!(
            out,
            "Agent {} in {}",
            target.agent.name, target.project.name
        )?;
        if let Some(process) = &target.process {
            writeln!(
                out,
                "Original process: PID {}, started {}",
                process.pid, process.started_at
            )?;
        }
    }
    if let Some(witness) = &value.witness {
        exit(witness, out)?;
    }
    population(
        value.population.as_deref(),
        value.enumeration.as_deref(),
        value.population_reason.as_deref(),
        out,
    )?;
    if let Some(release) = &value.ownership_release {
        released(release, out)?;
    }
    if let Some(remaining) = &value.remaining {
        processes(remaining, out)?;
    }
    if let Some(capture) = &value.capture {
        captured(capture, out)?;
    }
    if let Some(resume) = &value.resume {
        resumable(resume, out)?;
    }
    if !value.complete {
        writeln!(
            out,
            "Stop remains incomplete; inspect the named failure and any possible remaining processes before retrying."
        )?;
    }
    writeln!(out, "Use --json for full stop details.")
}
fn exit(value: &StopWitness, out: &mut impl Write) -> io::Result<()> {
    match value.state.as_str() {
        "witnessed" => writeln!(out, "Exit check complete.")?,
        "unwitnessed" => writeln!(out, "Process exit was not observed.")?,
        "unknown" => writeln!(out, "Process exit is unconfirmed.")?,
        other => writeln!(out, "Process exit status: {other}.")?,
    }
    if let Some(method) = &value.method {
        let explanation = match method.as_str() {
            "pidfd-exit+cgroup-removed" => {
                Some("The original Linux process exited and its managed process group was removed.")
            }
            "job-empty" => {
                Some("The Windows job is empty; the processes it contained have exited.")
            }
            "start-identity-exit+pgid-empty" => Some(
                "The original process exited and its recorded process group is empty. Processes that left that group may remain.",
            ),
            "not-applicable" => Some("No managed process required an exit check."),
            _ => None,
        };
        if value.state == "witnessed"
            && let Some(explanation) = explanation
        {
            writeln!(out, "{explanation}")?;
        } else {
            writeln!(out, "Exit check: {method}")?;
        }
    }
    if let Some(at) = &value.observed_at {
        writeln!(out, "Checked: {at}")?;
    }
    if let Some(detail) = &value.detail {
        // Successful native stops carry Debug-formatted evidence in this legacy
        // detail field. The method and population above carry its plain facts;
        // preserve any appended fallback failure without printing the struct.
        if detail.starts_with("scope=") {
            if let Some((_, failure)) =
                detail.split_once("; graceful stop failed before the native fallback: ")
            {
                writeln!(out, "Graceful stop failed before fallback: {failure}")?;
            }
        } else {
            writeln!(out, "{detail}")?;
        }
    }
    Ok(())
}
fn population(
    value: Option<&str>,
    enumeration: Option<&str>,
    reason: Option<&str>,
    out: &mut impl Write,
) -> io::Result<()> {
    if let Some(value) = value {
        writeln!(
            out,
            "{}",
            match value {
                "empty" => "No processes remain in the checked scope.",
                "populated" => "Processes remain in the checked scope.",
                _ => "Remaining processes could not be determined.",
            }
        )?;
    }
    if let Some(enumeration) = enumeration {
        match enumeration {
            "complete" => writeln!(out, "The process list is complete.")?,
            "not-applicable" => (),
            "best-effort" => writeln!(
                out,
                "The process list is best effort and may omit processes."
            )?,
            _ => writeln!(out, "The process list is incomplete or unavailable.")?,
        }
    }
    if let Some(reason) = reason {
        writeln!(out, "{reason}")?;
    }
    Ok(())
}
pub(super) fn agent(value: &AgentStopResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Agent {} in {}: {}",
        value.target.agent.name, value.target.project.name, value.result
    )?;
    if let Some(process) = &value.target.process {
        writeln!(
            out,
            "Original process: PID {}, started {}",
            process.pid, process.started_at
        )?;
    }
    exit(&value.witness, out)?;
    population(
        Some(&value.population),
        Some(&value.enumeration),
        value.population_reason.as_deref(),
        out,
    )?;
    if let Some(release) = &value.ownership_release {
        released(release, out)?;
    }
    processes(&value.remaining, out)?;
    captured(&value.capture, out)?;
    resumable(&value.resume, out)
}
fn captured(value: &StopCapture, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Saved conversation: {}.",
        if value.flushed {
            "up to date"
        } else {
            "may be incomplete"
        }
    )?;
    Ok(())
}
fn resumable(value: &StopResume, out: &mut impl Write) -> io::Result<()> {
    let label = match value.state.as_str() {
        "ready" => "Resume",
        "new-required" => "Start a new conversation",
        _ => "Resume unavailable",
    };
    if !value.command.is_empty() {
        writeln!(out, "{label}: {}", value.command)?;
    }
    if let Some(reason) = &value.reason {
        writeln!(out, "{reason}")?;
    }
    Ok(())
}
fn released(value: &OwnershipRelease, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Ownership released without an exit check; processes may remain."
    )?;
    writeln!(out, "Release: {} at {}", value.lifecycle, value.released_at)?;
    processes(&value.remaining, out)
}
fn processes(values: &[se_core::ops::ProcessView], out: &mut impl Write) -> io::Result<()> {
    for process in values {
        writeln!(
            out,
            "Possible remaining process: PID {}, started {}, {}",
            process.pid, process.started_at, process.exe
        )?;
    }
    Ok(())
}
