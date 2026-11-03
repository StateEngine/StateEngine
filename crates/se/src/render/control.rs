//! Human output preserves achieved native effects and every named obligation.
use super::write;
use se_core::ops::{
    LaunchResult, RemoveResult, StopResult,
    agent_stop::{AgentStopResult, OwnershipRelease, StopCapture, StopResume, StopWitness},
    project_remove::RemovalWitness,
};
use std::io::{self, Write};

pub fn launch(value: &LaunchResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Agent {}: {} ({}, {})",
        value.agent.name,
        value.state,
        write::provider(value.provider),
        value.surface
    )?;
    writeln!(
        out,
        "Process: PID {}, started {}",
        value.process.pid, value.process.started_at
    )?;
    writeln!(out, "Containment: {}", value.containment)?;
    if let Some(reason) = &value.containment_cause {
        writeln!(out, "Containment reason: {}", containment_cause(reason))?;
    }
    write::profile(&value.permission_profile, out)?;
    writeln!(out, "Conversation: {}", value.conversation_id)?;
    if let Some(command) = &value.resume.command {
        writeln!(out, "Resume: {command}")?;
    }
    if let Some(reason) = &value.resume.reason {
        writeln!(out, "Resume: {reason}")?;
    }
    writeln!(out, "Stop: se stop {}", value.agent.name)?;
    writeln!(
        out,
        "Event: {}; request key: {}",
        value.event_id, value.idempotency_key
    )
}
pub fn stop(value: &StopResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Stop {}: {} (complete: {})",
        value.scope, value.result, value.complete
    )?;
    if let Some(stops) = &value.stops {
        for row in stops {
            stopped(row, out)?;
        }
    }
    if let Some(target) = &value.target {
        writeln!(
            out,
            "Agent {} in {}",
            target.agent.name, target.project.name
        )?;
    }
    if let Some(witness) = &value.witness {
        stop_witness(witness, out)?;
    }
    if let Some(population) = &value.population {
        writeln!(out, "Population: {population}")?;
    }
    if let Some(reason) = &value.population_reason {
        writeln!(out, "Population reason: {reason}")?;
    }
    if let Some(enumeration) = &value.enumeration {
        writeln!(out, "Enumeration: {enumeration}")?;
    }
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
            "Stop is incomplete; the named obligations and possible remaining processes still require readback."
        )?;
    }
    writeln!(out, "Request key: {}", value.idempotency_key)
}
fn stop_witness(value: &StopWitness, out: &mut impl Write) -> io::Result<()> {
    write!(out, "Witness: {}", value.state)?;
    if let Some(method) = &value.method {
        write!(out, " via {method}")?;
    }
    if let Some(at) = &value.observed_at {
        write!(out, " at {at}")?;
    }
    if let Some(detail) = &value.detail {
        write!(out, ": {detail}")?;
    }
    writeln!(out)
}
fn stopped(value: &AgentStopResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Agent {} in {}: {}",
        value.target.agent.name, value.target.project.name, value.result
    )?;
    stop_witness(&value.witness, out)?;
    writeln!(
        out,
        "Population: {}; enumeration: {}",
        value.population, value.enumeration
    )?;
    if let Some(reason) = &value.population_reason {
        writeln!(out, "Population reason: {reason}")?;
    }
    if let Some(release) = &value.ownership_release {
        released(release, out)?;
    }
    processes(&value.remaining, out)?;
    captured(&value.capture, out)?;
    resumable(&value.resume, out)
}
fn captured(value: &StopCapture, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Capture flushed: {}", value.flushed)?;
    if let Some(event) = &value.last_event_id {
        writeln!(out, "Last captured event: {event}")?;
    }
    Ok(())
}
fn resumable(value: &StopResume, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Resume {}: {}", value.state, value.command)?;
    if let Some(reason) = &value.reason {
        writeln!(out, "Resume reason: {reason}")?;
    }
    if let Some(conversation) = &value.conversation_id {
        writeln!(out, "Conversation: {conversation}")?;
    }
    Ok(())
}
fn released(value: &OwnershipRelease, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Ownership released without an exit witness; processes may remain."
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
fn removal_witness(value: &RemovalWitness, out: &mut impl Write) -> io::Result<()> {
    write!(out, "  {}", value.state)?;
    if let Some(method) = &value.method {
        write!(out, " via {method}")?;
    }
    if let Some(detail) = &value.detail {
        write!(out, ": {detail}")?;
    }
    writeln!(out)
}
pub fn remove(value: &RemoveResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Remove {}: {}", value.scope, value.outcome)?;
    for project in &value.projects {
        writeln!(out, "Project {}: {}", project.project.name, project.outcome)?;
        for agent in &project.agents_stopped {
            writeln!(
                out,
                "Agent {} (was {})",
                agent.agent.name, agent.prior_state
            )?;
            removal_witness(&agent.witness, out)?;
        }
        for process in &project.processes_stopped {
            writeln!(out, "Process PID {}", process.process.pid)?;
            removal_witness(&process.witness, out)?;
        }
        for pending in &project.processes_may_remain {
            stopped(pending, out)?;
        }
        for credential in &project.credentials_revoked {
            writeln!(
                out,
                "Credential {} ({}): {}",
                credential.credential_id, credential.kind, credential.state
            )?;
        }
        for integration in &project.integrations {
            writeln!(
                out,
                "Integration {} ({}): {}",
                integration.path, integration.entry, integration.action
            )?;
            removal_witness(&integration.witness, out)?;
        }
        for item in &project.removed {
            writeln!(
                out,
                "Removed: {}{}",
                item.what,
                item.path
                    .as_ref()
                    .map(|path| format!(" ({path})"))
                    .unwrap_or_default()
            )?;
        }
        for item in &project.kept {
            writeln!(
                out,
                "Kept: {}{}; {}",
                item.what,
                item.path
                    .as_ref()
                    .map(|path| format!(" ({path})"))
                    .unwrap_or_default(),
                item.note
            )?;
        }
        for pending in &project.remaining {
            writeln!(out, "Remaining: {}: {}", pending.what, pending.reason)?;
            if let Some(command) = &pending.command {
                writeln!(out, "Next: {command}")?;
            }
        }
    }
    writeln!(out, "Runtime: {}", value.runtime.action)?;
    removal_witness(&value.runtime.witness, out)?;
    writeln!(
        out,
        "Machine credential: {}",
        value.machine_credential.state
    )?;
    removal_witness(&value.machine_credential.witness, out)?;
    writeln!(out, "{}: {}", value.next.text, value.next.command)?;
    writeln!(out, "Request key: {}", value.idempotency_key)
}

// Both launch and status show the same explanation; JSON retains the stable code.
pub(super) fn containment_cause(code: &str) -> &str {
    match code {
        "no-user-manager" => "No user service manager is available for containment.",
        "no-delegation" => "The OS has not delegated a containment scope to this user.",
        "cgroup-v2-absent" => "The OS does not provide cgroup v2 containment.",
        "cgroup-unreadable" => "The OS containment configuration cannot be read.",
        "scope-create-failed" => "The OS could not create the containment scope.",
        other => other,
    }
}
