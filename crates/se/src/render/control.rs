//! Human output preserves achieved native effects and every named obligation.
use super::write;
use se_core::ops::{LaunchResult, RemoveResult, project_remove::RemovalWitness};
use std::io::{self, Write};

pub fn launch(value: &LaunchResult, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Agent {}: {} ({}, {})",
        value.agent.name,
        value.state,
        super::labels::provider(value.provider),
        value.surface
    )?;
    writeln!(
        out,
        "Process: PID {}, started {}",
        value.process.pid, value.process.started_at
    )?;
    writeln!(out, "Containment: {}", value.containment)?;
    if let Some(takeover) = &value.takeover {
        writeln!(
            out,
            "Previous session stopped: {} ({})",
            takeover.previous_session, takeover.scope
        )?;
        writeln!(out, "Jobs stopped: {}", takeover.jobs_stopped.len())?;
        for job in &takeover.jobs_stopped {
            writeln!(out, "  PID {}: {}", job.pid, job.command)?;
        }
        for job in &takeover.jobs_remaining {
            writeln!(
                out,
                "Job still live outside stopped scope: PID {}: {}",
                job.pid, job.command
            )?;
        }
        writeln!(out, "Stop witness: {}", takeover.witness)?;
    }
    if let Some(reason) = &value.containment_cause {
        writeln!(
            out,
            "Containment reason: {}",
            se_core::ops::containment_cause_description(reason)
        )?;
    }
    write::profile(&value.permission_profile, out)?;
    writeln!(out, "Conversation: {}", value.conversation_id)?;
    if let Some(command) = &value.resume.command {
        writeln!(out, "Resume: {command}")?;
    }
    if let Some(reason) = &value.resume.reason {
        writeln!(out, "Resume: {reason}")?;
    }
    if let Some(command) = &value.replies {
        writeln!(out, "Read replies: {}", command.command)?;
    } else {
        writeln!(
            out,
            "Read replies: {}",
            se_core::ops::AgentCommand::HOME_UNAVAILABLE
        )?;
    }
    writeln!(
        out,
        "Event: {}; request key: {}",
        value.event_id, value.idempotency_key
    )
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
            super::stop::agent(pending, out)?;
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
