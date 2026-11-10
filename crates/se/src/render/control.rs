//! Human output preserves achieved native effects and every named obligation.
use super::write;
use se_core::ops::{
    LaunchPendingState, LaunchReply, LaunchResult, RemoveResult, agent_launch::TakeoverReport,
    project_remove::RemovalWitness,
};
use std::io::{self, Write};

pub fn launch(value: &LaunchReply, out: &mut impl Write) -> io::Result<()> {
    let value = match value {
        LaunchReply::Running(value) => return running(value, out),
        LaunchReply::Pending(value) => value,
    };
    let state = match value.state {
        LaunchPendingState::Starting => "starting",
        LaunchPendingState::SetupNeeded => "setup needed",
    };
    writeln!(
        out,
        "Agent {}: {state} ({}, window)",
        value.agent.name,
        super::labels::provider(value.provider)
    )?;
    writeln!(
        out,
        "The original launch is still retained; it has not activated yet."
    )?;
    if matches!(value.state, LaunchPendingState::SetupNeeded) {
        writeln!(
            out,
            "Complete the welcome or workspace trust prompt in the existing window."
        )?;
    }
    if let Some(takeover) = &value.takeover {
        stopped_previous(takeover, out)?;
    }
    if let Some(command) = &value.retry_command {
        writeln!(out, "Check launch: {}", command.command)?;
    } else {
        writeln!(
            out,
            "Repeat the original launch arguments with --key {} to check this same request.",
            value.idempotency_key
        )?;
    }
    writeln!(
        out,
        "Lifecycle: {}; request key: {}",
        value.lifecycle_id, value.idempotency_key
    )
}

fn running(value: &LaunchResult, out: &mut impl Write) -> io::Result<()> {
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
        stopped_previous(takeover, out)?;
    }
    if let Some(reason) = &value.containment_cause {
        writeln!(
            out,
            "Containment reason: {}",
            se_core::ops::containment_cause_description(reason)
        )?;
    }
    write::profile(&value.permission_profile, out)?;
    if let Some(notice) = &value.harness_policy_notice {
        writeln!(out, "{notice}")?;
    }
    write!(
        out,
        "Conversation: {} ({}",
        value.conversation_id,
        if value.resumed { "resumed" } else { "new" }
    )?;
    if value.resumed {
        match &value.saved_conversation_age {
            se_types::Read::Present { value } => match &value.age_seconds {
                se_types::Read::Present { value } => {
                    write!(out, "; saved session {} old at launch", age(*value))?
                }
                other => write!(
                    out,
                    "; saved session age unavailable: {}",
                    read_reason(other)
                )?,
            },
            other => write!(
                out,
                "; saved session age unavailable: {}",
                read_reason(other)
            )?,
        }
    }
    writeln!(out, ")")?;
    if let se_types::Read::Present { value } = &value.saved_conversation_age {
        writeln!(out, "Saved session started: {}", value.session_started_at)?;
    }
    if let Some(binding) = &value.secode_binding {
        super::read::secode::launch(binding, out)?;
    }
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
fn stopped_previous(takeover: &TakeoverReport, out: &mut impl Write) -> io::Result<()> {
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

fn age(seconds: u64) -> String {
    let (count, unit) = if seconds >= 86_400 {
        (seconds / 86_400, "day")
    } else if seconds >= 3_600 {
        (seconds / 3_600, "hour")
    } else if seconds >= 60 {
        (seconds / 60, "minute")
    } else {
        (seconds, "second")
    };
    format!("{count} {unit}{}", if count == 1 { "" } else { "s" })
}
fn read_reason<T>(read: &se_types::Read<T>) -> &str {
    match read {
        se_types::Read::Absent { checked } => checked,
        se_types::Read::Unknown { what } => what,
        se_types::Read::Unreadable { reason, .. } => reason,
        se_types::Read::Present { .. } => "not reported",
    }
}
