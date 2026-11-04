#[path = "notification.rs"]
pub(super) mod notification;
use se_core::ops::outputs::*;
use se_types::{OmissionReason, Page, Read};
use std::io::{self, Write};

pub fn status(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
    if matches!(value.setup.state, SetupState::NotSetUp) {
        writeln!(out, "StateEngine {} — no project here yet.", value.version)?;
        writeln!(
            out,
            "  An agent (Claude Code or Codex) works in a project: a folder StateEngine tracks."
        )?;
        writeln!(
            out,
            "  Start: se init            (registers this folder; your files and Git history stay as they are)"
        )?;
        writeln!(
            out,
            "  Then:  se status          (inspect the saved project and agent)"
        )?;
        return Ok(());
    }
    writeln!(out, "StateEngine {}", value.version)?;
    writeln!(out, "State home: {}", value.setup.home)?;
    if let Some(reason) = &value.setup.reason {
        writeln!(out, "Setup: {reason}")?;
    }
    match &value.project {
        Read::Present { value } => writeln!(out, "Project: {} ({})", value.name, value.root)?,
        Read::Absent { .. } => writeln!(out, "No project selected.")?,
        Read::Unreadable { source, reason, .. } => {
            writeln!(out, "Project unreadable: {source}: {reason}")?
        }
        Read::Unknown { what } => writeln!(out, "Project unknown: {what}")?,
    }
    writeln!(out, "Runtime: {}", value.runtime.state)?;
    if let Some(reason) = &value.runtime.resources_unavailable {
        writeln!(out, "Host resources unavailable: {reason}")?;
    }
    if matches!(
        value.runtime.detachment.as_ref(),
        Some(HostDetachment::SessionOnly)
    ) {
        writeln!(
            out,
            "Host: runs as a session process and stops when this login session ends"
        )?;
    }
    if let Some(process) = &value.runtime.process {
        writeln!(
            out,
            "  PID {} (started {})",
            process.pid, process.started_at
        )?;
    }
    if let Some(agents) = &value.agents {
        for agent in agents.items() {
            writeln!(
                out,
                "  {}: {} — unread {}",
                agent.name,
                agent.session.state,
                count(agent.unread)
            )?;
            super::transcript::render(&agent.session.transcript, out)?;
            if let Some(reason) = &agent.session.containment_cause {
                writeln!(
                    out,
                    "    Containment reason: {}",
                    se_core::ops::containment_cause_description(reason)
                )?;
            }
            if let Some(reason) = &agent.resume.reason {
                writeln!(out, "    Resume: {reason}")?;
            }
        }
        omissions(agents, out)?;
    }
    if let Some(projects) = &value.projects {
        for project in projects.items() {
            writeln!(
                out,
                "  {}: {} — {} agents running, {} unread",
                project.name,
                project.root.as_deref().unwrap_or("root unreadable"),
                count(project.agents_running),
                count(project.owner_unread)
            )?;
            for error in &project.errors {
                writeln!(out, "    Unreadable: {}", error.message())?;
            }
        }
        omissions(projects, out)?;
    }
    if value.principal.is_some() {
        writeln!(
            out,
            "Your unread messages: {}",
            count(value.inbox.self_unread)
        )?;
    } else {
        writeln!(
            out,
            "Owner unread messages: {}",
            count(value.inbox.owner_unread)
        )?;
    }
    writeln!(out, "Pending decisions: {}", count(value.decisions.pending))?;
    writeln!(
        out,
        "Capture: {}; code index: {}",
        value.capture.state, value.atlas.state
    )?;
    for pending in &value.pending {
        writeln!(out, "Pending {}: {}", pending.what, pending.detail)?;
    }
    next_step(&value.next, out)
}

pub fn messages(value: &MessagePage, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Unread messages: {}", count(value.unread_total))?;
    for message in value.page.items() {
        writeln!(
            out,
            "{}  {} → {}  {}",
            message.id, message.from.name, message.to.name, message.sent_at
        )?;
        notification::render(&message.notification, out)?;
        if let Some(unreadable) = &message.unreadable {
            writeln!(out, "  Message unreadable: {}", unreadable.reason)?;
        } else {
            writeln!(out, "{}", message.body.text)?;
        }
        if !message.body.complete {
            if let Some(command) = &message.body.command {
                writeln!(out, "  Body preview; read the full message: {command}")?;
            } else {
                writeln!(out, "  Body preview; more text is available with --full.")?;
            }
        }
    }
    omissions(&value.page, out)
}

pub fn working_state(value: &WorkingStateOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Working state for {}", value.agent.name)?;
    match &value.value {
        Read::Present { value } => {
            writeln!(
                out,
                "Revision {} (saved {})",
                value.revision, value.recorded_at
            )?;
            writeln!(out, "{}", value.text)
        }
        Read::Absent { .. } => writeln!(out, "No saved working state."),
        Read::Unreadable { source, reason, .. } => writeln!(out, "Unreadable: {source}: {reason}"),
        Read::Unknown { what } => writeln!(out, "Unknown: {what}"),
    }
}

pub fn schema(value: &SchemaCatalogue, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "StateEngine API {} — {} registered operations",
        value.api,
        value.ops.len()
    )?;
    for operation in &value.ops {
        writeln!(out, "  {}", operation.name)?;
    }
    writeln!(
        out,
        "Use --json for the complete input, output and error schemas."
    )
}

pub fn next_step(value: &NextStep, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{}: {}", value.text, value.command)
}

fn count(value: Option<u64>) -> String {
    value
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn omissions<T>(page: &Page<T>, out: &mut impl Write) -> io::Result<()> {
    if !page.window().complete() {
        let omitted = page.window().omitted();
        let reason = match omitted.reason {
            Some(OmissionReason::Limit) => "page limit",
            Some(OmissionReason::Budget) => "byte budget",
            Some(OmissionReason::Unreadable) => "unreadable source",
            Some(OmissionReason::SourceIncomplete) => "incomplete source",
            None => "reason unavailable",
        };
        writeln!(out, "Omitted: {} ({reason})", count(omitted.count))?;
    }
    if let Some(cursor) = page.next() {
        writeln!(out, "Continue with --cursor {cursor}")?;
    }
    Ok(())
}
