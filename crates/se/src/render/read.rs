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
            "  An agent ({} or {}) works in a project: a folder StateEngine tracks.",
            super::labels::provider(se_types::Provider::Claude),
            super::labels::provider(se_types::Provider::Codex)
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
        Read::Present { value } => {
            writeln!(out, "Project: {} ({})", value.name, value.root)?;
            if let Some(git) = &value.git {
                repo_line(git, out)?;
            }
        }
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
                "  Agent {}: {} — unread messages {}",
                agent.name,
                if agent.session.state == "never-launched" {
                    "not started yet"
                } else {
                    &agent.session.state
                },
                count(agent.unread)
            )?;
            if agent.session.state != "never-launched" {
                super::transcript::render(&agent.session.transcript, out)?;
            }
            if let Some(reason) = &agent.session.containment_cause {
                writeln!(
                    out,
                    "    Containment reason: {}",
                    se_core::ops::containment_cause_description(reason)
                )?;
            }
            resume_advice(&agent.resume, "    ", out)?;
        }
        omissions(agents, out)?;
    }
    if let Some(projects) = &value.projects {
        for project in projects.items() {
            writeln!(
                out,
                "  {}: {} — {} agents running, {} unread for owner",
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
    writeln!(
        out,
        "Proposed decisions: {}",
        value
            .decisions
            .pending
            .map_or("not counted".into(), |value| value.to_string())
    )?;
    writeln!(
        out,
        "Conversation recording: {}; code index: {}; history: {}",
        if value.capture.state == "unknown" {
            "not checked"
        } else {
            &value.capture.state
        },
        if value.atlas.state == "not-built" {
            "not built"
        } else {
            &value.atlas.state
        },
        value.atlas.history
    )?;
    if let Some(reason) = &value.atlas.reason {
        writeln!(out, "  Atlas: {reason}")?;
    }
    if let Some(summary) = &value.atlas.summary {
        let c = &summary.coverage;
        if value.atlas.state == "preparing" && summary.epoch.is_none() {
            writeln!(
                out,
                "  Atlas file counts: awaiting the first published index."
            )?;
        } else {
            writeln!(
                out,
                "  Atlas files: {} indexed / {} discovered; {} partial, {} deferred, {} failed, {} stale",
                c.indexed_files,
                c.discovered_files,
                c.partial_files,
                c.deferred_files,
                c.failed_files,
                c.stale_files
            )?;
            if !c.discovery_complete {
                writeln!(out, "  Atlas file discovery is still preparing.")?;
            }
            if c.unwatched_directories > 0 || !c.watch_discovery_complete {
                writeln!(
                    out,
                    "  Atlas watching is partial: {} directories unwatched; discovery complete: {}",
                    c.unwatched_directories, c.watch_discovery_complete
                )?;
            }
        }
    }
    for pending in &value.pending {
        if pending.what == "runtime observation"
            && pending
                .detail
                .starts_with("No runtime connection file was found.")
        {
            writeln!(
                out,
                "Background runtime: no connection file found. Running agents have not been checked; use se doctor for this home."
            )?;
        } else {
            writeln!(out, "Pending {}: {}", pending.what, pending.detail)?;
        }
    }
    if let Read::Present { value: project } = &value.project
        && let Some(agent) = value.agents.as_ref().and_then(|page| page.items().first())
        && agent.session.state == "never-launched"
        && value.next.argv.iter().any(|word| word == "launch")
    {
        first_launch(
            &value.setup.home,
            &project.root,
            &agent.name,
            &value.next,
            out,
        )
    } else {
        next_step(&value.next, out)
    }
}

pub(super) fn resume_advice(
    value: &se_core::ops::ResumeCommand,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    let reason = value.reason.as_deref().unwrap_or(if value.ready {
        "Ready to reopen the saved conversation."
    } else {
        "Resume readiness has not been established."
    });
    writeln!(out, "{indent}Resume: {reason}")?;
    if let Some(command) = &value.command {
        writeln!(out, "{indent}Next: {command}")
    } else {
        let next = match value.mode.as_str() {
            "running" => {
                "Continue in the current agent, or stop it before reopening its conversation."
            }
            "reconcile" => "Complete the recovery step above before reopening this conversation.",
            _ => "Resolve the issue above, then check this agent again before resuming.",
        };
        writeln!(out, "{indent}Next: {next}")
    }
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

pub(super) fn first_launch(
    home: &str,
    root: &str,
    agent: &str,
    next: &NextStep,
    out: &mut impl Write,
) -> io::Result<()> {
    let command = se_core::ops::AgentCommand::from_argv(vec![
        "se".into(),
        "--home".into(),
        home.into(),
        "launch".into(),
        agent.into(),
        "--detach".into(),
    ]);
    let Some(command) = command else {
        return next_step(next, out);
    };
    let mut text = next.text.clone();
    let command = if let Some(instruction) = text.strip_prefix("In cmd.exe, ") {
        match command.for_cmd() {
            Some(command) => command,
            None => {
                // The friendly name can require a different shell than the
                // original ID-based command; change its instruction too.
                text = format!("Open PowerShell, then {instruction}");
                command
            }
        }
    } else {
        command
    };
    writeln!(out, "From the project folder {root}:")?;
    writeln!(out, "{text}: {}", command.command)
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

pub(super) fn repo_line(git: &GitView, out: &mut impl Write) -> io::Result<()> {
    let Some(commits) = git.commits else {
        return Ok(());
    };
    let mut line = format!(
        "Existing repo: {commits} commit{}",
        if commits == 1 { "" } else { "s" }
    );
    if let Some(branch) = &git.branch {
        line.push_str(&format!(" on {branch}"));
    }
    if git.uncommitted == Some(true) {
        line.push_str("; uncommitted changes left untouched");
    }
    writeln!(out, "{line}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_launch_names_powershell_when_a_friendly_name_cannot_use_cmd() -> io::Result<()> {
        for agent in ["Build!", "Build%TEMP%", "Build\"quoted"] {
            let next = NextStep {
                text: "In cmd.exe, launch your first agent".into(),
                command: "se --home C:\\state launch ag_saved --detach".into(),
                argv: vec![],
            };
            let mut output = Vec::new();
            first_launch("C:\\state", "C:\\repo", agent, &next, &mut output)?;
            let output = String::from_utf8(output).map_err(io::Error::other)?;
            assert!(output.contains("Open PowerShell, then launch your first agent:"));
            assert!(!output.contains("In cmd.exe,"));
            assert!(output.contains(agent));
        }
        Ok(())
    }

    #[test]
    fn first_launch_keeps_cmd_when_every_friendly_argument_is_representable() -> io::Result<()> {
        let next = NextStep {
            text: "In cmd.exe, launch your first agent".into(),
            command: String::new(),
            argv: vec![],
        };
        let mut output = Vec::new();
        first_launch(
            "C:\\state home",
            "C:\\repo",
            "Build agent",
            &next,
            &mut output,
        )?;
        let output = String::from_utf8(output).map_err(io::Error::other)?;
        assert!(output.contains("In cmd.exe, launch your first agent: se --home \"C:\\state home\" launch \"Build agent\" --detach"));
        Ok(())
    }
}
