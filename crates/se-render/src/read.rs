#[path = "notification.rs"]
pub(super) mod notification;
#[path = "provider.rs"]
pub(super) mod provider;
#[path = "secode.rs"]
pub(super) mod secode;
use se_core::ops::outputs::*;
use se_types::{OmissionReason, Page, Read};
use std::io::{self, Write};

pub fn status(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
    if matches!(value.setup.state, SetupState::NotSetUp) {
        return not_set_up(value, out);
    }
    let healthy_stopped = healthy_stopped_runtime(value);
    header_lines(value, out)?;
    project_lines(value, out)?;
    runtime_lines(value, out)?;
    agents_section(value, out)?;
    projects_section(value, out)?;
    unread_lines(value, out)?;
    recording_lines(value, healthy_stopped, out)?;
    atlas_lines(value, out)?;
    pending_lines(value, healthy_stopped, out)?;
    next_lines(value, out)
}
fn not_set_up(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
    )
}
fn healthy_stopped_runtime(value: &StatusOutput) -> bool {
    value.runtime.state == "stopped"
        && value.agents.as_ref().is_some_and(|agents| {
            agents.window().complete()
                && agents.items().iter().all(|agent| {
                    matches!(agent.session.state.as_str(), "stopped" | "never-launched")
                })
        })
}
fn header_lines(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "StateEngine {}", value.version)?;
    writeln!(out, "State home: {}", value.setup.home)?;
    if let Some(reason) = &value.setup.reason {
        writeln!(out, "Setup: {reason}")?;
    }
    Ok(())
}
fn project_lines(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
    Ok(())
}
fn runtime_lines(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
            "Host: runs as a session process and may stop when this login session ends"
        )?;
        if let Some(reason) = &value.runtime.detachment_notice {
            writeln!(out, "  Background lifetime: {reason}")?;
        }
    } else if matches!(
        value.runtime.detachment,
        Some(HostDetachment::UserManagerUnit)
    ) {
        writeln!(
            out,
            "Host: runs in its own user-manager scope and survives login-session cleanup"
        )?;
    }
    if let Some(process) = &value.runtime.process {
        writeln!(
            out,
            "  PID {} (started {})",
            process.pid, process.started_at
        )?;
    }
    Ok(())
}
fn agents_section(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
    if let Some(agents) = &value.agents {
        for agent in agents.items() {
            let state = match &agent.state {
                Some(state) if agent.session.state != "never-launched" => crew_state(state),
                _ if agent.session.state == "never-launched" => "not started yet".into(),
                _ => agent.session.state.clone(),
            };
            writeln!(
                out,
                "  Agent {}: {state} — unread messages {}",
                agent.name,
                count(agent.unread)
            )?;
            if let Some(question) = agent.state.as_ref().and_then(|s| s.waiting_on.as_ref()) {
                writeln!(
                    out,
                    "    Waiting on {} to answer {} (asked {})",
                    question.to, question.message_id, question.asked_at
                )?;
            }
            if let Some(se_types::Read::Present { value: note }) = &agent.working_note
                && !note.text.is_empty()
            {
                let more = if note.truncated { " …" } else { "" };
                writeln!(out, "    Note: {}{more}", note.text)?;
            }
            if let Some(harness) = &agent.harness {
                writeln!(out, "    Harness: {harness}")?;
            }
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
            if let Some(notice) = &agent.harness_policy_notice {
                writeln!(out, "    {notice}")?;
            }
            if let Some(activity) = &agent.provider_activity {
                provider::activity(activity, "    ", out)?;
            }
            if let Some(login) = &agent.codex_login {
                provider::codex_login(login, "    ", out)?;
            }
            if let Some(runtime) = &agent.acp_runtime {
                super::acp::runtime(runtime, "    ", out)?;
            }
            if let Some(runtime) = &agent.secode_runtime {
                secode::runtime(runtime, "    ", out)?;
            }
            resume_advice(&agent.resume, "    ", out)?;
        }
        omissions(agents, out)?;
    }
    Ok(())
}
/// "working for 4m", "idle for 2h 5m", or the bare state when its start is unknown.
fn crew_state(state: &se_core::ops::AgentStateView) -> String {
    let label = match state.state.as_str() {
        "attention" => "needs attention",
        "running" => "running (turns not observed)",
        "turn-unreadable" => "running (turn state unreadable)",
        other => other,
    };
    match state.elapsed_seconds {
        Some(s) if s >= 3_600 => format!("{label} for {}h {}m", s / 3_600, s % 3_600 / 60),
        Some(s) if s >= 60 => format!("{label} for {}m", s / 60),
        Some(s) => format!("{label} for {s}s"),
        None => label.into(),
    }
}
fn projects_section(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
    Ok(())
}
fn unread_lines(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
    Ok(())
}
fn recording_lines(
    value: &StatusOutput,
    healthy_stopped: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    if !healthy_stopped || value.capture.state != "unknown" || value.atlas.state != "not-built" {
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
    }
    if let Some(reason) = &value.atlas.reason {
        writeln!(out, "  Atlas: {reason}")?;
    }
    Ok(())
}
fn atlas_lines(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
    Ok(())
}
fn pending_lines(
    value: &StatusOutput,
    healthy_stopped: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    for pending in &value.pending {
        if pending.what == "runtime observation"
            && pending
                .detail
                .starts_with("No runtime connection file was found.")
        {
            if !healthy_stopped {
                writeln!(
                    out,
                    "Background runtime: no connection file found. Running agents have not been checked; use se doctor for this home."
                )?;
            }
        } else {
            writeln!(out, "Pending {}: {}", pending.what, pending.detail)?;
        }
    }
    Ok(())
}
fn next_lines(value: &StatusOutput, out: &mut impl Write) -> io::Result<()> {
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
        notification::message_state(message, out)?;
        notification::render(&message.notification, out)?;
        if let Some(unreadable) = &message.unreadable {
            writeln!(out, "  Message unreadable: {}", unreadable.reason)?;
        } else {
            writeln!(out, "{}", message.body.text)?;
            if let Some(route) = &message.channel_reply {
                writeln!(out, "{}", route.instruction)?;
            }
            if let Some(route) = &message.remote_reply {
                writeln!(out, "{}", route.instruction)?;
            }
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

pub(super) fn assignments(
    value: &se_core::ops::AssignmentPage,
    out: &mut impl Write,
) -> io::Result<()> {
    if value.page.items().is_empty() && value.page.window().complete() {
        writeln!(out, "No open assignments.")?;
    }
    for row in value.page.items() {
        writeln!(out, "{}  {}  {}", row.id, row.assignee, row.state)?;
    }
    omissions(&value.page, out)
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
    let mut line = match git.commits {
        Some(commits) => format!(
            "Existing repo: {commits} commit{}",
            if commits == 1 { "" } else { "s" }
        ),
        // A history walk that outlived its deadline says so; the facts that
        // did settle are still reported beside it rather than withheld.
        None => "Existing repo: commit count unknown".to_owned(),
    };
    if let Some(branch) = &git.branch {
        line.push_str(&format!(" on {branch}"));
    }
    if git.uncommitted == Some(true) {
        line.push_str("; uncommitted changes left untouched");
    }
    if let Some(observation) = &git.observation
        && observation.basis == "watched"
    {
        let state = if git.uncommitted == Some(false) {
            "watched clean"
        } else {
            "watched"
        };
        line.push_str(&format!(
            "; {state}, last reconciled {}",
            observation.reconciled_at
        ));
        if let Some(age) = observation.age_seconds.filter(|age| *age > 3) {
            line.push_str(&format!(" ({age}s ago)"));
        }
        if let Some(last) = &observation.last_notification_at {
            line.push_str(&format!("; last notification {last}"));
        } else {
            line.push_str("; no notifications since the watch started");
        }
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
