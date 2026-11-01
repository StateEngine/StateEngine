use super::read::next_step;
use se_core::{
    config_policy::{Approval, EffectiveSandbox, Provider, ResolvedProfile},
    ops::outputs::*,
};
use std::io::{self, Write};

pub fn init(value: &InitOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Project {} registered at {}",
        value.project.name, value.project.root
    )?;
    writeln!(out, "State home: {}", value.home)?;
    writeln!(
        out,
        "Repository files written: {}",
        value.repo.files_touched
    )?;
    writeln!(
        out,
        "Agent {} uses {}",
        value.agent.name,
        provider(value.agent.provider)
    )?;
    profile(&value.agent.permission_profile, out)?;
    for integration in &value.integrations {
        writeln!(
            out,
            "Integration {} ({}): {}",
            integration.path,
            integration.entry,
            outcome(integration.action)
        )?;
        witness(&integration.witness, out)?;
    }
    for change in &value.changed {
        writeln!(out, "  {change}")?;
    }
    if let Some(launched) = &value.launch {
        launch(launched, out)?;
    }
    next_step(&value.next, out)?;
    if value.repo.files_touched == 0 && value.integrations.is_empty() {
        writeln!(
            out,
            "For user-started Claude Code or Codex sessions: se init --adopt"
        )?;
    }
    Ok(())
}

fn profile(value: &ResolvedProfile, out: &mut impl Write) -> io::Result<()> {
    let sandbox = match value.sandbox {
        EffectiveSandbox::ReadOnly => "read-only",
        EffectiveSandbox::WorkspaceWrite => "workspace-write",
        EffectiveSandbox::Bypass => "bypass",
    };
    let approval = match value.approval {
        Approval::OnRequest => "on-request",
        Approval::Untrusted => "untrusted",
        Approval::Never => "never",
    };
    writeln!(
        out,
        "Permission profile {}: {sandbox}, approval {approval}, network {}, bypass {}",
        value.name, value.network, value.bypass
    )?;
    if !value.network {
        writeln!(
            out,
            "To enable network for this profile: se config set profiles.{}.network true",
            value.name
        )?;
    }
    Ok(())
}

fn provider(value: Provider) -> &'static str {
    match value {
        Provider::Claude => "Claude Code",
        Provider::Codex => "Codex",
    }
}

pub fn launch(value: &LaunchOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{} launched with {} (PID {})",
        value.agent.name,
        provider(value.provider),
        value.process.pid
    )?;
    profile(&value.permission_profile, out)?;
    writeln!(out, "Conversation: {}", value.conversation_id)
}

pub fn message(value: &MessageOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Message {}: {} → {}",
        value.message_id, value.from.name, value.to.name
    )?;
    writeln!(out, "Delivery: {}", value.delivery.state)?;
    writeln!(
        out,
        "Event: {}; request key: {}",
        value.event_id, value.idempotency_key
    )
}

pub fn working_state(value: &WorkingStateReceipt, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Working state saved for {} at revision {}",
        value.agent.name, value.revision
    )?;
    writeln!(out, "Request key: {}", value.idempotency_key)
}

pub fn runtime_start(value: &RuntimeStart, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Runtime {} (PID {}, generation {})",
        value.state, value.process.pid, value.generation
    )?;
    writeln!(out, "Endpoint: {}", value.endpoint)?;
    if let Some(recovery) = &value.endpoint_recovery {
        writeln!(
            out,
            "Retained stale endpoint {} as {}",
            recovery
                .original
                .to_local()
                .map_err(io::Error::other)?
                .display(),
            recovery
                .retained
                .to_local()
                .map_err(io::Error::other)?
                .display()
        )?;
    }
    Ok(())
}

pub fn runtime_stop(value: &RuntimeStop, out: &mut impl Write) -> io::Result<()> {
    stops(&value.stops, out)?;
    writeln!(
        out,
        "Runtime stop {}",
        if value.complete {
            "complete"
        } else {
            "incomplete"
        }
    )?;
    witness(&value.witness, out)
}

pub fn uninstall(value: &UninstallOutput, out: &mut impl Write) -> io::Result<()> {
    stops(&value.stops, out)?;
    for file in &value.install_files {
        writeln!(out, "{}: {}", file.path, outcome(file.outcome))?;
        witness(&file.witness, out)?;
    }
    for directory in &value.directories {
        let outcome = match directory.outcome {
            DirectoryOutcome::Removed => "removed",
            DirectoryOutcome::AlreadyAbsent => "already absent",
            DirectoryOutcome::NotEmptyPreserved => "nonempty directory preserved",
            DirectoryOutcome::Unreadable => "unreadable",
            DirectoryOutcome::Unsafe => "unsafe path preserved",
            DirectoryOutcome::Pending => "pending",
        };
        writeln!(out, "{}: {outcome}", directory.path)?;
        witness(&directory.witness, out)?;
    }
    for integration in &value.integrations {
        writeln!(
            out,
            "{} ({}): {}",
            integration.path,
            integration.entry,
            outcome(integration.action)
        )?;
        witness(&integration.witness, out)?;
    }
    for directory in &value.recovery {
        writeln!(out, "Recovery scan {}:", directory.directory)?;
        witness(&directory.witness, out)?;
        match &directory.copies {
            se_types::Read::Present { value: copies } => {
                if copies.is_empty() {
                    writeln!(out, "  No recovery copies found")?;
                }
                for copy in copies {
                    match &copy.restored_to {
                        Some(target) => writeln!(out, "  {} restored to {}", copy.path, target)?,
                        None => writeln!(out, "  {} preserved; recovery unresolved", copy.path)?,
                    }
                    witness(&copy.witness, out)?;
                }
            }
            se_types::Read::Absent { checked } => writeln!(out, "  Absent: {checked}")?,
            se_types::Read::Unreadable { source, reason, .. } => {
                writeln!(out, "  Unreadable {source}: {reason}")?
            }
            se_types::Read::Unknown { what } => writeln!(out, "  Unknown: {what}")?,
        }
        match &directory.temporary_files {
            se_types::Read::Present { value: files } => {
                for file in files {
                    writeln!(
                        out,
                        "  Installer temporary {}: {}",
                        file.path,
                        outcome(file.outcome)
                    )?;
                    witness(&file.witness, out)?;
                }
            }
            se_types::Read::Absent { checked } => {
                writeln!(out, "  Installer temporaries absent: {checked}")?
            }
            se_types::Read::Unreadable { source, reason, .. } => {
                writeln!(out, "  Installer temporaries unreadable {source}: {reason}")?
            }
            se_types::Read::Unknown { what } => {
                writeln!(out, "  Installer temporaries unknown: {what}")?
            }
        }
    }
    for revoked in &value.revocations {
        writeln!(out, "Session {} credential revocation:", revoked.session)?;
        witness(&revoked.witness, out)?;
    }
    writeln!(out, "PATH ({}):", value.path.scope)?;
    witness(&value.path.witness, out)?;
    for path in &value.preserved {
        writeln!(out, "Preserved: {path}")?;
    }
    writeln!(
        out,
        "Uninstall {}. Request key: {}",
        if value.complete {
            "complete"
        } else {
            "incomplete"
        },
        value.idempotency_key
    )
}

fn stops(values: &[StopFact], out: &mut impl Write) -> io::Result<()> {
    for stop in values {
        writeln!(
            out,
            "Stop {}: {}",
            stop.target,
            if stop.complete {
                "complete"
            } else {
                "incomplete"
            }
        )?;
        witness(&stop.witness, out)?;
        if let Some(command) = &stop.resume.command {
            writeln!(out, "  Resume conversation: {command}")?;
        }
        if let Some(reason) = &stop.resume.reason {
            writeln!(out, "  Resume: {reason}")?;
        }
    }
    Ok(())
}

fn witness(value: &Witness, out: &mut impl Write) -> io::Result<()> {
    let state = match value.state {
        WitnessState::Witnessed => "witnessed",
        WitnessState::Unknown => "unknown",
        WitnessState::Failed => "failed",
    };
    write!(out, "  {state} via {}", value.method)?;
    if let Some(detail) = &value.detail {
        write!(out, ": {detail}")?;
    }
    writeln!(out)
}

fn outcome(value: FileOutcome) -> &'static str {
    match value {
        FileOutcome::Written => "written",
        FileOutcome::Removed => "removed",
        FileOutcome::Unchanged => "unchanged",
        FileOutcome::AlreadyAbsent => "already absent",
        FileOutcome::ConflictKept => "edited file preserved",
        FileOutcome::Unreadable => "unreadable",
        FileOutcome::Pending => "pending",
    }
}
