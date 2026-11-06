use super::{
    labels,
    read::{notification, repo_line},
};
use se_core::{config_policy::ResolvedProfile, ops::outputs::*};
use std::io::{self, Write};

pub fn init(value: &InitOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Project {} registered at {}",
        value.project.name, value.project.root
    )?;
    if let Some(git) = value.repo.git.as_ref() {
        repo_line(git, out)?;
    }
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
        labels::provider(value.agent.provider)
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
    if let Some(hint) = &value.import_hint {
        writeln!(out, "{hint}")?;
    }
    super::read::first_launch(
        &value.home,
        &value.project.root,
        &value.agent.name,
        &value.next,
        out,
    )?;
    Ok(())
}

pub(super) fn profile(value: &ResolvedProfile, out: &mut impl Write) -> io::Result<()> {
    let sandbox = labels::permission(value.sandbox);
    let approval = labels::approval(value.approval);
    writeln!(
        out,
        "Permission profile {}: {sandbox}, approval {approval}, network {}, bypass {}",
        value.name,
        labels::network(value.network),
        value.bypass
    )?;
    if !value.network {
        writeln!(
            out,
            "To enable network, set network = true under [profiles.{}] in this state home's config.toml, then relaunch the agent.",
            value.name
        )?;
    }
    Ok(())
}

pub fn launch(value: &LaunchOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{} launched with {} (PID {})",
        value.agent.name,
        labels::provider(value.provider),
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
    notification::delivery(&value.delivery, out)?;
    notification::render(&value.notification, out)?;
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
    if value.already_down {
        writeln!(out, "Already down; no host was running.")?;
        return witness(&value.witness, out);
    }
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
    uninstall_report(value, false, out)
}
pub fn uninstall_deferred(value: &UninstallOutput, out: &mut impl Write) -> io::Result<()> {
    uninstall_report(value, true, out)
}
fn uninstall_report(
    value: &UninstallOutput,
    deferred: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    if let Some(cleanup) = &value.home_cleanup {
        writeln!(
            out,
            "Initialized-home cleanup; executable and PATH retained."
        )?;
        match &cleanup.runtime {
            se_types::Read::Present { value } => runtime_stop(value, out)?,
            se_types::Read::Absent { checked } => {
                writeln!(out, "Runtime stop report absent. Checked: {checked}")?
            }
            se_types::Read::Unreadable { source, reason, .. } => {
                writeln!(out, "Runtime stop report unreadable at {source}: {reason}")?
            }
            se_types::Read::Unknown { what } => writeln!(out, "Runtime stop not verified: {what}")?,
        }
        for file in &cleanup.runtime_files {
            writeln!(out, "{}: {}", file.path, outcome(file.outcome))?;
            witness(&file.witness, out)?;
        }
        writeln!(out, "{}", cleanup.manual_data_removal)?;
    }
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
    for entry in &value.path.before_entries {
        writeln!(out, "  Before: {entry}")?;
    }
    for entry in &value.path.after_entries {
        writeln!(out, "  After: {entry}")?;
    }
    for issue in &value.issues {
        writeln!(out, "Uninstall result check: {issue}")?;
    }
    if !value.complete && !deferred {
        writeln!(
            out,
            "Resolve the named pending outcomes, then retry se uninstall with the same --home and --key."
        )?;
    }
    for path in &value.preserved {
        writeln!(out, "Preserved: {path}")?;
    }
    writeln!(
        out,
        "Uninstall {}. Request key: {}",
        if deferred {
            "handoff pending"
        } else if value.complete {
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

pub(super) fn witness(value: &Witness, out: &mut impl Write) -> io::Result<()> {
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
