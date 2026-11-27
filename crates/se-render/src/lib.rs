mod acp;
mod administration;
mod continuity;
mod control;
mod doctor;
pub mod error;
mod event;
mod forget;
mod guide;
#[cfg(feature = "import")]
mod import;
mod labels;
#[cfg(test)]
mod mail_state_tests;
mod read;
mod remote;
mod restore;
mod stop;
mod transcript;
mod wake;
mod write;

use se_core::{
    ops::{AnyOutput, MessageReadOutput},
    registry::HumanKind,
};
use std::io::{self, Write};

/// Commands printed by a local consumer retain its resolved state home.
pub fn output_at(
    value: &AnyOutput,
    json: bool,
    quiet: bool,
    home: &std::path::Path,
    atlas: Option<&se_core::ops::AtlasOptions>,
    out: &mut impl Write,
) -> io::Result<u8> {
    // Atlas exits honor --require-complete in compact and JSON output alike.
    let atlas_code = atlas.and_then(|options| value.atlas_exit(options.require_complete));
    if !json
        && let Some(options) = atlas
        && let Some(text) =
            se_host::atlas_queries::compact(value, options.byte_budget as usize, options.explain)
                .map_err(io::Error::other)?
    {
        let code = atlas_code.unwrap_or_else(|| value.exit_code());
        if !quiet || code != 0 {
            write!(out, "{text}")?;
        }
        out.flush()?;
        return Ok(code);
    }
    if !json
        && !quiet
        && let AnyOutput::Resume(resume) = value
    {
        continuity::resume_at(&resume.value, Some(home), out)?;
        out.flush()?;
        return Ok(value.exit_code());
    }
    let code = output(value, json, quiet, out)?;
    Ok(atlas_code.unwrap_or(code))
}

pub fn output(value: &AnyOutput, json: bool, quiet: bool, out: &mut impl Write) -> io::Result<u8> {
    if !json && matches!(value, AnyOutput::HookClaude(_)) {
        return Err(io::Error::other(
            "native hook output requires its provider framing writer",
        ));
    }
    if json {
        serde_json::to_writer(&mut *out, &se_mcp::presented(value)).map_err(io::Error::other)?;
        writeln!(out)?;
    } else if !quiet
        || value.exit_code() != 0
        || matches!(value.human_kind(), HumanKind::Help | HumanKind::Guide)
    {
        if let Some(text) =
            se_host::atlas_queries::compact(value, 4096, false).map_err(io::Error::other)?
        {
            write!(out, "{text}")?;
            out.flush()?;
            return Ok(value.exit_code());
        }
        render_human(value, out)?;
    }
    out.flush()?;
    Ok(value.exit_code())
}
fn render_human(value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    if let AnyOutput::MessageRead(value) = value {
        return message_read(&value.value, out);
    }
    if let AnyOutput::MessageDisposition(value) = value {
        return writeln!(
            out,
            "{}: {}.",
            value.value.disposition, value.value.message_id
        );
    }
    let kind = value.human_kind();
    match kind {
        HumanKind::RemoteLaunch
        | HumanKind::RemoteList
        | HumanKind::RemoteWatch
        | HumanKind::RemoteSend => render_remote(kind, value, out),
        HumanKind::Resume
        | HumanKind::Handoff
        | HumanKind::SessionContext
        | HumanKind::Version
        | HumanKind::Help
        | HumanKind::Guide
        | HumanKind::Schema => render_meta(kind, value, out),
        #[cfg(feature = "import")]
        HumanKind::Import => render_import(kind, value, out),
        HumanKind::Erasure => match value {
            AnyOutput::StoreForget(value) => forget::output(&value.value, out),
            _ => Err(renderer_disagreement()),
        },
        HumanKind::Restore => match value {
            AnyOutput::StoreRestore(value) => restore::output(&value.value, out),
            _ => Err(renderer_disagreement()),
        },
        HumanKind::Init
        | HumanKind::ProjectMove
        | HumanKind::WorktreeRemove
        | HumanKind::Bundle
        | HumanKind::Diagnosis
        | HumanKind::Repair
        | HumanKind::Status => render_project(kind, value, out),
        HumanKind::Assignment => render_assignment(kind, value, out),
        HumanKind::Captain => render_captain(kind, value, out),
        HumanKind::ConfigReceipt
        | HumanKind::ConfigValue
        | HumanKind::ConfigPage
        | HumanKind::HarnessReceipt
        | HumanKind::AgentPage
        | HumanKind::AgentStatus
        | HumanKind::AgentReceipt => render_administration(kind, value, out),
        HumanKind::Launch
        | HumanKind::Stop
        | HumanKind::Wake
        | HumanKind::DelegateStart
        | HumanKind::DelegateCancel
        | HumanKind::Remove => render_control(kind, value, out),
        HumanKind::HistoryPage | HumanKind::SearchPage | HumanKind::Event => {
            render_history(kind, value, out)
        }
        HumanKind::MessageReceipt
        | HumanKind::MessagePage
        | HumanKind::WorkingState
        | HumanKind::WorkingStateReceipt
        | HumanKind::RuntimeStart
        | HumanKind::RuntimeStop
        | HumanKind::Uninstall => render_session(kind, value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn render_remote(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::RemoteLaunch, AnyOutput::RemoteLaunch(value)) => {
            remote::launch(&value.value, out)
        }
        (HumanKind::RemoteList, AnyOutput::RemoteList(value)) => remote::list(&value.value, out),
        (HumanKind::RemoteWatch, AnyOutput::RemoteWatch(value)) => remote::watch(&value.value, out),
        (HumanKind::RemoteSend, AnyOutput::RemoteSend(value)) => remote::send(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn render_meta(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::Resume, AnyOutput::Resume(value)) => continuity::resume(&value.value, out),
        (HumanKind::Handoff, AnyOutput::HandoffExport(value)) => {
            continuity::handoff(&value.value, out)
        }
        (HumanKind::SessionContext, AnyOutput::SessionContext(value)) => {
            write!(out, "{}", value.value.assembled_model_input)
        }
        (HumanKind::Version, AnyOutput::MetaVersion(value)) => {
            writeln!(out, "stateengine {}", value.value.version)
        }
        (HumanKind::Help, AnyOutput::MetaHelp(value)) => write!(out, "{}", value.value.usage),
        (HumanKind::Guide, AnyOutput::MetaGuide(value)) => guide::output(&value.value, out),
        (HumanKind::Schema, AnyOutput::MetaSchema(value)) => read::schema(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
#[cfg(feature = "import")]
fn render_import(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::Import, AnyOutput::ImportNode(value)) => import::output(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn render_project(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::Init, AnyOutput::ProjectInit(value)) => write::init(&value.value, out),
        (HumanKind::ProjectMove, AnyOutput::ProjectMove(value)) => {
            write::move_output(&value.value, out)
        }
        (HumanKind::WorktreeRemove, AnyOutput::WorktreeRemove(value)) => {
            let v = &value.value;
            writeln!(
                out,
                "Removed worktree {} ({}; pruned={})",
                v.path, v.worktree_name, v.pruned
            )
        }
        (HumanKind::Bundle, AnyOutput::DiagnosticBundle(value)) => {
            writeln!(out, "Diagnostic file: {}", value.value.path)?;
            writeln!(
                out,
                "{} bytes; SHA-256 {}",
                value.value.bytes, value.value.sha256
            )?;
            if !value.value.complete {
                writeln!(
                    out,
                    "Collection incomplete; the file names unreadable or omitted sections."
                )?;
            }
            writeln!(
                out,
                "Review the redacted file before sharing it. Delete it when no longer needed."
            )
        }
        (HumanKind::Diagnosis, AnyOutput::DoctorInspect(value)) => {
            doctor::diagnosis(&value.value, out)
        }
        (HumanKind::Repair, AnyOutput::DoctorRepair(value)) => doctor::repair(&value.value, out),
        (HumanKind::Status, AnyOutput::ProjectStatus(value)) => read::status(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn render_assignment(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::Assignment, AnyOutput::AssignmentWrite(value)) => {
            writeln!(
                out,
                "Assignment {}: {}",
                value.value.assignment, value.value.state
            )
        }
        (HumanKind::Assignment, AnyOutput::AssignmentList(value)) => {
            read::assignments(&value.value, out)
        }
        _ => Err(renderer_disagreement()),
    }
}
fn render_captain(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::Captain, AnyOutput::CaptainShow(value)) => {
            if let Some(captain) = &value.value.captain {
                writeln!(out, "Captain: {} ({})", captain.name, captain.id)?;
            } else {
                writeln!(out, "No captain is set.")?;
            }
            Ok(())
        }
        (HumanKind::Captain, AnyOutput::CaptainSet(value)) => {
            writeln!(
                out,
                "Recorded captain: {} ({})",
                value.value.captain.name, value.value.captain.id
            )?;
            match &value.value.current_captain {
                Some(captain) => {
                    writeln!(out, "Current captain: {} ({})", captain.name, captain.id)?
                }
                None => writeln!(out, "No current captain is set.")?,
            }
            match &value.value.one_agent_project {
                se_types::Read::Present { value: true } => {
                    writeln!(out, "Warning: this project has one agent.")?
                }
                se_types::Read::Present { value: false } => {}
                other => writeln!(out, "Agent count not established: {other:?}")?,
            }
            Ok(())
        }
        (HumanKind::Captain, AnyOutput::CaptainClear(value)) => {
            writeln!(out, "Recorded captain clear.")?;
            match &value.value.current_captain {
                Some(captain) => {
                    writeln!(out, "Current captain: {} ({})", captain.name, captain.id)?
                }
                None => writeln!(out, "No current captain is set.")?,
            }
            Ok(())
        }
        _ => Err(renderer_disagreement()),
    }
}
fn render_administration(
    kind: HumanKind,
    value: &AnyOutput,
    out: &mut impl Write,
) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::ConfigReceipt, AnyOutput::ConfigSet(value)) => {
            administration::config(&value.value, out)
        }
        (HumanKind::ConfigValue, AnyOutput::ConfigGet(value)) => {
            administration::config_value(&value.value, out)
        }
        (HumanKind::ConfigPage, AnyOutput::ConfigList(value)) => {
            administration::config_page(&value.value, out)
        }
        (HumanKind::HarnessReceipt, AnyOutput::HarnessAdd(value)) => {
            administration::harness(&value.value, out)
        }
        (HumanKind::AgentPage, AnyOutput::AgentList(value)) => {
            administration::agents(&value.value, out)
        }
        (HumanKind::AgentStatus, AnyOutput::AgentShow(value)) => {
            administration::agent_status(&value.value, out)
        }
        (HumanKind::AgentReceipt, AnyOutput::AgentCreate(value)) => {
            administration::agent(&value.value, out)
        }
        _ => Err(renderer_disagreement()),
    }
}
fn render_control(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::Launch, AnyOutput::AgentLaunch(value)) => control::launch(&value.value, out),
        (HumanKind::Stop, AnyOutput::AgentStop(value)) => stop::output(&value.value, out),
        (HumanKind::Wake, AnyOutput::AgentWake(value)) => wake::output(&value.value, out),
        (HumanKind::DelegateStart, AnyOutput::DelegateStart(value)) => {
            let v = &value.value;
            writeln!(
                out,
                "Delegated {} ({}) on {} [profile {}, ttl {}s]\nSession: {}",
                v.name,
                v.agent_id,
                labels::provider(v.provider),
                v.profile,
                v.ttl_seconds,
                v.session_id
            )
        }
        (HumanKind::DelegateCancel, AnyOutput::DelegateCancel(value)) => {
            let v = &value.value;
            writeln!(
                out,
                "Cancelled temporary agent {} ({}): retired={}, stopped_lifecycle={}",
                v.name, v.agent_id, v.retired, v.stopped_lifecycle
            )
        }
        (HumanKind::Remove, AnyOutput::ProjectRemove(value)) => control::remove(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn render_history(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::HistoryPage, AnyOutput::HistoryList(value)) => event::page(&value.value, out),
        (HumanKind::SearchPage, AnyOutput::HistorySearch(value)) => {
            event::search_page(&value.value, out)
        }
        (HumanKind::Event, AnyOutput::EventRead(value)) => event::output(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn render_session(kind: HumanKind, value: &AnyOutput, out: &mut impl Write) -> io::Result<()> {
    match (kind, value) {
        (HumanKind::MessageReceipt, AnyOutput::MessageSend(value)) => {
            write::message(&value.value, out)
        }
        (HumanKind::MessagePage, AnyOutput::MessageList(value)) => {
            read::messages(&value.value, out)
        }
        (HumanKind::WorkingState, AnyOutput::WorkingStateGet(value)) => {
            read::working_state(&value.value, out)
        }
        (HumanKind::WorkingStateReceipt, AnyOutput::WorkingStateSet(value)) => {
            write::working_state(&value.value, out)
        }
        (HumanKind::RuntimeStart, AnyOutput::RuntimeUp(value)) => {
            write::runtime_start(&value.value, out)
        }
        (HumanKind::RuntimeStop, AnyOutput::RuntimeDown(value)) => {
            write::runtime_stop(&value.value, out)
        }
        (HumanKind::Uninstall, AnyOutput::Uninstall(value)) => write::uninstall(&value.value, out),
        _ => Err(renderer_disagreement()),
    }
}
fn message_read(value: &MessageReadOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "{} → {} [{}]",
        value.message.from.name, value.message.to.name, value.message.id
    )?;
    read::notification::message_state(&value.message, out)?;
    writeln!(out, "{}", value.message.body.text)?;
    writeln!(
        out,
        "{}",
        if value.marked_read {
            "Marked read."
        } else {
            "Inspection; recipient read mark unchanged."
        }
    )
}
fn renderer_disagreement() -> io::Error {
    io::Error::other("registered output and human renderer disagree")
}

/// Keep every achieved hazard fact while deferring the final Windows verdict.
pub fn uninstall_deferred(
    value: &se_core::ops::UninstallOutput,
    out: &mut impl Write,
) -> io::Result<()> {
    write::uninstall_deferred(value, out)
}
