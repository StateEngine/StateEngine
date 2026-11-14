mod acp;
mod administration;
mod continuity;
mod control;
mod doctor;
pub mod error;
mod event;
mod guide;
#[cfg(feature = "import")]
mod import;
mod labels;
#[cfg(test)]
mod mail_state_tests;
mod read;
mod remote;
mod stop;
mod transcript;
mod wake;
mod write;

use se_core::{ops::AnyOutput, registry::HumanKind};
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
    let _phase = crate::phase_trace::Phase::new("cli_output_at");
    if !json
        && let Some(options) = atlas
        && let Some(text) =
            se_host::atlas_queries::compact(value, options.byte_budget as usize, options.explain)
                .map_err(io::Error::other)?
    {
        if !quiet || value.exit_code() != 0 {
            write!(out, "{text}")?;
        }
        out.flush()?;
        return Ok(value.exit_code());
    }
    if !json
        && !quiet
        && let AnyOutput::Resume(resume) = value
    {
        continuity::resume_at(&resume.value, Some(home), out)?;
        out.flush()?;
        return Ok(value.exit_code());
    }
    output(value, json, quiet, out)
}

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn output(value: &AnyOutput, json: bool, quiet: bool, out: &mut impl Write) -> io::Result<u8> {
    let _phase = crate::phase_trace::Phase::new("cli_output");
    if !json && matches!(value, AnyOutput::HookClaude(_)) {
        return Err(io::Error::other(
            "native hook output requires its provider framing writer",
        ));
    }
    if json {
        serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
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
        match (value.human_kind(), value) {
            (HumanKind::RemoteLaunch, AnyOutput::RemoteLaunch(value)) => {
                remote::launch(&value.value, out)?
            }
            (HumanKind::RemoteList, AnyOutput::RemoteList(value)) => {
                remote::list(&value.value, out)?
            }
            (HumanKind::RemoteWatch, AnyOutput::RemoteWatch(value)) => {
                remote::watch(&value.value, out)?
            }
            (HumanKind::RemoteSend, AnyOutput::RemoteSend(value)) => {
                remote::send(&value.value, out)?
            }
            (HumanKind::Resume, AnyOutput::Resume(value)) => continuity::resume(&value.value, out)?,
            (HumanKind::SessionContext, AnyOutput::SessionContext(value)) => {
                write!(out, "{}", value.value.assembled_model_input)?
            }
            (HumanKind::Version, AnyOutput::MetaVersion(value)) => {
                writeln!(out, "stateengine {}", value.value.version)?
            }
            (HumanKind::Help, AnyOutput::MetaHelp(value)) => write!(out, "{}", value.value.usage)?,
            (HumanKind::Guide, AnyOutput::MetaGuide(value)) => guide::output(&value.value, out)?,
            (HumanKind::Schema, AnyOutput::MetaSchema(value)) => read::schema(&value.value, out)?,
            #[cfg(feature = "import")]
            (HumanKind::Import, AnyOutput::ImportNode(value)) => import::output(&value.value, out)?,
            (HumanKind::Init, AnyOutput::ProjectInit(value)) => write::init(&value.value, out)?,
            (HumanKind::ProjectMove, AnyOutput::ProjectMove(value)) => {
                write::move_output(&value.value, out)?
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
                )?;
            }
            (HumanKind::Diagnosis, AnyOutput::DoctorInspect(value)) => {
                doctor::diagnosis(&value.value, out)?
            }
            (HumanKind::Repair, AnyOutput::DoctorRepair(value)) => {
                doctor::repair(&value.value, out)?
            }
            (HumanKind::Status, AnyOutput::ProjectStatus(value)) => {
                read::status(&value.value, out)?
            }
            (HumanKind::ConfigReceipt, AnyOutput::ConfigSet(value)) => {
                administration::config(&value.value, out)?
            }
            (HumanKind::ConfigValue, AnyOutput::ConfigGet(value)) => {
                administration::config_value(&value.value, out)?
            }
            (HumanKind::ConfigPage, AnyOutput::ConfigList(value)) => {
                administration::config_page(&value.value, out)?
            }
            (HumanKind::AgentPage, AnyOutput::AgentList(value)) => {
                administration::agents(&value.value, out)?
            }
            (HumanKind::Launch, AnyOutput::AgentLaunch(value)) => {
                control::launch(&value.value, out)?
            }
            (HumanKind::Stop, AnyOutput::AgentStop(value)) => stop::output(&value.value, out)?,
            (HumanKind::Wake, AnyOutput::AgentWake(value)) => wake::output(&value.value, out)?,
            (HumanKind::Remove, AnyOutput::ProjectRemove(value)) => {
                control::remove(&value.value, out)?
            }
            (HumanKind::AgentStatus, AnyOutput::AgentShow(value)) => {
                administration::agent_status(&value.value, out)?
            }
            (HumanKind::AgentReceipt, AnyOutput::AgentCreate(value)) => {
                administration::agent(&value.value, out)?
            }
            (HumanKind::HistoryPage, AnyOutput::HistoryList(value)) => {
                event::page(&value.value, out)?
            }
            (HumanKind::Event, AnyOutput::EventRead(value)) => event::output(&value.value, out)?,
            (_, AnyOutput::MessageRead(value)) => {
                writeln!(
                    out,
                    "{} → {} [{}]",
                    value.value.message.from.name,
                    value.value.message.to.name,
                    value.value.message.id
                )?;
                read::notification::message_state(&value.value.message, out)?;
                writeln!(out, "{}", value.value.message.body.text)?;
                writeln!(
                    out,
                    "{}",
                    if value.value.marked_read {
                        "Marked read."
                    } else {
                        "Inspection; recipient read mark unchanged."
                    }
                )?;
            }
            (_, AnyOutput::MessageDisposition(value)) => writeln!(
                out,
                "{}: {}.",
                value.value.disposition, value.value.message_id
            )?,
            (HumanKind::MessageReceipt, AnyOutput::MessageSend(value)) => {
                write::message(&value.value, out)?
            }
            (HumanKind::MessagePage, AnyOutput::MessageList(value)) => {
                read::messages(&value.value, out)?
            }
            (HumanKind::WorkingState, AnyOutput::WorkingStateGet(value)) => {
                read::working_state(&value.value, out)?
            }
            (HumanKind::WorkingStateReceipt, AnyOutput::WorkingStateSet(value)) => {
                write::working_state(&value.value, out)?
            }
            (HumanKind::RuntimeStart, AnyOutput::RuntimeUp(value)) => {
                write::runtime_start(&value.value, out)?
            }
            (HumanKind::RuntimeStop, AnyOutput::RuntimeDown(value)) => {
                write::runtime_stop(&value.value, out)?
            }
            (HumanKind::Uninstall, AnyOutput::Uninstall(value)) => {
                write::uninstall(&value.value, out)?
            }
            _ => {
                return Err(io::Error::other(
                    "registered output and human renderer disagree",
                ));
            }
        }
    }
    out.flush()?;
    Ok(value.exit_code())
}

/// Keep every achieved hazard fact while deferring the final Windows verdict.
pub(crate) fn uninstall_deferred(
    value: &se_core::ops::UninstallOutput,
    out: &mut impl Write,
) -> io::Result<()> {
    write::uninstall_deferred(value, out)
}
