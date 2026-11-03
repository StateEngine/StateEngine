mod administration;
mod continuity;
mod control;
mod decision;
mod doctor;
pub mod error;
mod event;
mod read;
mod write;

use se_core::{ops::AnyOutput, registry::HumanKind};
use std::io::{self, Write};

pub fn output(value: &AnyOutput, json: bool, quiet: bool, out: &mut impl Write) -> io::Result<u8> {
    if !json && matches!(value, AnyOutput::HookClaude(_)) {
        return Err(io::Error::other(
            "native hook output requires its provider framing writer",
        ));
    }
    if json {
        serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
        writeln!(out)?;
    } else if !quiet || value.exit_code() != 0 || matches!(value.human_kind(), HumanKind::Help) {
        match (value.human_kind(), value) {
            (HumanKind::Resume, AnyOutput::Resume(value)) => continuity::resume(&value.value, out)?,
            (HumanKind::SessionContext, AnyOutput::SessionContext(value)) => {
                write!(out, "{}", value.value.assembled_model_input)?
            }
            (HumanKind::Version, AnyOutput::MetaVersion(value)) => {
                writeln!(out, "stateengine {}", value.value.version)?
            }
            (HumanKind::Help, AnyOutput::MetaHelp(value)) => write!(out, "{}", value.value.usage)?,
            (HumanKind::Schema, AnyOutput::MetaSchema(value)) => read::schema(&value.value, out)?,
            (HumanKind::Init, AnyOutput::ProjectInit(value)) => write::init(&value.value, out)?,
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
            (HumanKind::AgentPage, AnyOutput::AgentList(value)) => {
                administration::agents(&value.value, out)?
            }
            (HumanKind::Launch, AnyOutput::AgentLaunch(value)) => {
                control::launch(&value.value, out)?
            }
            (HumanKind::Stop, AnyOutput::AgentStop(value)) => control::stop(&value.value, out)?,
            (HumanKind::Remove, AnyOutput::ProjectRemove(value)) => {
                control::remove(&value.value, out)?
            }
            (HumanKind::AgentStatus, AnyOutput::AgentShow(value)) => {
                administration::agent_status(&value.value, out)?
            }
            (HumanKind::AgentReceipt, AnyOutput::AgentCreate(value)) => {
                administration::agent(&value.value, out)?
            }
            (HumanKind::DecisionPage, AnyOutput::DecisionList(value)) => {
                decision::page(&value.value, out)?
            }
            (HumanKind::Decision, AnyOutput::DecisionShow(value)) => {
                decision::output(&value.value, out)?
            }
            (HumanKind::DecisionReceipt, AnyOutput::Decision(value)) => {
                administration::decision(&value.value, out)?
            }
            (HumanKind::HistoryPage, AnyOutput::HistoryList(value)) => {
                event::page(&value.value, out)?
            }
            (HumanKind::Event, AnyOutput::EventRead(value)) => event::output(&value.value, out)?,
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
