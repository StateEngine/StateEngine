//! Plain wake facts; the original structured receipt remains available as JSON.
use se_core::ops::{
    WakeResult,
    agent_wake::{WakeLifecycle, WakeOutcome},
};
use std::io::{self, Write};

pub(super) fn output(value: &WakeResult, out: &mut impl Write) -> io::Result<()> {
    match value.outcome {
        WakeOutcome::Offered => writeln!(out, "Wake offered.")?,
        WakeOutcome::Delivered => writeln!(out, "Wake delivered.")?,
        WakeOutcome::Pending => writeln!(out, "Wake pending.")?,
        WakeOutcome::Refused => writeln!(out, "Wake refused.")?,
    }
    writeln!(out, "Agent {} ({}).", value.agent.name, value.agent.id)?;
    lifecycle(&value.lifecycle, out)?;
    if let Some(offer) = &value.offer {
        writeln!(out, "Offer: {}.", offer.kind)?;
        if let Some(transport) = &offer.transport {
            writeln!(out, "Transport: {transport}.")?;
        }
        if let Some(bytes) = offer.bytes {
            writeln!(out, "Bytes: {bytes}.")?;
        }
    }
    if let Some(detail) = &value.detail {
        writeln!(out, "{detail}")?;
    }
    if let Some(remedy) = &value.remedy {
        writeln!(out, "{remedy}")?;
    }
    writeln!(out, "Use --json for full wake details.")
}
fn lifecycle(value: &WakeLifecycle, out: &mut impl Write) -> io::Result<()> {
    match value.state.as_str() {
        "running" => {
            writeln!(out, "State: running.")?;
            if let Some(session) = &value.session {
                writeln!(out, "Session {session}.")?;
            }
            Ok(())
        }
        other => writeln!(out, "State: {other}."),
    }
}
