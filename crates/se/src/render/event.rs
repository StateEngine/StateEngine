use se_core::ops::{EventOutput, HistoryEvent, Writer};
use se_types::Read;
use std::io::{self, Write};
pub(super) fn output(value: &EventOutput, out: &mut impl Write) -> io::Result<()> {
    match value {
        EventOutput::Present(value) | EventOutput::Other(Read::Present { value }) => {
            present(value, out)
        }
        EventOutput::Other(Read::Absent { checked }) => {
            writeln!(out, "Event not found. Checked: {checked}")
        }
        EventOutput::Other(Read::Unreadable { source, reason, .. }) => {
            writeln!(out, "Event unreadable from {source}: {reason}")
        }
        EventOutput::Other(Read::Unknown { what }) => {
            writeln!(out, "Event observation unknown: {what}")
        }
    }
}
fn present(value: &HistoryEvent, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{} — {}", value.kind, value.project.name)?;
    writeln!(out, "Event: {}", value.event_id)?;
    writeln!(out, "By {} at {}", value.actor.name, value.recorded_at)?;
    match &value.writer {
        Writer::Direct => writeln!(out, "Committed directly with no runtime writer."),
        Writer::Host { host_generation } => {
            writeln!(out, "Committed by runtime generation {host_generation}.")
        }
    }?;
    for key in ["body", "statement", "rationale", "reason"] {
        if let Some(text) = value.payload.get(key).and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("text").and_then(serde_json::Value::as_str))
        }) {
            writeln!(out, "{text}")?;
        }
    }
    Ok(())
}
