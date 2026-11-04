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
    // The core has already selected the public payload. Render every selected
    // fact so registrations, grants and other non-body families stay useful.
    if value.kind == "profile.saved" {
        // The stored profile keeps internal enum names; plain history reuses
        // the same permission and provider terms init and launch print.
        let mapped = saved_profile_payload(&value.payload);
        payload(&mapped, "Payload", 0, out)
    } else {
        payload(&value.payload, "Payload", 0, out)
    }
}

fn saved_profile_payload(payload: &serde_json::Value) -> serde_json::Value {
    let mut mapped = payload.clone();
    let Some(profile) = mapped.get_mut("profile").and_then(|profile| profile.as_object_mut()) else {
        return mapped;
    };
    if let Some(serde_json::Value::String(permission)) = profile.get_mut("permission") {
        *permission = permission_label(permission).to_owned();
    }
    if let Some(serde_json::Value::String(provider)) = profile.get_mut("provider") {
        *provider = provider_label(provider).to_owned();
    }
    mapped
}

fn permission_label(permission: &str) -> &str {
    match permission {
        "ReadOnly" => "read-only",
        "WorkspaceWrite" => "workspace-write",
        "NamedFullBypass" => "bypass",
        other => other,
    }
}

fn provider_label(provider: &str) -> &str {
    match provider {
        "Claude" => "Claude Code",
        "SeCode" => "SE Code",
        other => other,
    }
}

fn payload(
    value: &serde_json::Value,
    label: &str,
    depth: usize,
    out: &mut impl Write,
) -> io::Result<()> {
    let indent = "  ".repeat(depth);
    let label = label.replace('_', " ");
    match value {
        serde_json::Value::Object(fields) => {
            writeln!(out, "{indent}{label}:")?;
            for (key, value) in fields {
                payload(value, key, depth + 1, out)?;
            }
        }
        serde_json::Value::Array(values) => {
            if values.is_empty() {
                writeln!(out, "{indent}{label}: (empty)")?;
            } else {
                writeln!(out, "{indent}{label}:")?;
                for (index, value) in values.iter().enumerate() {
                    payload(value, &(index + 1).to_string(), depth + 1, out)?;
                }
            }
        }
        serde_json::Value::String(text) => {
            writeln!(out, "{indent}{label}: {text}")?;
        }
        serde_json::Value::Null => writeln!(out, "{indent}{label}: (none)")?,
        value => writeln!(out, "{indent}{label}: {value}")?,
    }
    Ok(())
}

pub(super) fn page(value: &se_core::ops::HistoryPage, out: &mut impl Write) -> io::Result<()> {
    for event in value.page.items() {
        present(event, out)?;
    }
    if value.page.items().is_empty() {
        writeln!(out, "No events in this history page.")?;
    }
    if let Some(cursor) = value.page.next() {
        writeln!(out, "Continue the same command with --cursor {cursor}")?;
    }
    if !value.page.window().complete() {
        writeln!(
            out,
            "This history page is incomplete; its JSON window describes the remaining omissions."
        )?;
    }
    Ok(())
}
