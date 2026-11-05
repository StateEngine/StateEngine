use se_core::ops::{EventOutput, HistoryEvent};
use se_types::Read;
use std::io::{self, Write};
#[path = "event/tool.rs"]
mod tool;
pub(super) fn output(value: &EventOutput, out: &mut impl Write) -> io::Result<()> {
    match value {
        EventOutput::Present(value) | EventOutput::Other(Read::Present { value }) => {
            present(value, out)?;
            writeln!(out, "Use --json for full event details.")
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
    let captured_tool = value.kind == "transcript.event"
        && value
            .payload
            .pointer("/metadata/kind")
            .and_then(serde_json::Value::as_str)
            == Some("captured-tool");
    writeln!(
        out,
        "{} — {}",
        if captured_tool {
            "Tool action"
        } else {
            title(&value.kind)
        },
        value.project.name
    )?;
    writeln!(out, "  Event: {}", value.event_id)?;
    writeln!(out, "  By: {}", value.actor.name)?;
    writeln!(out, "  At: {}", value.recorded_at)?;
    if captured_tool {
        return tool::render(value.payload.pointer("/metadata/captured_tool"), out);
    }
    // Select the useful facts from the public projection. Never recursively
    // dump its storage/provenance envelope into a person's conversation view.
    for (label, path) in summary_fields(&value.kind) {
        if let Some(field) = value.payload.pointer(path) {
            match field {
                serde_json::Value::String(text) => {
                    let text = match (value.kind.as_str(), *path) {
                        ("profile.saved", "/profile/permission") => {
                            super::labels::stored_permission(text)
                        }
                        ("profile.saved", "/profile/provider") => {
                            super::labels::stored_provider(text)
                        }
                        _ => text,
                    };
                    fact(label, text, out)?;
                }
                serde_json::Value::Bool(value) => fact(label, &value.to_string(), out)?,
                serde_json::Value::Number(value) => fact(label, &value.to_string(), out)?,
                _ => {}
            }
        }
    }
    Ok(())
}

fn title(kind: &str) -> &str {
    match kind {
        "session.turn" => "Conversation message",
        "message.sent" => "Message sent",
        "message.work_sent" => "Project message sent",
        "working_state.set" => "Working notes saved",
        "principal.registered" => "Identity registered",
        "principal.renamed" => "Identity renamed",
        "profile.saved" => "Agent settings saved",
        "grant.recorded" => "Agent creation permission changed",
        "decision.proposed" => "Decision proposed",
        "decision.rejected" => "Decision rejected",
        "decision.retracted" => "Decision withdrawn",
        "decision.ratified" => "Decision approved",
        "decision.superseded" => "Decision replaced",
        "message.read" => "Message read",
        "message.dismissed" => "Message dismissed",
        "message.delivered" => "Message delivered",
        "message.superseded" => "Message replaced",
        "transcript.event" => "Provider activity",
        "capture.suppressed" => "Conversation recording limited",
        "alias.imported" => "Imported name linked",
        "legacy.retained" => "Original imported data retained",
        "import.started" => "Import started",
        "import.progress" => "Import progress",
        "import.finished" => "Import finished",
        "import.unreadable" => "Import source unreadable",
        other => other,
    }
}

fn fact(label: &str, text: &str, out: &mut impl Write) -> io::Result<()> {
    let mut lines = text.split('\n');
    writeln!(out, "  {label}: {}", lines.next().unwrap_or_default())?;
    for line in lines {
        writeln!(out, "    {line}")?;
    }
    Ok(())
}

fn summary_fields(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "session.turn" => &[("Role", "/role"), ("Text", "/body/text")],
        "message.sent" | "message.work_sent" => &[
            ("To", "/to/name"),
            ("Kind", "/kind"),
            ("Text", "/body/text"),
        ],
        "working_state.set" => &[("Agent", "/agent/name"), ("Text", "/body/text")],
        "principal.registered" | "principal.renamed" => &[("Name", "/name"), ("Role", "/role")],
        "profile.saved" => &[
            ("Agent", "/agent/name"),
            ("Profile", "/profile/named_profile"),
            ("Provider", "/profile/provider"),
            ("Permissions", "/profile/permission"),
            ("Model", "/profile/model"),
            ("Effort", "/profile/effort"),
        ],
        "grant.recorded" => &[
            ("Principal", "/principal/name"),
            ("Can create agents for", "/key/AgentCanCreate"),
            ("Active", "/active"),
        ],
        "decision.proposed" => &[
            ("Key", "/key"),
            ("Statement", "/statement/text"),
            ("Rationale", "/rationale/text"),
        ],
        "decision.rejected" | "decision.retracted" => {
            &[("Decision", "/decision_id"), ("Reason", "/reason/text")]
        }
        "decision.ratified" => &[("Decision", "/decision_id")],
        "decision.superseded" => &[
            ("Previous decision", "/prior"),
            ("Replacement", "/replacement"),
        ],
        "message.read" | "message.dismissed" | "message.delivered" => {
            &[("Message", "/message_id"), ("Recipient", "/recipient/name")]
        }
        "message.superseded" => &[("Message", "/message_id"), ("Replacement", "/replacement")],
        "transcript.event" => &[
            ("Provider event", "/metadata/kind"),
            ("Type", "/metadata/subtype"),
            ("Count", "/metadata/count"),
        ],
        "capture.suppressed" => &[("Count", "/count"), ("Reason", "/reason")],
        "alias.imported" => &[("Alias", "/alias"), ("Principal", "/principal/name")],
        "legacy.retained" => &[("Family", "/family")],
        "import.started" => &[("Format", "/format")],
        "import.progress" => &[("Family", "/family"), ("Source rows", "/source_rows")],
        "import.finished" => &[("Complete", "/complete")],
        "import.unreadable" => &[("Family", "/family"), ("Reason", "/reason")],
        _ => &[],
    }
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
    writeln!(out, "Use --json for full event details.")?;
    Ok(())
}
