//! Human action summaries use only facts retained by trusted capture.
use se_core::ops::transcript::tool::{Observation, Outcome, Phase, Target, ToolName};
use std::io::{self, Write};

pub(super) fn render(value: Option<&serde_json::Value>, out: &mut impl Write) -> io::Result<()> {
    let Some(tool) =
        value.and_then(|value| serde_json::from_value::<Observation>(value.clone()).ok())
    else {
        return writeln!(
            out,
            "  Tool action details unavailable; use --json for details."
        );
    };
    let name = match &tool.tool {
        ToolName::Known(name) => name.as_str(),
        ToolName::Unknown(_) => "unknown tool",
    };
    let editing = matches!(
        name,
        "FileChange" | "Edit" | "Write" | "MultiEdit" | "NotebookEdit"
    );
    let reading = matches!(name, "Read" | "read" | "read_file");
    let completed = tool.phase == Phase::Completed;
    let succeeded = completed && matches!(tool.outcome, Outcome::Succeeded);
    let verb = match (editing, reading, succeeded) {
        (true, _, true) => "edited",
        (_, true, true) => "read",
        (_, _, true) => "ran",
        (true, _, false) => "edit",
        (_, true, false) => "read",
        _ => "tool",
    };
    match &tool.target {
        Target::Command(command) => {
            write!(out, "  {}: ", if succeeded { "ran" } else { "command" })?;
            for character in command.chars() {
                if character.is_control() {
                    write!(out, "{}", character.escape_default())?;
                } else {
                    write!(out, "{character}")?;
                }
            }
            writeln!(out)?;
        }
        Target::Paths(paths) => {
            for path in paths {
                if editing || reading {
                    writeln!(out, "  {verb}: {}", path.spelling)?;
                } else {
                    writeln!(out, "  {verb}: {name} — {}", path.spelling)?;
                }
            }
        }
        Target::Query(query) => writeln!(out, "  {verb}: {name} — query: {query}")?,
        Target::Unknown(_) if editing => writeln!(out, "  {verb}: path not captured")?,
        Target::Unknown(_) => writeln!(out, "  {verb}: {name} (arguments not captured)")?,
    }
    if !succeeded {
        let outcome = if !completed {
            "requested; completion not captured"
        } else {
            match tool.outcome {
                Outcome::Failed => "failed",
                Outcome::Cancelled => "cancelled",
                _ => "outcome unknown",
            }
        };
        writeln!(out, "  Result: {outcome}")?;
    }
    Ok(())
}
