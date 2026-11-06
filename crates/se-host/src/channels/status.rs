//! Delayed phone text uses current committed mail facts, never a wake or read.
use se_core::{scope, store_error::store_error};
use se_store::{Snapshot, SqliteSnapshot};
use se_types::{AgentId, MessageId, Read, Result};

pub(super) fn delayed_phone_status(
    read: &mut SqliteSnapshot,
    target: &AgentId,
    original: &MessageId,
    at: i64,
    replied: bool,
) -> Result<String> {
    let row = scope::require_present(
        read.message(original.clone())
            .map_err(|e| store_error(&e))?,
        "phone mail status",
        "Inspect the original saved mail.",
    )?;
    // The ordinary mail and Saved mapping share this writer commit timestamp.
    let sent = scope::require_present(
        read.event(row.event).map_err(|e| store_error(&e))?,
        "saved mail timestamp",
        "Restore access to the original mail commit.",
    )?;
    let elapsed = at.saturating_sub(sent.recorded_at_us).max(0) as u64 / 1_000_000;
    let state = if replied {
        "A linked reply is saved; inspect its Telegram send result"
    } else if row.read.is_some() {
        "Read; no reply yet"
    } else {
        "Not read yet"
    };
    let reason = match read
        .control_target(target.clone())
        .map_err(|e| store_error(&e))?
    {
        Read::Present { value } if value.sessions.is_empty() => {
            if !value.processes.is_empty() {
                "Native process custody is unresolved; open StateEngine to inspect it."
            } else if matches!(value.latest_session, Read::Absent { .. }) {
                "The agent has not been started."
            } else {
                "The agent is stopped; mail is waiting for an authorized resume."
            }
        }
        Read::Present { .. } => "The agent may be busy; mail remains saved.",
        Read::Absent { .. } => "The saved agent is unavailable.",
        _ => "The agent's runtime state is unknown.",
    };
    Ok(format!(
        "Status for {original}: {state}; {elapsed} seconds since Saved. {reason} Read and replies do not prove task completion. Only a linked mail reply is forwarded here; final turn text stays local."
    ))
}
