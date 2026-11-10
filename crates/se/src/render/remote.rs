use se_core::ops::remote::*;
use se_types::{Read, remote::*};
use std::io::{self, Write};
fn fact<T: serde::Serialize>(v: &Read<T>) -> io::Result<String> {
    Ok(match v {
        Read::Present { value } => return serde_json::to_string(value).map_err(io::Error::other),
        Read::Absent { checked } => format!("absent ({checked})"),
        Read::Unreadable { source, reason, .. } => format!("unreadable {source}: {reason}"),
        Read::Unknown { what } => format!("unknown: {what}"),
    })
}
pub(super) fn list(value: &RemoteListOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Agents (project = workspace; agent = saved worker):")?;
    for row in value.agents.items() {
        writeln!(
            out,
            "  {}/{} ({:?}) project {}/{}; status {}; pending {}",
            row.project_name.escape_debug(),
            row.agent_name.escape_debug(),
            row.provider,
            row.target.project,
            row.target.agent,
            fact(&row.status)?.escape_debug(),
            fact(&row.pending)?.escape_debug()
        )?;
    }
    writeln!(
        out,
        "  complete: {}; omitted: {:?}",
        value.agents.window().complete(),
        value.agents.window().omitted()
    )?;
    if let Some(cursor) = value.agents.next() {
        writeln!(out, "  Continue with --cursor {cursor}")?;
    }
    Ok(())
}
pub(super) fn watch(value: &RemoteWatchOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Watch: durable = committed history; provisional/live = uncommitted observation."
    )?;
    for record in &value.records {
        match record {
            RemoteWatchRecord::Snapshot { view } => list(&view.body, out)?,
            RemoteWatchRecord::Durable {
                target,
                cursor,
                event,
            } => writeln!(
                out,
                "  durable {}/{} cursor {}: {}",
                target.project,
                target.agent,
                cursor,
                serde_json::to_string(event).map_err(io::Error::other)?
            )?,
            RemoteWatchRecord::Provisional {
                target,
                cursor,
                item,
            } => writeln!(
                out,
                "  provisional/live {}/{} item {} cursor {}: {} (complete: {}; omitted UTF-8 bytes: {:?})",
                target.project,
                target.agent,
                item.item_id.escape_debug(),
                cursor,
                item.preview.text.escape_debug(),
                item.preview.complete,
                item.preview.omitted_utf8_bytes
            )?,
            RemoteWatchRecord::Gap {
                target,
                reason,
                reset_required,
            } => writeln!(
                out,
                "  gap {}/{}: {}; reset required: {}",
                target.project,
                target.agent,
                reason.escape_debug(),
                reset_required
            )?,
        }
    }
    writeln!(
        out,
        "  complete: {}; omitted: {:?}; reset required: {}",
        value.complete, value.omitted_records, value.reset_required
    )?;
    writeln!(
        out,
        "  Continue with --cursors '{}' (disconnect leaves agents working)",
        serde_json::to_string(&value.cursors).map_err(io::Error::other)?
    )
}
pub(super) fn send(value: &RemoteSendOutput, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Remote host {:?}, grant {}, principal {}",
        value.attribution.host, value.attribution.grant, value.attribution.principal
    )?;
    writeln!(
        out,
        "  receipt: {}",
        serde_json::to_string(&value.receipt).map_err(io::Error::other)?
    )?;
    writeln!(
        out,
        "  delivery: {:?}; a commit alone does not prove delivered, read or acted",
        value.delivery
    )
}
