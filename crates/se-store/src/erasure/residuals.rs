//! Copies outside the store's custody that a forget leaves behind: provider
//! transcripts, the Atlas index and stores a restore preserved. They are named
//! in the manifest, never claimed as erased.
use super::MAX_RESIDUALS;
use crate::{error::*, *};
use rusqlite::Connection;
use se_types::NativePath;

/// The copy outside the store's custody that a forgotten body leaves behind.
pub(super) fn residual(
    source: Option<Vec<u8>>,
    turn: bool,
    home: &std::path::Path,
) -> StoreResult<Option<ResidualCopy>> {
    Ok(match source {
        Some(path) => serde_json::from_slice::<Option<NativePath>>(&path)
            .map_err(invalid)?
            .map(|location| ResidualCopy {
                custodian: "provider transcript".into(),
                location,
                reason: "The provider wrote this turn to its own transcript; StateEngine does not own or edit that file.".into(),
            }),
        None if !turn => Some(ResidualCopy {
            custodian: "Atlas project index".into(),
            location: NativePath::from_local(home.join("atlas")).map_err(invalid)?,
            reason: "Atlas drops the message record when it next reads history; freed index pages may hold the text until Atlas compacts its database.".into(),
        }),
        None => None,
    })
}
/// The recipient agent's recorded provider transcripts written after the message
/// was sent: the message may have been shown to it there, through its mail
/// prompt or a read tool result.
pub(super) fn recipient_transcripts(
    c: &Connection,
    seq: i64,
    kind: &str,
) -> StoreResult<Option<ResidualCopy>> {
    let mut q = c
        .prepare(match kind {
            // Work mail names its recipients only in its delivery rows.
            "message.work_sent" => {
                "SELECT DISTINCT s.value FROM message_deliveries m JOIN turn_data t ON t.project_id=m.project_id AND t.agent_id=m.recipient_id AND t.event_seq>m.sent_seq JOIN symbols s ON s.id=t.source_path WHERE m.sent_seq=?"
            }
            "message.sent" => {
                "SELECT DISTINCT s.value FROM message_data m JOIN events e ON e.seq=m.event_seq JOIN turn_data t ON t.project_id=e.project_id AND t.agent_id=m.recipient_id AND t.event_seq>m.event_seq JOIN symbols s ON s.id=t.source_path WHERE m.event_seq=?"
            }
            _ => return Ok(None),
        })
        .map_err(sql)?;
    let mut rows = q.query([seq]).map_err(sql)?;
    let mut paths = Vec::new();
    while let Some(row) = rows.next().map_err(sql)? {
        let path: Vec<u8> = row.get(0).map_err(sql)?;
        if let Some(location) =
            serde_json::from_slice::<Option<NativePath>>(&path).map_err(invalid)?
        {
            paths.push(location.to_local().map_err(invalid)?);
        }
    }
    // One entry per message, however many transcripts: their shared folder.
    let Some(first) = paths.first() else {
        return Ok(None);
    };
    let (location, reason) = if paths.len() == 1 {
        (first.clone(), "The recipient agent's conversation after this message may contain it; StateEngine does not own or edit that file.".to_string())
    } else {
        let mut shared = first.clone();
        while !paths.iter().all(|p| p.starts_with(&shared)) && shared.pop() {}
        let count = paths.len();
        if shared.as_os_str().is_empty() {
            // No folder holds them all (for example, two drives): name one.
            (
                first.clone(),
                format!(
                    "The recipient agent's {count} transcript files after this message, including this one, may contain it; StateEngine does not own or edit them."
                ),
            )
        } else {
            (
                shared,
                format!(
                    "The recipient agent's {count} transcript files after this message, under this folder, may contain it; StateEngine does not own or edit them."
                ),
            )
        }
    };
    Ok(Some(ResidualCopy {
        custodian: "recipient's provider transcripts".into(),
        location: NativePath::from_local(location).map_err(invalid)?,
        reason,
    }))
}
/// Every copy outside the store's custody that the observed bodies leave, as planned.
pub(super) fn inventory(
    files: &dyn StateFiles,
    home: &std::path::Path,
    observed: Vec<ResidualCopy>,
) -> StoreResult<Vec<ResidualCopy>> {
    within_cap(
        observed
            .into_iter()
            .chain(preserved_copies(files, home)?)
            .collect(),
    )
}
/// The same copies in any order; the reason counts too, since it states how many files.
pub(super) fn same_inventory(left: &[ResidualCopy], right: &[ResidualCopy]) -> bool {
    let same = |a: &ResidualCopy, b: &ResidualCopy| {
        a.custodian == b.custodian && a.location == b.location && a.reason == b.reason
    };
    left.len() == right.len()
        && left.iter().all(|a| right.iter().any(|b| same(a, b)))
        && right.iter().all(|b| left.iter().any(|a| same(a, b)))
}
/// The commit names at most `MAX_RESIDUALS` copies; refuse in the plan, with a
/// step that works, rather than at --yes.
fn within_cap(residuals: Vec<ResidualCopy>) -> StoreResult<Vec<ResidualCopy>> {
    if residuals.len() > MAX_RESIDUALS {
        let mut error = fail(
            StoreErrorCode::InvalidTransition,
            format!(
                "these events leave {} copies to name, more than one forget can record ({MAX_RESIDUALS})",
                residuals.len()
            ),
        );
        error.remedy.text = "Forget fewer events at a time.".into();
        return Err(error);
    }
    Ok(residuals)
}
/// Stores a restore replaced are kept whole under `preserved/`; a forget leaves
/// them as they are, so the folder is named once rather than claimed as erased.
fn preserved_copies(
    files: &dyn StateFiles,
    home: &std::path::Path,
) -> StoreResult<Option<ResidualCopy>> {
    let directory = home.join("preserved");
    // Absence is read without following links; the listing itself goes
    // through the lease's protected file port.
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(fail(StoreErrorCode::Unreadable, error.to_string())),
        Ok(_) => (),
    }
    let files = files.list_owned(&directory, 4096)?.len();
    if files == 0 {
        return Ok(None);
    }
    Ok(Some(ResidualCopy {
        custodian: "stores replaced by a restore".into(),
        location: NativePath::from_local(directory).map_err(invalid)?,
        reason: format!(
            "A restore kept the store it replaced here, unchanged ({files} files); they may still hold this text. Delete them yourself once you no longer need them."
        ),
    }))
}
