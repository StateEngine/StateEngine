//! Resuming an interrupted erasure from the manifest its request committed: the
//! same targets and residuals, and the backup generations it pinned.
use super::{MAX_RESIDUALS, event_key};
use crate::{error::*, *};
use rusqlite::{Connection, OptionalExtension};

/// An interrupted erasure is planned again from its own committed manifest, so
/// a retry resumes its cleanup instead of failing on bodies it already removed.
/// Also returns the backup generations the manifest pinned, when it records them.
pub(super) fn unfinished(
    c: &Connection,
    targets: &[EraseTarget],
) -> StoreResult<Option<(ErasurePlan, Option<Vec<RecordId>>)>> {
    let mut erasure: Option<Vec<u8>> = None;
    for target in targets {
        let id: Option<Vec<u8>> = c
            .query_row(
                "SELECT f.erasure_id FROM events e JOIN erased_fields f ON f.event_seq=e.seq WHERE e.event_id=? AND f.field='body'",
                [event_key(c, &target.event)?],
                |r| crate::sql_value::value(r, 0),
            )
            .optional()
            .map_err(sql)?;
        match (id, &erasure) {
            (None, _) => return Ok(None),
            (Some(id), Some(known)) if &id != known => return Ok(None),
            (Some(id), _) => erasure = Some(id),
        }
    }
    let Some(erasure) = erasure else {
        return Ok(None);
    };
    let Some((_, value)) = open_manifest(c, &erasure)? else {
        return Ok(None);
    };
    let field = |v: &serde_json::Value, name: &str| {
        v.get(name)
            .cloned()
            .ok_or_else(|| invalid(format!("erasure manifest lacks {name}")))
    };
    let mut planned = Vec::new();
    for t in field(&value, "targets")?
        .as_array()
        .ok_or_else(|| invalid("erasure manifest targets"))?
    {
        planned.push(EraseTarget {
            event: serde_json::from_value(field(t, "event")?).map_err(invalid)?,
            expected: Revision {
                value: serde_json::from_value(field(t, "expected")?).map_err(invalid)?,
            },
        });
    }
    if planned.len() != targets.len()
        || targets
            .iter()
            .any(|t| !planned.iter().any(|p| p.event == t.event))
    {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "these events belong to an unfinished erasure with a different event list; retry it with exactly its events",
        ));
    }
    let mut residuals = Vec::new();
    for r in field(&value, "residuals")?
        .as_array()
        .ok_or_else(|| invalid("erasure manifest residuals"))?
    {
        residuals.push(ResidualCopy {
            custodian: serde_json::from_value(field(r, "custodian")?).map_err(invalid)?,
            location: serde_json::from_value(field(r, "location")?).map_err(invalid)?,
            reason: serde_json::from_value(field(r, "reason")?).map_err(invalid)?,
        });
    }
    let plan = ErasurePlan {
        id: RecordId::from_bytes(
            erasure
                .try_into()
                .map_err(|_| invalid("erasure ID length"))?,
        )?,
        targets: planned,
        owned_generations: Vec::new(),
        residuals,
        required_bytes: 0,
    };
    Ok(Some((plan, pinned_generations(&value)?)))
}
/// The committed manifest of an erasure that has not completed: its exact bytes,
/// which the completion digest covers, and their parsed form.
pub(super) fn open_manifest(
    c: &Connection,
    erasure: &[u8],
) -> StoreResult<Option<(Vec<u8>, serde_json::Value)>> {
    let manifest: Option<Vec<u8>> = c
        .query_row(
            "SELECT p.content FROM erasures x JOIN payloads p ON p.payload_id=x.manifest_payload WHERE x.erasure_id=? AND x.completed_seq IS NULL",
            [erasure],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    manifest
        .map(|bytes| {
            let value = serde_json::from_slice(&bytes).map_err(invalid)?;
            Ok((bytes, value))
        })
        .transpose()
}
/// The generations a manifest pinned; `None` for one recorded before pinning.
pub(super) fn pinned_generations(
    manifest: &serde_json::Value,
) -> StoreResult<Option<Vec<RecordId>>> {
    let Some(listed) = manifest.get("generations") else {
        return Ok(None);
    };
    let listed = listed
        .as_array()
        .filter(|ids| ids.len() <= MAX_RESIDUALS)
        .ok_or_else(|| invalid("erasure manifest generations"))?;
    listed
        .iter()
        .map(|id| {
            let id: uuid::Uuid = id
                .as_str()
                .ok_or_else(|| invalid("erasure manifest generation"))?
                .parse()
                .map_err(invalid)?;
            RecordId::from_bytes(id.into_bytes())
        })
        .collect::<StoreResult<_>>()
        .map(Some)
}
/// The generations an unfinished erasure replaces: the ones its request pinned, or,
/// for a request recorded before pinning, the indexed copies that end before the
/// request committed. Copies taken after it never held the erased bodies.
pub(super) fn committed_generations(
    c: &Connection,
    erasure: &RecordId,
    pinned: Option<Vec<RecordId>>,
    lease: &dyn RuntimeLease,
    options: &StoreOptions,
    info: &StoreInfo,
) -> StoreResult<Vec<RecordId>> {
    if let Some(pinned) = pinned {
        return Ok(pinned);
    }
    let requested: u64 = c
        .query_row(
            "SELECT requested_seq FROM erasures WHERE erasure_id=?",
            [erasure.as_bytes().to_vec()],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    crate::backup::generations_before(
        lease.files(),
        &options.state_directory,
        info,
        requested,
        super::deadline(options.busy_timeout)?,
    )
}
