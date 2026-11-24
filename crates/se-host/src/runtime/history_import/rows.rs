//! Atomic source ownership and deferred-reference replay planning.
use super::node::{self, NodeContext, NodeKind};
pub(super) mod rejected;
use super::{super::ExecutionContext, batch, read};
use se_core::{scope, store_error::store_error};
use se_store::{import::LegacyTarget, *};
use se_types::Result;
use sha2::{Digest, Sha256};
pub(super) enum RowPlan {
    Skipped,
    Deferred(String),
    Commit(Box<PlannedRow>),
}
pub(super) struct PlannedRow {
    pub batch: AtomicBatch,
    pub counts: ImportCounts,
    pub resume: Vec<node::ResumeFact>,
    pub reason: Option<String>,
}
fn same_retained(
    body: &EventBody<StoredText>,
    row: &super::source::Row,
    target: &LegacyTarget,
) -> bool {
    matches!(body, EventBody::LegacyRetained { source, mapped_id, .. } if source.sha256 == row.evidence.sha256 && mapped_id == target)
}
fn apply_dispositions(
    decoded: &node::DecodedRow,
    units: u64,
    counts: &mut ImportCounts,
) -> Result<()> {
    if let Some(d) = &decoded.dispositions {
        if d.read != units
            || d.deferred != 0
            || d.imported + d.duplicate + d.unreadable + d.dropped_by_policy != units
        {
            return Err(scope::unreadable(
                "profile accounting",
                "each profile entry needs exactly one disposition",
            ));
        }
        counts.imported += d.imported;
        counts.duplicate += d.duplicate;
        counts.unreadable += d.unreadable;
        counts.dropped_by_policy += d.dropped_by_policy;
    } else if decoded.duplicate {
        counts.duplicate += units;
    } else if decoded.dropped_by_policy {
        counts.dropped_by_policy += units;
    } else {
        counts.imported += units;
    }
    Ok(())
}
fn record_new_owner(
    cx: &NodeContext,
    row: &super::source::Row,
    owner_key: &str,
    owner_id: &se_types::EventId,
    decoded: &mut node::DecodedRow,
    counts: &mut ImportCounts,
    events: &mut Vec<NewEvent>,
) -> Result<()> {
    let units = decoded.dispositions.as_ref().map(|d| d.read).unwrap_or(1);
    if decoded
        .retained
        .as_ref()
        .and_then(|v| v.get("import_note"))
        .and_then(serde_json::Value::as_str)
        == Some("historical-human-name-disambiguated")
    {
        *counts
            .notes
            .entry("historical-human-name-disambiguated".into())
            .or_default() += 1;
    }
    let bytes = decoded
        .retained
        .take()
        .map(|v| {
            serde_json::to_vec(&v)
                .map_err(|e| scope::unreadable("retained Node user fields", &e.to_string()))
        })
        .transpose()?
        .map(|bytes| LegacyBytes {
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        });
    events.push(batch::event(
        cx,
        owner_key,
        EventBody::LegacyRetained {
            import: cx.import,
            family: decoded.family,
            format_version: 1,
            legacy_id: owner_key.to_owned(),
            mapped_id: decoded.target.clone(),
            source: row.evidence.clone(),
            bytes,
            retained_from: None,
        },
    )?);
    for mut event in std::mem::take(&mut decoded.events) {
        event.header.cause = Some(owner_id.clone());
        events.push(event);
    }
    apply_dispositions(decoded, units, counts)
}
fn materialize(
    snapshot: &mut SqliteSnapshot,
    cx: &NodeContext,
    row: &super::source::Row,
    key: &[u8],
    mut decoded: node::DecodedRow,
    counts: &mut ImportCounts,
    events: &mut Vec<NewEvent>,
) -> Result<Vec<node::ResumeFact>> {
    let units = decoded.dispositions.as_ref().map(|d| d.read).unwrap_or(1);
    if let Some(value) = crate::read_optional(
        snapshot
            .import_legacy(cx.import, decoded.family, &decoded.legacy_id)
            .map_err(|e| store_error(&e))?,
        "Node source correspondence",
    )? {
        if !same_retained(&value.body, row, &decoded.target) {
            return Err(scope::unreadable(
                "Node source duplicate",
                "the same original identity has conflicting bytes or identity correspondence",
            ));
        }
        counts.duplicate += units;
        return Ok(decoded.resume);
    }
    let tag = serde_json::to_value(decoded.family)
        .map_err(|e| scope::unreadable("source family", &e.to_string()))?;
    let owner_key = format!(
        "owned:{}:{}",
        tag.as_str()
            .ok_or_else(|| scope::unreadable("source family", "tag missing"))?,
        decoded.legacy_id
    );
    let owner_id = node::event_id(&cx.admission.scope, &owner_key).map_err(|e| store_error(&e))?;
    if let Some(value) = crate::read_optional(
        snapshot
            .event(owner_id.clone())
            .map_err(|e| store_error(&e))?,
        "source text owner",
    )? {
        if !same_retained(&value.body, row, &decoded.target) {
            return Err(scope::unreadable(
                "Node source conflict",
                "the original scoped source identity has conflicting bytes or identity correspondence",
            ));
        }
        counts.duplicate += units;
    } else {
        record_new_owner(cx, row, &owner_key, &owner_id, &mut decoded, counts, events)?;
    }
    events.push(batch::event(
        cx,
        &format!(
            "import:{:?}:legacy:{}:{}",
            cx.import,
            se_types::hex_lower(key),
            row.next_row
        ),
        EventBody::LegacyRetained {
            import: cx.import,
            family: decoded.family,
            format_version: 1,
            legacy_id: decoded.legacy_id,
            mapped_id: decoded.target,
            source: row.evidence.clone(),
            bytes: None,
            retained_from: Some(owner_id),
        },
    )?);
    Ok(decoded.resume)
}
fn marker(
    cx: &NodeContext,
    row: &super::source::Row,
    family: ImportFamily,
    key: &[u8],
    kind: &str,
) -> Result<NewEvent> {
    let name = format!("{kind}:{}:{}", se_types::hex_lower(key), row.next_row);
    batch::event(
        cx,
        &format!("import:{:?}:{name}", cx.import),
        EventBody::LegacyRetained {
            import: cx.import,
            family,
            format_version: 1,
            legacy_id: name.clone(),
            mapped_id: LegacyTarget::Record(
                node::record_id("pending", &name).map_err(|e| store_error(&e))?,
            ),
            source: row.evidence.clone(),
            bytes: None,
            retained_from: None,
        },
    )
}
fn check_replay_markers(
    snapshot: &mut SqliteSnapshot,
    cx: &NodeContext,
    row: &super::source::Row,
    state: &mut RowState,
    units: u64,
) -> Result<bool> {
    let hex = se_types::hex_lower(&state.key);
    let Some(value) = crate::read_optional(
        snapshot
            .import_legacy(
                cx.import,
                state.family,
                &format!("pending:{hex}:{}", row.next_row),
            )
            .map_err(|e| store_error(&e))?,
        "staged source",
    )?
    else {
        return Ok(true);
    };
    if !matches!(value.body, EventBody::LegacyRetained { source, .. } if source.path == row.evidence.path && source.incarnation == row.evidence.incarnation && source.offset == row.evidence.offset && source.length == row.evidence.length && source.sha256 == row.evidence.sha256)
    {
        return Err(scope::unreadable(
            "staged source changed",
            "the deferred row no longer matches its original native range",
        ));
    }
    if crate::read_optional(
        snapshot
            .import_legacy(
                cx.import,
                state.family,
                &format!("resolved:{hex}:{}", row.next_row),
            )
            .map_err(|e| store_error(&e))?,
        "resolved source",
    )?
    .is_some()
    {
        return Ok(true);
    }
    state.counts.deferred =
        state.counts.deferred.checked_sub(units).ok_or_else(|| {
            scope::unreadable("staged source count", "no staged disposition remains")
        })?;
    Ok(false)
}
fn record_unreadable(
    cx: &NodeContext,
    row: &super::source::Row,
    state: &mut RowState,
    error: &StoreError,
    units: u64,
    events: &mut Vec<NewEvent>,
) -> Result<String> {
    if row.value.is_some()
        && !matches!(
            error.code,
            StoreErrorCode::EventInvalid
                | StoreErrorCode::BodyTooLarge
                | StoreErrorCode::NaturalKeyConflict
                | StoreErrorCode::ScopeMismatch
        )
    {
        return Err(store_error(error));
    }
    let code = row
        .code
        .unwrap_or(match error.code {
            StoreErrorCode::NaturalKeyConflict => "source-identity-conflict",
            StoreErrorCode::ScopeMismatch => "source-scope-mismatch",
            StoreErrorCode::BodyTooLarge => "source-row-too-large",
            _ => "source-format-unsupported",
        })
        .into();
    events.push(batch::event(
        cx,
        &format!(
            "import:{:?}:unreadable:{}:{}",
            cx.import,
            se_types::hex_lower(&state.key),
            row.next_row
        ),
        EventBody::ImportUnreadable {
            import: cx.import,
            family: state.family,
            evidence: row.evidence.clone(),
            code,
        },
    )?);
    state.counts.unreadable += units;
    Ok(error.cause.clone())
}
#[derive(Clone)]
pub(super) struct RowState {
    pub kind: NodeKind,
    pub family: ImportFamily,
    pub key: Vec<u8>,
    pub counts: ImportCounts,
    pub want: Expected,
    pub replay: Option<ImportCheckpoint>,
}
pub(super) fn plan(
    context: &ExecutionContext,
    cx: &NodeContext,
    row: &super::source::Row,
    mut state: RowState,
) -> Result<RowPlan> {
    let units = node::units(state.kind, row.value.as_ref());
    read::snapshot(context, &cx.admission, |snapshot| {
        if state.replay.is_some() {
            if check_replay_markers(snapshot, cx, row, &mut state, units)? {
                return Ok(RowPlan::Skipped);
            }
        } else {
            state.counts.read = state
                .counts
                .read
                .checked_add(units)
                .ok_or_else(|| scope::unreadable("import count", "counter overflow"))?;
        }
        let (mut events, mut resume, mut reason) = (Vec::new(), Vec::new(), None);
        let disposition = match &row.value {
            Some(value) => node::decode(cx, snapshot, state.kind, value),
            None => Err(Box::new(StoreError {
                code: StoreErrorCode::Unreadable,
                cause: row.code.unwrap_or("source-undecodable").into(),
                detail: StoreDetail::None,
                remedy: se_types::Remedy {
                    text: "Preserve the original source and inspect this exact range.".into(),
                    command: None,
                },
                retry: se_types::Retry::Never,
            })),
        };
        match disposition {
            Ok(decoded) => {
                resume = materialize(
                    snapshot,
                    cx,
                    row,
                    &state.key,
                    decoded,
                    &mut state.counts,
                    &mut events,
                )?
            }
            Err(error) if error.code == StoreErrorCode::ReferenceMissing => {
                if state.replay.is_some() {
                    return Ok(RowPlan::Deferred(error.cause.clone()));
                }
                reason = Some(error.cause.clone());
                events.push(marker(cx, row, state.family, &state.key, "pending")?);
                state.counts.deferred += units;
            }
            Err(error) => {
                reason = Some(record_unreadable(
                    cx,
                    row,
                    &mut state,
                    &error,
                    units,
                    &mut events,
                )?)
            }
        }
        let batch = if let Some(mut checkpoint) = state.replay {
            events.push(marker(cx, row, state.family, &state.key, "resolved")?);
            checkpoint.expected = state.want;
            batch::checkpoint(cx, checkpoint, state.counts.clone(), events)?
        } else {
            batch::progress(
                cx,
                row,
                state.key,
                state.family,
                state.want,
                state.counts.clone(),
                events,
            )?
        };
        Ok(RowPlan::Commit(Box::new(PlannedRow {
            batch,
            counts: state.counts,
            resume,
            reason,
        })))
    })
}
