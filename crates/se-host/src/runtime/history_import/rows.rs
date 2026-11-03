//! Atomic source ownership and deferred-reference replay planning.
use super::node::{self, NodeContext, NodeKind};
pub(super) mod rejected;
use super::{super::ExecutionContext, batch, read};
use se_core::{scope, store_error::store_error};
use se_store::{import::LegacyTarget, *};
use se_types::{Read, Result};
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
fn materialize(
    snapshot: &mut SqliteSnapshot,
    cx: &NodeContext,
    row: &super::source::Row,
    key: &[u8],
    decoded: node::DecodedRow,
    counts: &mut ImportCounts,
    events: &mut Vec<NewEvent>,
) -> Result<Vec<node::ResumeFact>> {
    let units = decoded.dispositions.as_ref().map(|d| d.read).unwrap_or(1);
    let legacy = snapshot
        .import_legacy(cx.import, decoded.family, &decoded.legacy_id)
        .map_err(|e| store_error(&e))?;
    match legacy {
        Read::Present { value } => {
            if !matches!(value.body,EventBody::LegacyRetained{source,..} if source.sha256==row.evidence.sha256)
            {
                return Err(scope::unreadable(
                    "Node source duplicate",
                    "the same original identity has conflicting bytes",
                ));
            }
            counts.duplicate += units;
        }
        Read::Absent { .. } => {
            let tag = serde_json::to_value(decoded.family)
                .map_err(|e| scope::unreadable("source family", &e.to_string()))?;
            let owner_key = format!(
                "owned:{}:{}",
                tag.as_str()
                    .ok_or_else(|| scope::unreadable("source family", "tag missing"))?,
                decoded.legacy_id
            );
            let owner_id =
                node::event_id(&cx.admission.scope, &owner_key).map_err(|e| store_error(&e))?;
            let existing = match snapshot
                .event(owner_id.clone())
                .map_err(|e| store_error(&e))?
            {
                Read::Present { value } => {
                    if !matches!(&value.body,EventBody::LegacyRetained{source,..} if source.sha256==row.evidence.sha256)
                    {
                        return Err(scope::unreadable(
                            "Node source conflict",
                            "the original scoped source identity has conflicting bytes",
                        ));
                    }
                    true
                }
                Read::Absent { .. } => false,
                Read::Unreadable { source, reason, .. } => {
                    return Err(scope::unreadable(&source, &reason));
                }
                Read::Unknown { what } => {
                    return Err(scope::unreadable("source text owner", &what));
                }
            };
            if existing {
                counts.duplicate += units;
            } else {
                let bytes = decoded
                    .retained
                    .map(|v| {
                        serde_json::to_vec(&v).map_err(|e| {
                            scope::unreadable("retained Node user fields", &e.to_string())
                        })
                    })
                    .transpose()?
                    .map(|bytes| {
                        let sha256 = Sha256::digest(&bytes).into();
                        LegacyBytes { bytes, sha256 }
                    });
                events.push(batch::event(
                    cx,
                    &owner_key,
                    EventBody::LegacyRetained {
                        import: cx.import,
                        family: decoded.family,
                        format_version: 1,
                        legacy_id: owner_key.clone(),
                        mapped_id: decoded.target.clone(),
                        source: row.evidence.clone(),
                        bytes,
                        retained_from: None,
                    },
                )?);
                for mut event in decoded.events {
                    event.header.cause = Some(owner_id.clone());
                    events.push(event);
                }
                if let Some(dispositions) = decoded.dispositions {
                    if dispositions.read != units
                        || dispositions.deferred != 0
                        || dispositions.imported
                            + dispositions.duplicate
                            + dispositions.unreadable
                            + dispositions.dropped_by_policy
                            != units
                    {
                        return Err(scope::unreadable(
                            "profile accounting",
                            "each profile entry needs exactly one disposition",
                        ));
                    }
                    counts.imported += dispositions.imported;
                    counts.duplicate += dispositions.duplicate;
                    counts.unreadable += dispositions.unreadable;
                    counts.dropped_by_policy += dispositions.dropped_by_policy;
                } else if decoded.duplicate {
                    counts.duplicate += units;
                } else if decoded.dropped_by_policy {
                    counts.dropped_by_policy += units;
                } else {
                    counts.imported += units;
                }
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
        }
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => {
            return Err(scope::unreadable("Node source correspondence", &what));
        }
    }
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
    state: RowState,
) -> Result<RowPlan> {
    let RowState {
        kind,
        family,
        key,
        mut counts,
        want,
        replay,
    } = state;
    let units = node::units(kind, row.value.as_ref());
    read::snapshot(context, &cx.admission, |snapshot| {
        if replay.is_some() {
            let pending = format!("pending:{}:{}", se_types::hex_lower(&key), row.next_row);
            match snapshot
                .import_legacy(cx.import, family, &pending)
                .map_err(|e| store_error(&e))?
            {
                Read::Absent { .. } => return Ok(RowPlan::Skipped),
                Read::Present { value } => {
                    if !matches!(value.body,EventBody::LegacyRetained{source,..} if source.path==row.evidence.path && source.incarnation==row.evidence.incarnation && source.offset==row.evidence.offset && source.length==row.evidence.length && source.sha256==row.evidence.sha256)
                    {
                        return Err(scope::unreadable(
                            "staged source changed",
                            "the deferred row no longer matches its original native range",
                        ));
                    }
                }
                Read::Unreadable { source, reason, .. } => {
                    return Err(scope::unreadable(&source, &reason));
                }
                Read::Unknown { what } => return Err(scope::unreadable("staged source", &what)),
            }
            let resolved = format!("resolved:{}:{}", se_types::hex_lower(&key), row.next_row);
            match snapshot
                .import_legacy(cx.import, family, &resolved)
                .map_err(|e| store_error(&e))?
            {
                Read::Present { .. } => return Ok(RowPlan::Skipped),
                Read::Absent { .. } => {}
                Read::Unreadable { source, reason, .. } => {
                    return Err(scope::unreadable(&source, &reason));
                }
                Read::Unknown { what } => return Err(scope::unreadable("resolved source", &what)),
            }
            counts.deferred = counts.deferred.checked_sub(units).ok_or_else(|| {
                scope::unreadable("staged source count", "no staged disposition remains")
            })?;
        } else {
            counts.read = counts
                .read
                .checked_add(units)
                .ok_or_else(|| scope::unreadable("import count", "counter overflow"))?;
        }
        let mut events = Vec::new();
        let mut resume = Vec::new();
        let mut reason = None;
        let disposition = match &row.value {
            Some(value) => node::decode(cx, snapshot, kind, value),
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
                resume = materialize(snapshot, cx, row, &key, decoded, &mut counts, &mut events)?
            }
            Err(error) => {
                if error.code == StoreErrorCode::ReferenceMissing {
                    if replay.is_some() {
                        return Ok(RowPlan::Deferred(error.cause.clone()));
                    }
                    reason = Some(error.cause.clone());
                    events.push(marker(cx, row, family, &key, "pending")?);
                    counts.deferred += units;
                } else {
                    if row.value.is_some()
                        && !matches!(
                            error.code,
                            StoreErrorCode::EventInvalid
                                | StoreErrorCode::BodyTooLarge
                                | StoreErrorCode::NaturalKeyConflict
                                | StoreErrorCode::ScopeMismatch
                        )
                    {
                        return Err(store_error(&error));
                    }
                    reason = Some(error.cause.clone());
                    events.push(batch::event(
                        cx,
                        &format!(
                            "import:{:?}:unreadable:{}:{}",
                            cx.import,
                            se_types::hex_lower(&key),
                            row.next_row
                        ),
                        EventBody::ImportUnreadable {
                            import: cx.import,
                            family,
                            evidence: row.evidence.clone(),
                            code: row
                                .code
                                .unwrap_or(match error.code {
                                    StoreErrorCode::NaturalKeyConflict => {
                                        "source-identity-conflict"
                                    }
                                    StoreErrorCode::ScopeMismatch => "source-scope-mismatch",
                                    StoreErrorCode::BodyTooLarge => "source-row-too-large",
                                    _ => "source-format-unsupported",
                                })
                                .into(),
                        },
                    )?);
                    counts.unreadable += units;
                }
            }
        }
        let batch = if let Some(mut checkpoint) = replay {
            events.push(marker(cx, row, family, &key, "resolved")?);
            checkpoint.expected = want;
            batch::checkpoint(cx, checkpoint, counts.clone(), events)?
        } else {
            batch::progress(cx, row, key, family, want, counts.clone(), events)?
        };
        Ok(RowPlan::Commit(Box::new(PlannedRow {
            batch,
            counts,
            resume,
            reason,
        })))
    })
}
