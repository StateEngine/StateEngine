//! A known rolled-back row refusal becomes a durable omission at its range.
use super::*;
pub(in crate::runtime::history_import) fn plan(
    cx: &NodeContext,
    row: &super::super::source::Row,
    state: RowState,
    error: StoreError,
) -> Result<PlannedRow> {
    let RowState {
        family,
        key,
        mut counts,
        want,
        replay,
        kind,
    } = state;
    let units = node::units(kind, row.value.as_ref());
    if replay.is_some() {
        counts.deferred = counts.deferred.checked_sub(units).ok_or_else(|| {
            scope::unreadable("rejected deferred row", "no deferred disposition remains")
        })?;
    } else {
        counts.read = counts
            .read
            .checked_add(units)
            .ok_or_else(|| scope::unreadable("import count", "counter overflow"))?;
    }
    counts.unreadable = counts
        .unreadable
        .checked_add(units)
        .ok_or_else(|| scope::unreadable("import count", "counter overflow"))?;
    let mut events = vec![batch::event(
        cx,
        &format!(
            "import:{:?}:commit-unreadable:{}:{}",
            cx.import,
            se_types::hex_lower(&key),
            row.next_row
        ),
        EventBody::ImportUnreadable {
            import: cx.import,
            family,
            evidence: row.evidence.clone(),
            code: match error.code {
                StoreErrorCode::BodyTooLarge => "source-row-too-large",
                _ => "source-commit-invalid",
            }
            .into(),
        },
    )?];
    let batch = if let Some(mut checkpoint) = replay {
        events.push(marker(cx, row, family, &key, "resolved")?);
        checkpoint.expected = want;
        batch::checkpoint(cx, checkpoint, counts.clone(), events)?
    } else {
        batch::progress(cx, row, key, family, want, counts.clone(), events)?
    };
    Ok(PlannedRow {
        batch,
        counts,
        resume: vec![],
        reason: Some(error.cause),
    })
}
