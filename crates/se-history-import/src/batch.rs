//! Pure import bookkeeping on the common event/checkpoint transaction boundary.
use super::node::{NodeContext, event_id};
use se_core::store_error::store_error;
use se_store::*;
use se_types::{NativePath, Read, Result};
pub(super) fn event(cx: &NodeContext, key: &str, body: EventBody<InputText>) -> Result<NewEvent> {
    Ok(NewEvent {
        header: EventHeader {
            event: event_id(&cx.admission.scope, key).map_err(|e| store_error(&e))?,
            scope: cx.admission.scope.clone(),
            actor: cx.admission.actor.clone(),
            session: None,
            origin: cx.store.id.clone(),
            door: Door::Import,
            occurred_at_us: cx.observed_at_us,
            cause: None,
            supersedes: None,
        },
        body,
    })
}
pub(super) fn atomic(
    cx: &NodeContext,
    events: Vec<NewEvent>,
    checkpoint: Option<ImportCheckpoint>,
) -> AtomicBatch {
    AtomicBatch {
        expected_incarnation: cx.store.incarnation,
        admission: cx.admission.clone(),
        request: None,
        events,
        import_checkpoint: checkpoint,
    }
}
pub(super) fn start(cx: &NodeContext, source: NativePath) -> Result<AtomicBatch> {
    let digest = cx.source.sha256.ok_or_else(|| {
        se_core::scope::unreadable(
            "Node source identity",
            "the retained registration source digest is missing",
        )
    })?;
    let e = event(
        cx,
        &format!("import:{:?}:started", cx.import),
        EventBody::ImportStarted {
            import: cx.import,
            source,
            source_sha256: digest,
            format: "node-user-history/v1".into(),
            policy_version: 2,
        },
    )?;
    Ok(atomic(cx, vec![e], None))
}
pub(super) fn progress(
    cx: &NodeContext,
    row: &super::source::Row,
    key: Vec<u8>,
    family: ImportFamily,
    want: Expected,
    counts: ImportCounts,
    events: Vec<NewEvent>,
) -> Result<AtomicBatch> {
    let checkpoint = ImportCheckpoint {
        import: cx.import,
        family,
        source_key: key.clone(),
        source_sha256: row.prefix,
        byte_offset: row.next_offset,
        row_offset: row.next_row,
        expected: want,
    };
    self::checkpoint(cx, checkpoint, counts, events)
}
pub(super) fn checkpoint(
    cx: &NodeContext,
    checkpoint: ImportCheckpoint,
    counts: ImportCounts,
    mut events: Vec<NewEvent>,
) -> Result<AtomicBatch> {
    let revision = match checkpoint.expected {
        Expected::Absent => 0,
        Expected::Revision(r) => r.value.get(),
    };
    events.push(event(
        cx,
        &format!(
            "import:{:?}:{}:{}:{revision}",
            cx.import,
            se_types::hex_lower(&checkpoint.source_key),
            checkpoint.row_offset
        ),
        EventBody::ImportProgress {
            checkpoint: checkpoint.clone(),
            counts,
        },
    )?);
    Ok(atomic(cx, events, Some(checkpoint)))
}
pub(super) fn finish(
    cx: &NodeContext,
    expected: Expected,
    counts: ImportCounts,
    complete: bool,
    omissions: Vec<RecordId>,
) -> Result<AtomicBatch> {
    let revision = match expected {
        Expected::Absent => 0,
        Expected::Revision(r) => r.value.get(),
    };
    let event = event(
        cx,
        &format!("import:{:?}:finished:{revision}", cx.import),
        EventBody::ImportFinished {
            import: cx.import,
            expected,
            counts,
            complete,
            omissions,
        },
    )?;
    Ok(atomic(cx, vec![event], None))
}
pub(super) fn required<T>(read: Read<T>, what: &str) -> Result<T> {
    se_core::scope::require_present(
        read,
        what,
        "Preserve the original import run and source copy, then retry the same source.",
    )
}
