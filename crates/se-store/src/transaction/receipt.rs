//! Retained immutable membership and primary-event stamps.
use super::*;
pub(crate) fn stamp(writer: &WriterMode) -> (&'static str, Option<u64>) {
    match writer.kind() {
        WriterKind::Direct => ("direct", None),
        WriterKind::Host { generation } => ("host", Some(generation)),
    }
}
pub(crate) fn door(d: Door) -> &'static str {
    match d {
        Door::Cli => "cli",
        Door::Mcp => "mcp",
        Door::Hook => "hook",
        Door::Host => "host",
        Door::Import => "import",
    }
}
pub(crate) fn receipt(
    c: &Connection,
    op: &[u8],
    info: &StoreInfo,
    request_key: Option<se_types::IdempotencyKey>,
) -> StoreResult<CommitReceipt> {
    let mut q = c
        .prepare("SELECT event_seq FROM operation_events WHERE operation_id=? ORDER BY ordinal")
        .map_err(sql)?;
    let seqs = q
        .query_map([op], |r| crate::sql_value::value::<i64>(r, 0))
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    if seqs.is_empty() || seqs.len() > 64 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "operation membership absent or exceeds bound",
        ));
    }
    receipt_members(c, &seqs, info, request_key)
}
pub(super) fn receipt_members(
    c: &Connection,
    seqs: &[i64],
    info: &StoreInfo,
    request_key: Option<se_types::IdempotencyKey>,
) -> StoreResult<CommitReceipt> {
    let events = seqs
        .iter()
        .map(|s| crate::read::load_event(c, *s, info))
        .collect::<StoreResult<Vec<_>>>()?;
    let primary = &events[0];
    let mut wakes = Vec::new();
    for e in &events {
        if let (
            Scope::Project(p),
            EventBody::MessageSent {
                recipient,
                quiet: false,
                ..
            },
        ) = (&e.header.scope, &e.body)
        {
            wakes.push(Wake {
                project: p.clone(),
                principal: recipient.clone(),
                through: e.position.clone(),
            })
        }
        if let (
            Scope::Project(project),
            EventBody::WorkMessageSent {
                work, quiet: false, ..
            },
        ) = (&e.header.scope, &e.body)
        {
            for agent in &work.addressees {
                wakes.push(Wake {
                    project: project.clone(),
                    principal: Actor::Agent(agent.clone()),
                    through: e.position.clone(),
                });
            }
        }
    }
    Ok(CommitReceipt {
        write_timings: None,
        maintenance_pending: false,
        maintenance_failed: false,
        request_key,
        state: CommitState::Committed,
        primary_event: primary.header.event.clone(),
        writer: primary.writer.clone(),
        durability: primary.durability,
        wakes,
        first: events
            .iter()
            .min_by_key(|e| e.position.sequence())
            .ok_or_else(|| invalid("empty membership"))?
            .position
            .clone(),
        last: events
            .iter()
            .max_by_key(|e| e.position.sequence())
            .ok_or_else(|| invalid("empty membership"))?
            .position
            .clone(),
        events: events.into_iter().map(|e| e.header.event).collect(),
    })
}
