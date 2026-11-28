//! One committed record per chunk bounds transient bodies and preserves source order.
use super::*;
use se_core::ops::transcript::tool::ObservedPath;
use se_store::{
    EventKind, HistoryDirection, HistoryQuery, ReadBudget, StorePosition, TranscriptFilter,
};
use std::{num::NonZeroU32, time::Duration};

/// Only the host's admitted owner maintenance read feeds an index. Ordinary
/// viewers use hit/body and cannot populate a cache from a partial private view.
pub fn next<R: Snapshot>(
    read: &mut R,
    admission: &Admission,
    after: Option<se_types::EventId>,
) -> Result<Option<RecordFeed>> {
    next_scoped(read, admission, after, None)
}
/// Host-only path binding uses its retained registered root, never ambient cwd.
pub fn next_with_paths<R: Snapshot>(
    read: &mut R,
    admission: &Admission,
    after: Option<se_types::EventId>,
    resolve: &mut dyn FnMut(&ObservedPath) -> Result<Option<RelativePath>>,
) -> Result<Option<RecordFeed>> {
    next_scoped(read, admission, after, Some(resolve))
}
type PathResolver<'a> = Option<&'a mut dyn FnMut(&ObservedPath) -> Result<Option<RelativePath>>>;
fn next_scoped<R: Snapshot>(
    read: &mut R,
    admission: &Admission,
    after: Option<se_types::EventId>,
    resolve: PathResolver<'_>,
) -> Result<Option<RecordFeed>> {
    if !matches!(admission.actor, Actor::Human(_)) {
        return Err(SeError::invalid(
            "Atlas record feed",
            "an admitted project-owner maintenance snapshot",
        ));
    }
    let project = scope::project(admission)?;
    let since = feed_cursor(read, &after, &project)?;
    let kinds = feed_kinds(&resolve);
    let page = feed_page(read, kinds, since)?;
    let complete = page.window().complete();
    let mut events = page.into_items();
    if events.is_empty() {
        if complete {
            return Ok(None);
        }
        return Err(scope::unreadable(
            "Atlas record feed",
            "history stopped without a committed event or a complete range",
        ));
    }
    let event = events.remove(0);
    let through = event.header.event.clone();
    if event.header.scope != Scope::Project(project.clone()) {
        return Err(scope::unreadable(
            "Atlas feed event",
            "event is outside the admitted project",
        ));
    }
    let mut changes = Vec::with_capacity(2);
    let key = feed_change(read, &event, &project, &through, resolve, &mut changes)?;
    if let Some((kind, key)) = key {
        let pointer = RecordPointer {
            key,
            kind,
            source_event: through.clone(),
        };
        feed_upsert(read, admission, &project, &event, pointer, &mut changes)?;
    }
    let feed = RecordFeed {
        project,
        after,
        through,
        changes,
        complete,
    };
    feed.validate()?;
    Ok(Some(feed))
}

fn feed_cursor<R: Snapshot>(
    read: &mut R,
    after: &Option<se_types::EventId>,
    project: &ProjectId,
) -> Result<Option<StorePosition>> {
    if let Some(after) = after {
        let value = scope::require_present(
            read.event(after.clone()).map_err(|e| store_error(&e))?,
            "Atlas feed cursor",
            "Rebuild this project's record index from the retained authoritative history.",
        )?;
        if value.header.scope != Scope::Project(project.clone()) {
            return Err(scope::unreadable(
                "Atlas feed cursor",
                "event belongs to another project",
            ));
        }
        Ok(Some(value.position))
    } else {
        Ok(None)
    }
}
fn feed_kinds(resolve: &PathResolver<'_>) -> Vec<EventKind> {
    let mut kinds = vec![
        EventKind::MessageSent,
        EventKind::WorkMessageSent,
        EventKind::MessageErased,
        EventKind::WorkingStateSet,
        EventKind::DecisionProposed,
        EventKind::DecisionRatified,
        EventKind::DecisionRejected,
        EventKind::DecisionRetracted,
        EventKind::DecisionSuperseded,
        EventKind::SessionTurnPublished,
        EventKind::TurnErased,
    ];
    if resolve.is_some() {
        kinds.push(EventKind::SessionTurn);
    }
    kinds
}
fn feed_page<R: Snapshot>(
    read: &mut R,
    kinds: Vec<EventKind>,
    since: Option<StorePosition>,
) -> Result<se_types::Page<StoredEvent>> {
    read.history(
        HistoryQuery {
            agent: None,
            session: None,
            kinds,
            families: vec![],
            transcript: TranscriptFilter::Metadata,
            since,
            direction: HistoryDirection::OldestFirst,
        },
        ReadBudget {
            page: se_types::PageRequest {
                after: None,
                limit: NonZeroU32::new(1)
                    .ok_or_else(|| SeError::invalid("feed limit", "positive"))?,
                max_bytes: NonZeroU32::new(131072)
                    .ok_or_else(|| SeError::invalid("feed bytes", "positive"))?,
            },
            deadline: Duration::from_millis(100),
        },
    )
    .map_err(|e| store_error(&e))
}
fn feed_edit_change<R: Snapshot>(
    read: &mut R,
    event: &StoredEvent,
    project: &ProjectId,
    through: &se_types::EventId,
    mut resolve: PathResolver<'_>,
    changes: &mut Vec<RecordFeedChange>,
) -> Result<()> {
    let tool = match super::captured::successful(event)? {
        super::captured::Captured::Match(tool) => tool,
        super::captured::Captured::Skip => return Ok(()),
        super::captured::Captured::Oversized(_) => {
            changes.push(RecordFeedChange::Skipped(project.clone()));
            return Ok(());
        }
    };
    tool.validate_source(read, project)?;
    let mut mentions = Vec::new();
    if let Some(resolve) = &mut resolve {
        for path in tool.paths() {
            if let Some(path) = resolve(path)? {
                let target = MentionTarget::File(path);
                if !mentions.contains(&target) {
                    mentions.push(target);
                }
            }
        }
    }
    if !mentions.is_empty() {
        let record = FeedRecord {
            pointer: RecordPointer {
                key: tool.key()?,
                kind: RecordKind::Edit,
                source_event: through.clone(),
            },
            project: project.clone(),
            actor: Some(tool.actor()),
            occurred_unix_ms: receipt::event_time(event) / 1000,
            title: tool.description(),
            body: tool.description(),
            body_truncated: false,
            visibility: audience(event),
            mentions: bound_mentions(mentions),
        };
        record.validate()?;
        changes.push(RecordFeedChange::Upsert(record));
    }
    Ok(())
}
fn feed_change<R: Snapshot>(
    read: &mut R,
    event: &StoredEvent,
    project: &ProjectId,
    through: &se_types::EventId,
    resolve: PathResolver<'_>,
    changes: &mut Vec<RecordFeedChange>,
) -> Result<Option<(RecordKind, RecordKey)>> {
    Ok(match &event.body {
        EventBody::SessionTurn { .. } => {
            feed_edit_change(read, event, project, through, resolve, changes)?;
            None
        }
        EventBody::MessageSent {
            message,
            body: StoredText::Erased { .. },
            ..
        }
        | EventBody::WorkMessageSent {
            message,
            body: StoredText::Erased { .. },
            ..
        } => {
            changes.push(RecordFeedChange::Remove {
                project: project.clone(),
                key: RecordKey::new(message.as_str())?,
            });
            None
        }
        EventBody::MessageSent { message, .. } | EventBody::WorkMessageSent { message, .. } => {
            Some((RecordKind::Message, RecordKey::new(message.as_str())?))
        }
        EventBody::WorkingStateSet { agent, .. } => {
            Some((RecordKind::Working, RecordKey::new(agent.as_str())?))
        }
        EventBody::SessionTurnPublished {
            body: Some(StoredText::Erased { .. }),
            ..
        } => {
            changes.push(RecordFeedChange::Remove {
                project: project.clone(),
                key: super::published::key(&event.header.event)?,
            });
            None
        }
        EventBody::SessionTurnPublished { .. } => super::published::document(event)?
            .map(|_| super::published::key(&event.header.event))
            .transpose()?
            .map(|key| (RecordKind::Turn, key)),
        EventBody::TurnErased { target, .. } => {
            let source = scope::require_present(
                read.event(target.clone()).map_err(|e| store_error(&e))?,
                "erased turn identity",
                "Restore the immutable turn metadata before completing Atlas privacy maintenance.",
            )?;
            // A captured turn's edit record reads as stale once its text is gone.
            if matches!(source.body, EventBody::SessionTurnPublished { .. }) {
                changes.push(RecordFeedChange::Remove {
                    project: project.clone(),
                    key: super::published::key(target)?,
                });
            }
            None
        }
        EventBody::DecisionProposed { decision, .. }
        | EventBody::DecisionRatified { decision, .. }
        | EventBody::DecisionRejected { decision, .. }
        | EventBody::DecisionRetracted { decision, .. } => {
            changes.push(RecordFeedChange::Remove {
                project: project.clone(),
                key: RecordKey::new(decision.as_str())?,
            });
            None
        }
        EventBody::DecisionSuperseded { prior, .. } => {
            changes.push(RecordFeedChange::Remove {
                project: project.clone(),
                key: RecordKey::new(prior.as_str())?,
            });
            None
        }
        EventBody::MessageErased { target, .. } => {
            let source = scope::require_present(
                read.event(target.clone()).map_err(|e| store_error(&e))?,
                "erased message identity",
                "Restore the immutable message metadata before completing Atlas privacy maintenance.",
            )?;
            let (EventBody::MessageSent { message, .. }
            | EventBody::WorkMessageSent { message, .. }) = source.body
            else {
                return Err(scope::unreadable(
                    "erased message identity",
                    "target is not a message",
                ));
            };
            changes.push(RecordFeedChange::Remove {
                project: project.clone(),
                key: RecordKey::new(message.as_str())?,
            });
            None
        }
        _ => {
            return Err(scope::unreadable(
                "Atlas feed event",
                "history returned an unrequested record kind",
            ));
        }
    })
}
fn feed_upsert<R: Snapshot>(
    read: &mut R,
    admission: &Admission,
    project: &ProjectId,
    event: &StoredEvent,
    pointer: RecordPointer,
    changes: &mut Vec<RecordFeedChange>,
) -> Result<()> {
    let viewer = match &admission.actor {
        Actor::Human(id) => AtlasPrincipal::Human(id.clone()),
        _ => {
            return Err(SeError::invalid(
                "Atlas feed owner",
                "a human maintenance principal",
            ));
        }
    };
    let document = RecordAccess::new(read, admission).load(project, &viewer, &pointer)?;
    match document {
        Read::Present { value } => {
            let mut body = value.body;
            let truncated = body.len() > 65536;
            body.truncate(body.floor_char_boundary(65536));
            let mut record = FeedRecord {
                pointer,
                project: project.clone(),
                actor: value.actor,
                occurred_unix_ms: value.at,
                title: excerpt::line(&body, None),
                visibility: audience(event),
                body,
                body_truncated: truncated,
                mentions: bound_mentions(explicit_mentions(read, event, project)?),
            };
            record.title.truncate(record.title.floor_char_boundary(160));
            if let Some(actor) = record.actor.as_mut() {
                actor.name.truncate(actor.name.floor_char_boundary(160));
            }
            record.validate()?;
            changes.push(RecordFeedChange::Upsert(record));
        }
        // Historical revisions already replaced by a later committed record
        // are skipped. They never remove a newer cache entry on replay.
        Read::Absent { .. } => (),
        Read::Unknown { what } => return Err(scope::unreadable("Atlas record feed", &what)),
        Read::Unreadable { source, reason, .. } => {
            return Err(scope::unreadable(&source, &reason));
        }
    }
    Ok(())
}

fn explicit_mentions<R: Snapshot>(
    read: &mut R,
    event: &StoredEvent,
    project: &ProjectId,
) -> Result<Vec<MentionTarget>> {
    let mut output = Vec::new();
    let refs = match &event.body {
        EventBody::MessageSent { reply_to, refs, .. }
        | EventBody::WorkMessageSent { reply_to, refs, .. } => {
            if let Some(message) = reply_to {
                output.push(MentionTarget::Record(RecordKey::new(message.as_str())?));
            }
            refs.as_slice()
        }
        EventBody::SessionTurnPublished { .. } => {
            if let Some(published) = super::published::document(event)? {
                output.extend(published.paths.into_iter().map(MentionTarget::File));
                output.dedup();
            }
            return Ok(output);
        }
        _ => return Ok(output),
    };
    for id in refs {
        let referenced = match visible(read.event(id.clone()))? {
            Read::Present { value } => value,
            Read::Absent { .. } => continue,
            Read::Unknown { what } => {
                return Err(scope::unreadable("Atlas explicit reference", &what));
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
        };
        if referenced.header.scope != Scope::Project(project.clone()) {
            continue;
        }
        let key = match referenced.body {
            EventBody::MessageSent { message, .. } | EventBody::WorkMessageSent { message, .. } => {
                Some(message.to_string())
            }
            EventBody::WorkingStateSet { agent, .. } => Some(agent.to_string()),
            _ => None,
        };
        if let Some(key) = key {
            let mention = MentionTarget::Record(RecordKey::new(key)?);
            if !output.contains(&mention) {
                output.push(mention);
            }
        }
    }
    Ok(output)
}

fn bound_mentions(mut out: Vec<MentionTarget>) -> Vec<MentionTarget> {
    while out.len() > 256 || serde_json::to_vec(&out).map_or(usize::MAX, |v| v.len()) > 32768 {
        out.pop();
    }
    out
}

// These hints mirror the store's SelfOnly event visibility. Ordinary record
// readers still recheck core authority; hooks use hints only at a current fence.
fn audience(event: &StoredEvent) -> RecordVisibility {
    let mut keys = Vec::new();
    if let Actor::Agent(agent) = &event.header.actor {
        keys.push(AtlasPrincipal::Agent(agent.clone()));
    }
    match &event.body {
        EventBody::MessageSent {
            recipient: Actor::Agent(agent),
            ..
        }
        | EventBody::WorkingStateSet { agent, .. }
        | EventBody::SessionTurn { agent, .. } => keys.push(AtlasPrincipal::Agent(agent.clone())),
        EventBody::SessionTurnPublished { turn, .. } => {
            keys.push(AtlasPrincipal::Agent(turn.agent.clone()));
        }
        EventBody::WorkMessageSent { work, .. } => {
            keys.extend(work.addressees.iter().cloned().map(AtlasPrincipal::Agent));
        }
        _ => (),
    }
    keys.sort();
    keys.dedup();
    RecordVisibility::Restricted {
        audience: (keys.len() <= 32).then_some(keys),
    }
}
