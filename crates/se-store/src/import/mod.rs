//! User-history accounting on the common atomic append path. Native source
//! custody and owner admission belong to the caller, never to imported bytes.
use crate::{apply::expected, codec, connection::project_id, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
mod apply;
pub(crate) mod counts;
mod wire;
pub(crate) use apply::apply;
pub(crate) use wire::{decode, metadata};

/// The original declaration used RecordId here, which cannot represent the
/// private v8 dictionary keys of imported domain identities. Resolve a closed
/// typed target in the same transaction instead of fabricating a v7 alias.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum LegacyTarget {
    Project(se_types::ProjectId),
    Principal(Actor),
    Session(se_types::SessionId),
    Message(se_types::MessageId),
    Decision(se_types::DecisionId),
    Event(se_types::EventId),
    Record(RecordId),
}
fn target_key(
    c: &Connection,
    target: &LegacyTarget,
    scope: &Scope,
    source: &SourceEvidence,
) -> StoreResult<Vec<u8>> {
    let s = scope_key(c, scope, true)?;
    if let LegacyTarget::Principal(Actor::Agent(agent)) = target
        && se_types::AgentId::from_legacy(agent.to_string()).is_err()
    {
        return exception_key(c, agent, &s, source);
    }
    let (kind, wire, registry) = match target {
        LegacyTarget::Project(id) => ("project", id.as_str(), true),
        LegacyTarget::Principal(actor) => {
            (actor.kind(), actor.wire(), matches!(actor, Actor::Human(_)))
        }
        LegacyTarget::Session(id) => ("session", id.as_str(), false),
        LegacyTarget::Message(id) => ("message", id.as_str(), false),
        LegacyTarget::Decision(id) => ("decision", id.as_str(), false),
        LegacyTarget::Event(id) => ("event", id.as_str(), false),
        LegacyTarget::Record(id) => return Ok(id.as_bytes().to_vec()),
    };
    key(c, kind, wire, if registry { &[0] } else { &s }, true)
}

/// The dictionary is immutable: source-bound exceptions must be inserted with
/// their encoding/provenance, never upgraded after a legacy-shaped allocation.
fn exception_key(
    c: &Connection,
    agent: &se_types::AgentId,
    scope: &[u8],
    source: &SourceEvidence,
) -> StoreResult<Vec<u8>> {
    let id = key(c, "agent", agent.as_str(), scope, false)?;
    let existing: Option<bool> = c
        .query_row(
            "SELECT kind='agent' AND wire_id=? AND scope_key=? AND encoding='registered-exception' AND registration_source IS NOT NULL FROM identities WHERE storage_key=?",
            rusqlite::params![agent.as_str(),scope,id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(valid) = existing {
        if !valid {
            return Err(fail(
                StoreErrorCode::NaturalKeyConflict,
                "source-registered agent collides with an existing scoped identity",
            ));
        }
    } else {
        use sha2::{Digest, Sha256};
        let evidence = Sha256::digest(codec::encode(source)?.as_bytes()).to_vec();
        c.execute(
            "INSERT INTO identities(storage_key,kind,wire_id,scope_key,encoding,registration_source) VALUES(?,'agent',?,?,'registered-exception',?)",
            rusqlite::params![id,agent.as_str(),scope,evidence],
        ).map_err(sql)?;
    }
    Ok(id)
}

fn family(value: ImportFamily) -> StoreResult<String> {
    let value = serde_json::to_value(value).map_err(invalid)?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("import family tag"))
}
fn counts(value: &ImportCounts) -> StoreResult<()> {
    let accounted = value
        .imported
        .checked_add(value.duplicate)
        .and_then(|v| v.checked_add(value.unreadable))
        .and_then(|v| v.checked_add(value.dropped_by_policy))
        .and_then(|v| v.checked_add(value.deferred));
    if accounted != Some(value.read) {
        return Err(invalid(
            "each imported source row needs exactly one disposition",
        ));
    }
    Ok(())
}
/// Only the owner-admitted adapter can carry historical actors and ended
/// sessions. The closed allowlist excludes every live capability/custody fact.
pub(crate) fn validate_batch(batch: &AtomicBatch) -> StoreResult<bool> {
    if !batch.events.iter().any(|e| e.header.door == Door::Import) {
        return Ok(false);
    }
    if !matches!(batch.admission.actor, Actor::Human(_)) || batch.admission.session.is_some() {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "user-history import requires owner admission",
        ));
    }
    use EventBody::*;
    for event in &batch.events {
        if event.header.door != Door::Import
            || !matches!(
                event.body,
                ImportStarted { .. }
                    | ImportProgress { .. }
                    | ImportFinished { .. }
                    | ImportUnreadable { .. }
                    | LegacyRetained { .. }
                    | ProjectRegistered { .. }
                    | ProjectUpdated { .. }
                    | ProjectRemoved { .. }
                    | PrincipalRegistered { .. }
                    | PrincipalRenamed { .. }
                    | AliasImported { .. }
                    | ProfileSaved { .. }
                    | MessageSent { .. }
                    | MessageDelivered { .. }
                    | MessageRead { .. }
                    | MessageDismissed { .. }
                    | MessageSuperseded { .. }
                    | DecisionProposed { .. }
                    | DecisionRatified { .. }
                    | DecisionRejected { .. }
                    | DecisionRetracted { .. }
                    | DecisionSuperseded { .. }
                    | WorkingStateSet { .. }
                    | SessionPrepared { .. }
                    | SessionEnded { .. }
                    | SessionTurn { .. }
                    | CaptureSource { .. }
                    | CaptureProgress { .. }
                    | CaptureFailed { .. }
                    | CaptureVerified { .. }
            )
        {
            return Err(invalid(
                "import can retain user history, never credentials, grants, live sessions or process authority",
            ));
        }
        if let SessionPrepared { session, .. } = &event.body
            && !batch
                .events
                .iter()
                .any(|e| matches!(&e.body,SessionEnded{session:ended,..} if ended==session))
        {
            return Err(invalid(
                "an imported conversation must end in the same atomic operation",
            ));
        }
        if matches!(event.body, PrincipalRegistered { .. })
            && batch.admission.scope == Scope::Registry
        {
            return Err(invalid(
                "historical owner identities are correspondence data, not registry owner proof",
            ));
        }
    }
    Ok(true)
}
pub(crate) fn validate_checkpoint(batch: &AtomicBatch) -> StoreResult<()> {
    let progress: Vec<_> = batch
        .events
        .iter()
        .filter_map(|event| match &event.body {
            EventBody::ImportProgress { checkpoint, .. } => Some(checkpoint),
            _ => None,
        })
        .collect();
    match (&batch.import_checkpoint, progress.as_slice()) {
        (None, []) => Ok(()),
        (Some(want), [found]) if codec::encode(want)? == codec::encode(found)? => Ok(()),
        _ => Err(invalid(
            "one import progress event and its identical atomic checkpoint are required together",
        )),
    }
}
pub(crate) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    use EventBody::*;
    match &e.body {
        ImportStarted { import, .. } => expected(
            c,
            "import_runs",
            "import_id=?",
            &[import.as_bytes()],
            Expected::Absent,
        ),
        ImportFinished {
            import,
            expected: want,
            ..
        } => expected(c, "import_runs", "import_id=?", &[import.as_bytes()], *want),
        ImportProgress { checkpoint: p, .. } => expected(
            c,
            "import_progress",
            "import_id=? AND family=? AND source_key=?",
            &[p.import.as_bytes(), &family(p.family)?, &p.source_key],
            p.expected,
        ),
        ImportUnreadable { .. } | LegacyRetained { .. } | AliasImported { .. } => Ok(1),
        _ => Err(invalid("import revision dispatch")),
    }
}

/// Import-specific finite reads; ordinary Snapshot implementers do not grow
/// an adapter-specific wire protocol.
pub trait ImportSnapshot: Snapshot {
    fn import_root_claim(
        &mut self,
        canonical_key: &[u8],
    ) -> StoreResult<Option<se_types::ProjectId>>;
    fn import_prior(&mut self, key: &str) -> StoreResult<Option<(se_types::DecisionId, Revision)>>;
}
