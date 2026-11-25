//! Fold core's committed record feed into `records`, `mentions`, and `touches`.
//! Bodies are tokenized into a contentless FTS index and never stored verbatim.
use crate::{error::sqlite, root::FeedReceipt};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use se_types::code::AtlasText as _;
use se_types::{
    EventId, ProjectId, Result, SeError,
    code::{
        FeedRecord, GitObjectId, MentionTarget, QueryText, RecordFeed, RecordFeedChange, RecordKey,
        RecordKind, RecordVisibility, RelativePath,
    },
};

/// Mentions and touches kept per record and per target.
const MAX_TARGETS: usize = 256;
const TOUCHES_PER_TARGET: i64 = 10;
/// Title bytes the store keeps; core may send a longer excerpt.
const MAX_TITLE: usize = 160;

/// The longest prefix of `text` within `max` bytes on a character boundary.
fn clip(text: &str, max: usize) -> &str {
    &text[..text.floor_char_boundary(max)]
}

/// The last core event the store has folded in.
pub(crate) fn cursor(conn: &Connection) -> Result<Option<EventId>> {
    let saved: Option<Option<String>> = conn
        .query_row(
            "SELECT last_event FROM record_feed WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| sqlite(&e))?;
    saved.flatten().map(|id| id.parse()).transpose()
}

pub(crate) fn apply(
    conn: &Connection,
    project: &ProjectId,
    feed: &RecordFeed,
) -> Result<FeedReceipt> {
    feed.validate()?;
    if &feed.project != project {
        return Err(SeError::invalid(
            "Atlas record feed",
            "a feed of this worktree's project",
        ));
    }
    let saved = cursor(conn)?;
    if saved.as_ref() == Some(&feed.through) {
        return Ok(FeedReceipt {
            changed: 0,
            complete: feed.complete,
        });
    }
    if saved != feed.after {
        return Err(SeError::new(se_types::Detail::RevisionConflict(
            se_types::details::RevisionConflict {
                entity: "Atlas record feed".into(),
                expected: feed
                    .after
                    .as_ref()
                    .map_or("absent".into(), ToString::to_string),
                current: saved.map_or("absent".into(), |id| id.to_string()),
            },
        )));
    }
    let run = || -> rusqlite::Result<FeedReceipt> {
        let tx = conn.unchecked_transaction()?;
        for change in &feed.changes {
            match change {
                RecordFeedChange::Remove { key, .. } => {
                    let old = affected(&tx, key)?;
                    tx.execute("DELETE FROM records WHERE record_id=?1", [key.as_str()])?;
                    refresh(&tx, &old)?;
                }
                RecordFeedChange::Upsert(record) => upsert(&tx, record)?,
            }
        }
        tx.execute(
            "INSERT INTO record_feed(singleton, last_event) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET last_event=excluded.last_event",
            [feed.through.as_str()],
        )?;
        tx.commit()?;
        Ok(FeedReceipt {
            changed: u32::try_from(feed.changes.len()).unwrap_or(u32::MAX),
            complete: feed.complete,
        })
    };
    run().map_err(|e| sqlite(&e))
}

fn upsert(tx: &Transaction<'_>, record: &FeedRecord) -> rusqlite::Result<()> {
    // Update in place so incoming links to the row survive.
    let old = affected(tx, &record.pointer.key)?;
    let (visibility, audience) = match &record.visibility {
        RecordVisibility::Project => ("project", None),
        RecordVisibility::Restricted { audience } => (
            "restricted",
            audience
                .as_ref()
                .map(|k| serde_json::to_vec(k).unwrap_or_default()),
        ),
    };
    let title = clip(&record.title, MAX_TITLE);
    let actor = record
        .actor
        .as_ref()
        .and_then(|a| serde_json::to_string(a).ok());
    let r = &record.pointer;
    tx.execute(
        "INSERT INTO records(record_id, kind, actor, occurred_unix_ms, title, source_event,
           visibility, audience, body_truncated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(record_id) DO UPDATE SET kind=excluded.kind, actor=excluded.actor,
           occurred_unix_ms=excluded.occurred_unix_ms, title=excluded.title,
           source_event=excluded.source_event, visibility=excluded.visibility,
           audience=excluded.audience, body_truncated=excluded.body_truncated",
        params![
            r.key.as_str(),
            kind_name(r.kind),
            actor,
            record.occurred_unix_ms,
            title,
            r.source_event.as_str(),
            visibility,
            audience,
            record.body_truncated
        ],
    )?;
    let id: i64 = tx.query_row(
        "SELECT id FROM records WHERE record_id=?1",
        [record.pointer.key.as_str()],
        |row| row.get(0),
    )?;
    for statement in [
        "DELETE FROM record_fts WHERE rowid=?1",
        "DELETE FROM record_text_fts WHERE rowid=?1",
        "DELETE FROM mentions WHERE source_kind='record' AND source_id=?1",
        "DELETE FROM touches WHERE source_record=?1",
    ] {
        tx.execute(statement, [id])?;
    }
    refresh(tx, &old)?;
    tx.execute(
        "INSERT INTO record_fts(rowid, title, kind) VALUES (?1, ?2, ?3)",
        params![id, title, kind_name(record.pointer.kind)],
    )?;
    tx.execute(
        "INSERT INTO record_text_fts(rowid, body) VALUES (?1, ?2)",
        params![id, record.body],
    )?;
    let targets = targets(tx, record)?;
    link(tx, id, record, &targets, actor.as_deref())
}

pub(crate) fn kind_name(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Decision => "decision",
        RecordKind::Message => "message",
        RecordKind::Working => "working",
        RecordKind::Edit => "edit",
        RecordKind::Commit => "commit",
    }
}

type Target = (&'static str, Vec<u8>, &'static str);

fn link(
    tx: &Transaction<'_>,
    id: i64,
    record: &FeedRecord,
    targets: &[Target],
    actor: Option<&str>,
) -> rusqlite::Result<()> {
    let touch_kind = if record.pointer.kind == RecordKind::Edit {
        "tool_edit"
    } else {
        kind_name(record.pointer.kind)
    };
    let restricted = (!matches!(record.visibility, RecordVisibility::Project)).then_some(id);
    for (kind, key, accuracy) in targets {
        tx.execute(
            "INSERT OR IGNORE INTO mentions(source_kind, source_id, target_kind, target_key, accuracy)
             VALUES ('record', ?1, ?2, ?3, ?4)",
            params![id, kind, key, accuracy],
        )?;
        tx.execute(
            "INSERT INTO touches(target_kind, target_key, ordinal, touch_kind, actor, at_unix_ms,
               source_record, restricted_record)
             SELECT ?1, ?2, coalesce(max(ordinal), 0) + 1, ?3, ?4, ?5, ?6, ?7
             FROM touches WHERE target_kind=?1 AND target_key=?2",
            params![
                kind,
                key,
                touch_kind,
                actor,
                record.occurred_unix_ms,
                id,
                restricted
            ],
        )?;
        tx.execute(
            "DELETE FROM touches WHERE target_kind=?1 AND target_key=?2 AND ordinal NOT IN
               (SELECT ordinal FROM touches WHERE target_kind=?1 AND target_key=?2
                ORDER BY at_unix_ms DESC, ordinal DESC LIMIT ?3)",
            params![kind, key, TOUCHES_PER_TARGET],
        )?;
        // The summary leaves restricted records out; core checks them per viewer.
        tx.execute(
            "INSERT INTO activity(target_kind, target_key, last_touch_unix_ms, inbound_resolved)
             SELECT ?1, ?2, max(at_unix_ms), 0 FROM touches
             WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL
             GROUP BY target_kind, target_key
             ON CONFLICT(target_kind, target_key) DO UPDATE
               SET last_touch_unix_ms=excluded.last_touch_unix_ms",
            params![kind, key],
        )?;
    }
    Ok(())
}

/// The record's explicit mentions, then backticked identifiers, path-like
/// words and commit prefixes in its body, at most [`MAX_TARGETS`].
fn targets(tx: &Transaction<'_>, record: &FeedRecord) -> rusqlite::Result<Vec<Target>> {
    let mut out = Vec::new();
    for target in &record.mentions {
        resolve(tx, target, &mut out)?;
    }
    for (index, text) in record.body.split('`').enumerate() {
        if out.len() >= MAX_TARGETS {
            break;
        }
        if index % 2 == 1
            && !text.is_empty()
            && text.len() <= 1024
            && !text.chars().any(char::is_whitespace)
            && let Ok(name) = QueryText::new(text)
        {
            resolve(tx, &MentionTarget::Identifier(name), &mut out)?;
        }
        for word in text.split_whitespace() {
            if out.len() >= MAX_TARGETS {
                break;
            }
            body_word(tx, word, &mut out)?;
        }
    }
    Ok(out)
}

fn body_word(tx: &Transaction<'_>, word: &str, out: &mut Vec<Target>) -> rusqlite::Result<()> {
    let word = word.trim_matches(|c: char| "`\"'()[]{},;".contains(c));
    let path = word
        .rsplit_once(':')
        .filter(|(_, line)| !line.is_empty() && line.bytes().all(|c| c.is_ascii_digit()))
        .map_or(word, |(path, _)| path);
    if (path.contains('/') || path.contains('.'))
        && let Ok(path) = RelativePath::new(path)
    {
        resolve(tx, &MentionTarget::File(path), out)?;
    }
    if (7..=64).contains(&word.len()) && word.bytes().all(|c| c.is_ascii_hexdigit()) {
        let mut select =
            tx.prepare_cached("SELECT oid FROM commits WHERE hex(oid) LIKE ?1 LIMIT 2")?;
        let found: Vec<Vec<u8>> = select
            .query_map([format!("{}%", word.to_ascii_uppercase())], |row| {
                row.get(0)
            })?
            .collect::<rusqlite::Result<_>>()?;
        if let [oid] = found.as_slice() {
            push(out, "commit", oid.clone(), "ExplicitImport");
        }
    }
    Ok(())
}

fn push(out: &mut Vec<Target>, kind: &'static str, key: Vec<u8>, accuracy: &'static str) {
    if out.len() < MAX_TARGETS && !out.iter().any(|(k, v, _)| *k == kind && *v == key) {
        out.push((kind, key, accuracy));
    }
}

fn resolve(
    tx: &Transaction<'_>,
    target: &MentionTarget,
    out: &mut Vec<Target>,
) -> rusqlite::Result<()> {
    match target {
        MentionTarget::File(path) => {
            let key: Option<Vec<u8>> = tx
                .prepare_cached("SELECT key FROM files WHERE path=?1")?
                .query_row([path.as_str()], |row| row.get(0))
                .optional()?;
            match key {
                Some(key) => push(out, "file", key, "ExplicitImport"),
                None => push(out, "path", path.as_str().as_bytes().to_vec(), "NameOnly"),
            }
        }
        MentionTarget::Symbol(symbol) => push(out, "symbol", symbol.0.to_vec(), "ExplicitImport"),
        MentionTarget::Identifier(name) => {
            let mut select = tx.prepare_cached(
                "SELECT s.key FROM sym s JOIN vocab v ON v.id = s.name WHERE v.tok = ?1 LIMIT 2",
            )?;
            let keys: Vec<Vec<u8>> = select
                .query_map([name.as_str().to_lowercase()], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            match keys.as_slice() {
                [key] => push(out, "symbol", key.clone(), "NameOnly"),
                _ => push(out, "identifier", name.as_str().into(), "NameOnly"),
            }
        }
        MentionTarget::Commit(oid) => {
            let bytes = match oid {
                GitObjectId::Sha1(b) => b.as_slice(),
                GitObjectId::Sha256(b) => b.as_slice(),
            };
            push(out, "commit", bytes.to_vec(), "ExplicitImport");
        }
        MentionTarget::Record(key) => push(out, "record", key.as_str().into(), "ExplicitImport"),
    }
    Ok(())
}

fn affected(tx: &Transaction<'_>, key: &RecordKey) -> rusqlite::Result<Vec<(String, Vec<u8>)>> {
    let mut select = tx.prepare_cached(
        "SELECT DISTINCT target_kind, target_key FROM touches
         WHERE source_record IN (SELECT id FROM records WHERE record_id=?1) LIMIT 256",
    )?;
    let rows = select.query_map([key.as_str()], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect()
}

fn refresh(tx: &Transaction<'_>, keys: &[(String, Vec<u8>)]) -> rusqlite::Result<()> {
    for (kind, key) in keys {
        tx.execute(
            "DELETE FROM activity WHERE target_kind=?1 AND target_key=?2 AND inbound_resolved=0
               AND NOT EXISTS(SELECT 1 FROM touches WHERE target_kind=?1 AND target_key=?2
                                AND restricted_record IS NULL)",
            params![kind, key],
        )?;
        tx.execute(
            "UPDATE activity SET last_touch_unix_ms=(SELECT max(at_unix_ms) FROM touches
               WHERE target_kind=?1 AND target_key=?2 AND restricted_record IS NULL)
             WHERE target_kind=?1 AND target_key=?2",
            params![kind, key],
        )?;
    }
    Ok(())
}
