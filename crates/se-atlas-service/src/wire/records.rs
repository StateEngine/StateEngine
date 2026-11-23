//! Records on the wire. The store holds candidates of every visibility; a
//! record reaches an answer only through core's check for the viewer, and
//! pages and counts are cut after that check, so an answer never reveals
//! that a record the viewer may not see exists. An authority that cannot
//! answer is an error, never an empty result.
use super::{PageFacts, answer, checked, cursor, find::RANK_VERSION, page, size};
use crate::{
    error::{index_error, sqlite},
    read::RecordCheck,
    root::Shared,
};
use rusqlite::Connection;
use se_types::code::AtlasText as _;
use se_types::{
    Detail, Read, Result, SeError,
    code::{
        Answer, FindQuery, HitReason, HitTarget, IndexSummary, QueryText, RecordHit, RecordKey,
        RecordKind, RecordPointer, SearchHit, SearchMode, SearchResults,
    },
    details,
};

/// Records one impact or outline answer lists.
pub(crate) const MAX_LINKED: usize = 10;
/// Candidates read per target for one impact or outline answer.
const MAX_SCANNED: usize = 512;
/// Candidate rows read per round trip while paging a record search.
const CHUNK: u64 = 64;

/// Core's verdict on one candidate: a hit, not visible, or an error.
pub(crate) fn authorize(
    records: &dyn RecordCheck,
    pointer: &RecordPointer,
    query: Option<&QueryText>,
) -> Result<Option<RecordHit>> {
    match records.hit(pointer, query)? {
        Read::Present { value } => Ok(Some(value)),
        Read::Absent { .. } => Ok(None),
        Read::Unreadable {
            source,
            reason,
            error,
        } => Err(match error {
            Some(body) => SeError::from(*body),
            None => unreadable(&source, &reason),
        }),
        Read::Unknown { what } => Err(unreadable("the record store", &what)),
    }
}

fn unreadable(subject: &str, reason: &str) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
        subject: subject.into(),
        reason: reason.into(),
        next_step: "Retry the query; linked records are checked for every viewer.".into(),
    }))
}

/// Authorized records mentioning any of `targets`, newest first.
pub(crate) struct Linked {
    pub hits: Vec<RecordHit>,
    /// Another record this viewer may see exists beyond those listed. Only
    /// visible records decide it, so it never counts hidden ones.
    pub limited: bool,
}

/// Records whose mentions name one of `targets` (`target_kind`, key), of
/// every visibility, checked newest first until [`MAX_LINKED`] are visible.
pub(crate) fn linked(
    shared: &Shared,
    records: &dyn RecordCheck,
    targets: &[(&str, Vec<u8>)],
) -> Result<Linked> {
    let candidates = shared.with_reader(|reader| {
        let conn = reader.connection();
        let mut select = conn
            .prepare_cached(
                "SELECT r.record_id, r.kind, r.source_event, r.occurred_unix_ms
                 FROM mentions m JOIN records r ON r.id = m.source_id
                 WHERE m.source_kind='record' AND m.target_kind=?1 AND m.target_key=?2
                 ORDER BY r.occurred_unix_ms DESC, r.id DESC LIMIT ?3",
            )
            .map_err(|e| sqlite(&e))?;
        let mut found: Vec<(i64, String, String, String)> = Vec::new();
        for (kind, key) in targets {
            let rows = select
                .query_map(rusqlite::params![kind, key, MAX_SCANNED as i64], |row| {
                    Ok((row.get(3)?, row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(|e| sqlite(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| sqlite(&e))?;
            found.extend(rows);
        }
        found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        found.dedup_by(|a, b| a.1 == b.1);
        Ok(found)
    })?;
    let mut hits = Vec::new();
    let mut limited = false;
    for (_, key, kind, event) in &candidates {
        let Some(pointer) = pointer(key, kind, event) else {
            continue;
        };
        let Some(hit) = authorize(records, &pointer, None)? else {
            continue;
        };
        if hits.len() >= MAX_LINKED {
            limited = true;
            break;
        }
        hits.push(hit);
    }
    Ok(Linked { hits, limited })
}

/// A record's pointer from the store's copy of its identity.
fn pointer(record_id: &str, kind: &str, event: &str) -> Option<RecordPointer> {
    let kind = match kind {
        "decision" => RecordKind::Decision,
        "message" => RecordKind::Message,
        "working" => RecordKind::Working,
        "edit" => RecordKind::Edit,
        "commit" => RecordKind::Commit,
        _ => return None,
    };
    Some(RecordPointer {
        key: RecordKey::new(record_id).ok()?,
        kind,
        source_event: event.parse().ok()?,
    })
}

/// Records of one kind whose title or body holds every query word, newest
/// first. Every decision a viewer can see is made on records core admitted
/// for them: a page fills with visible records, `next` appears only when a
/// further visible record exists, and the cursor names the page's last
/// listed record, so no count, position or time of a hidden record leaks.
pub(crate) fn find(
    shared: &Shared,
    index: &IndexSummary,
    query: &FindQuery,
    kind: RecordKind,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<SearchResults>>> {
    let start = match &query.next {
        Some(next) => key(next)?,
        None => (i64::MAX, i64::MAX),
    };
    let limit = usize::from(query.budget.max_results);
    let max_bytes = query.budget.max_bytes as usize;
    // Sized with the longest cursor, so a page that gains one still fits.
    let widest = key_cursor((i64::MAX, i64::MAX))?;
    let empty = results(index, query, Vec::new(), Some(widest), 0)?;
    let mut bytes = size(&answer(index, Read::Present { value: empty }));
    let mut items = Vec::new();
    let mut last = None;
    let mut more = false;
    shared.with_reader(|reader| {
        let snapshot = reader.snapshot().map_err(|e| index_error(&e))?;
        let mut after = start;
        loop {
            let rows = rows(snapshot.connection(), query, kind, after, CHUNK)?;
            let exhausted = (rows.len() as u64) < CHUNK;
            for (record, event, at) in rows {
                after = at;
                let Some(pointer) = pointer(&record, crate::records::kind_name(kind), &event)
                else {
                    continue;
                };
                let Some(value) = authorize(records, &pointer, Some(&query.query))? else {
                    continue;
                };
                let hit = record_hit(value);
                let cost = size(&hit) + 1;
                if items.is_empty() && bytes + cost > max_bytes {
                    return Err(over_budget(bytes + cost, query.budget.max_bytes));
                }
                if items.len() >= limit || bytes + cost > max_bytes {
                    more = true;
                    return Ok(());
                }
                bytes += cost;
                items.push(hit);
                last = Some(at);
            }
            if exhausted {
                return Ok(());
            }
        }
    })?;
    let next = last.filter(|_| more).map(key_cursor).transpose()?;
    let value = results(index, query, items, next, bytes)?;
    checked(answer(index, Read::Present { value }), query.budget)
}

/// A record page cursor: the `(occurred_unix_ms, id)` of the last listed
/// record, one the viewer was admitted to.
fn key_cursor((at, id): (i64, i64)) -> Result<se_types::code::AtlasCursor> {
    cursor::wrap('m', &format!("{at}.{id}"))
}

fn key(next: &se_types::code::AtlasCursor) -> Result<(i64, i64)> {
    cursor::unwrap('m', next)?
        .split_once('.')
        .and_then(|(at, id)| Some((at.parse().ok()?, id.parse().ok()?)))
        .ok_or_else(|| {
            SeError::invalid(
                "Atlas cursor",
                "a cursor this query returned; repeat the query without it",
            )
        })
}

/// One visible record is larger than the whole byte budget: refuse rather
/// than return a page that cannot progress.
pub(crate) fn over_budget(requested: usize, available: u32) -> SeError {
    SeError::new(Detail::AtlasResourceBudget(details::AtlasResourceBudget {
        resource: "Atlas response bytes".into(),
        requested: requested as u64,
        available: u64::from(available),
    }))
}

fn record_hit(value: RecordHit) -> SearchHit {
    SearchHit {
        target: HitTarget::Record(value),
        reason: HitReason {
            mode: SearchMode::Exact,
            match_tier: 100,
            last_touch_unix_ms: None,
            edited_by: None,
            cited_messages: 0,
            text_only: false,
            related: false,
        },
        rank_version: RANK_VERSION,
        body: None,
    }
}

fn results(
    index: &IndexSummary,
    query: &FindQuery,
    items: Vec<SearchHit>,
    next: Option<se_types::code::AtlasCursor>,
    bytes: usize,
) -> Result<SearchResults> {
    Ok(SearchResults {
        mode: SearchMode::Exact,
        fallback_from: None,
        page: page(
            items,
            PageFacts {
                index,
                budget: query.budget,
                after: query.next.as_ref(),
                next,
                partial: false,
                bytes,
            },
        )?,
        truncated_candidates: Some(0),
        full: false,
        bodies_omitted: 0,
        text: None,
    })
}

/// A candidate's record id, source event and `(occurred_unix_ms, id)` key.
type Candidate = (String, String, (i64, i64));

/// Candidates older than `after`, newest first.
fn rows(
    conn: &Connection,
    query: &FindQuery,
    kind: RecordKind,
    after: (i64, i64),
    limit: u64,
) -> Result<Vec<Candidate>> {
    let words: Vec<String> = query
        .query
        .as_str()
        .split_whitespace()
        .map(|word| format!("\"{}\"", word.replace('"', "\"\"")))
        .collect();
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let pattern = words.join(" ");
    let mut select = conn
        .prepare_cached(
            "SELECT r.record_id, r.source_event, r.occurred_unix_ms, r.id FROM records r
             WHERE r.kind=?2 AND (r.id IN (SELECT rowid FROM record_fts WHERE record_fts MATCH ?1)
                OR r.id IN (SELECT rowid FROM record_text_fts WHERE record_text_fts MATCH ?1))
               AND (r.occurred_unix_ms, r.id) < (?4, ?5)
             ORDER BY r.occurred_unix_ms DESC, r.id DESC LIMIT ?3",
        )
        .map_err(|e| sqlite(&e))?;
    let rows = select
        .query_map(
            rusqlite::params![
                pattern,
                crate::records::kind_name(kind),
                i64::try_from(limit).unwrap_or(i64::MAX),
                after.0,
                after.1
            ],
            |row| Ok((row.get(0)?, row.get(1)?, (row.get(2)?, row.get(3)?))),
        )
        .map_err(|e| sqlite(&e))?;
    rows.collect::<rusqlite::Result<_>>()
        .map_err(|e| sqlite(&e))
}
