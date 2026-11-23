//! Records on the wire. The store holds candidates of every visibility; a
//! record reaches an answer only through core's check for the viewer, and
//! pages and counts are cut after that check, so an answer never reveals
//! that a record the viewer may not see exists. An authority that cannot
//! answer is an error, never an empty result.
use super::{PageFacts, answer, checked, cursor, find::RANK_VERSION, page, size};
use crate::{error::sqlite, read::RecordCheck, root::Shared};
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
/// Candidates checked for one answer before it reports a floor.
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
    /// More candidates exist than were checked or listed.
    pub limited: bool,
}

/// Records whose mentions name one of `targets` (`target_kind`, key), of
/// every visibility, checked newest first until [`MAX_LINKED`] are visible.
pub(crate) fn linked(
    shared: &Shared,
    records: &dyn RecordCheck,
    targets: &[(&str, Vec<u8>)],
) -> Result<Linked> {
    let (candidates, mut limited) = shared.with_reader(|reader| {
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
        let mut limited = false;
        for (kind, key) in targets {
            let rows = select
                .query_map(
                    rusqlite::params![kind, key, MAX_SCANNED as i64 + 1],
                    |row| Ok((row.get(3)?, row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| sqlite(&e))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| sqlite(&e))?;
            limited |= rows.len() > MAX_SCANNED;
            found.extend(rows);
        }
        found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        found.dedup_by(|a, b| a.1 == b.1);
        limited |= found.len() > MAX_SCANNED;
        found.truncate(MAX_SCANNED);
        Ok((found, limited))
    })?;
    let mut hits = Vec::new();
    for (at, (_, key, kind, event)) in candidates.iter().enumerate() {
        if hits.len() >= MAX_LINKED {
            limited |= at < candidates.len();
            break;
        }
        let Some(pointer) = pointer(key, kind, event) else {
            continue;
        };
        if let Some(hit) = authorize(records, &pointer, None)? {
            hits.push(hit);
        }
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

/// Records of one kind whose title or body holds every query word. Rows are
/// paged by candidate position, but a page holds only records core admitted
/// for this viewer: the page fills with visible records, and `more` is
/// decided by one further visible record, never by a raw candidate count.
pub(crate) fn find(
    shared: &Shared,
    index: &IndexSummary,
    query: &FindQuery,
    kind: RecordKind,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<SearchResults>>> {
    let start = match &query.next {
        Some(next) => cursor::number('m', next)?,
        None => 0,
    };
    let limit = usize::from(query.budget.max_results);
    let empty = results(index, query, Vec::new(), None, 0)?;
    let mut bytes = size(&answer(index, Read::Present { value: empty }));
    let mut items = Vec::new();
    let mut next = None;
    let mut scanned = 0usize;
    let mut offset = start;
    'pages: loop {
        let rows =
            shared.with_reader(|reader| rows(reader.connection(), query, kind, offset, CHUNK))?;
        let exhausted = (rows.len() as u64) < CHUNK;
        for (position, (key, event)) in (offset..).zip(rows) {
            if scanned >= MAX_SCANNED {
                // Unchecked candidates remain: resume at the first of them.
                next = Some(position);
                break 'pages;
            }
            scanned += 1;
            let Some(pointer) = pointer(&key, crate::records::kind_name(kind), &event) else {
                continue;
            };
            let Some(value) = authorize(records, &pointer, Some(&query.query))? else {
                continue;
            };
            let hit = record_hit(value);
            let cost = size(&hit) + 1;
            if items.len() >= limit || bytes + cost > query.budget.max_bytes as usize {
                next = Some(position);
                break 'pages;
            }
            bytes += cost;
            items.push(hit);
        }
        if exhausted {
            break;
        }
        offset += CHUNK;
    }
    let next = next
        .map(|at| cursor::wrap('m', &at.to_string()))
        .transpose()?;
    let value = results(index, query, items, next, bytes)?;
    checked(answer(index, Read::Present { value }), query.budget)
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

fn rows(
    conn: &Connection,
    query: &FindQuery,
    kind: RecordKind,
    offset: u64,
    limit: u64,
) -> Result<Vec<(String, String)>> {
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
            "SELECT r.record_id, r.source_event FROM records r
             WHERE r.kind=?2 AND (r.id IN (SELECT rowid FROM record_fts WHERE record_fts MATCH ?1)
                OR r.id IN (SELECT rowid FROM record_text_fts WHERE record_text_fts MATCH ?1))
             ORDER BY r.occurred_unix_ms DESC, r.id DESC LIMIT ?3 OFFSET ?4",
        )
        .map_err(|e| sqlite(&e))?;
    let rows = select
        .query_map(
            rusqlite::params![
                pattern,
                crate::records::kind_name(kind),
                i64::try_from(limit).unwrap_or(i64::MAX),
                i64::try_from(offset).unwrap_or(i64::MAX)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| sqlite(&e))?;
    rows.collect::<rusqlite::Result<_>>()
        .map_err(|e| sqlite(&e))
}
