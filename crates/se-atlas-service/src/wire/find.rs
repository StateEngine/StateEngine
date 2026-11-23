//! `find`: index search, the dirty-file overlay and the top-K stat check,
//! merged into one ranked page. Lines read live come first; index rows of
//! any file read live are dropped, so a stale line never shows beside its
//! replacement. Close spellings offered when nothing matched are a labelled
//! fallback, never ordinary hits.
use super::{
    PageFacts, answer, checked, cursor, file_id, kind, language_tags, page, pointer, size, span,
    unknown,
};
use crate::{
    dirty::Change,
    error::{index_error, sqlite},
    overlay::{self, FreshHit, Overlay, Terms},
    read::{RecordCheck, STARTING},
    root::{Msg, Shared},
};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::{
    custody::{GuardedRead, IndexSourceRoot},
    extract::LanguageTag,
    store::Reader,
};
use se_atlas_search::{
    Hit, HitField, KindFilter, MatchKind, QueryMode, SearchOutcome, SearchRequest,
};
use se_types::code::AtlasText as _;
use se_types::{
    Read, Result, SeError,
    code::{
        Answer, BodyOrigin, CodeHit, ContentHash, CoverageReason, FindMethod, FindQuery, HitBody,
        HitReason, HitTarget, IndexSummary, RecordKey, RecordKind, RecordPointer, RelativePath,
        SearchHit, SearchKind, SearchMode, SearchResults, SearchScope, SnapshotFreshness, SymbolId,
        TextSearchStats,
    },
};
use std::collections::BTreeSet;

/// Ranking version reported with every v5 hit.
pub const RANK_VERSION: u32 = 5;
/// Whole-response ceiling when bodies are included.
const FULL_RESPONSE: usize = 12 * 1024;

pub(crate) fn find(
    shared: &Shared,
    index: &IndexSummary,
    query: &FindQuery,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<SearchResults>>> {
    query.scope.validate()?;
    if query.regex
        && (!matches!(
            query.kind,
            SearchKind::All | SearchKind::Code | SearchKind::Text
        ) || query.mode.is_some_and(|mode| mode != SearchMode::Literal))
    {
        return Err(SeError::invalid(
            "Atlas regular expression",
            "a code query (all, code or text) with automatic or literal mode",
        ));
    }
    if let Some(kind) = record_kind(query.kind) {
        return record_find(shared, index, query, kind, records);
    }
    let Some(source) = shared.source() else {
        return Ok(unknown(index, STARTING));
    };
    let offset = match &query.next {
        Some(next) => usize::try_from(cursor::number('f', next)?).unwrap_or(usize::MAX),
        None => 0,
    };
    let reader = shared.reader()?;
    let result = se_atlas_search::search(&reader, source, &request(query, offset))
        .map_err(|error| index_error(&error))
        .and_then(|outcome| assemble(shared, &reader, source, index, query, offset, &outcome));
    shared.give_back(reader);
    result
}

fn record_kind(kind: SearchKind) -> Option<RecordKind> {
    match kind {
        SearchKind::Message => Some(RecordKind::Message),
        SearchKind::Working => Some(RecordKind::Working),
        SearchKind::Edit => Some(RecordKind::Edit),
        SearchKind::Commit => Some(RecordKind::Commit),
        _ => None,
    }
}

fn filter(kind: SearchKind) -> KindFilter {
    match kind {
        SearchKind::Symbol => KindFilter::Symbol,
        SearchKind::Text => KindFilter::Text,
        SearchKind::Path => KindFilter::Path,
        _ => KindFilter::All,
    }
}

fn request(query: &FindQuery, offset: usize) -> SearchRequest {
    let text = match query.mode {
        Some(SearchMode::Phrase) if !query.query.as_str().contains('"') => {
            format!("\"{}\"", query.query.as_str())
        }
        _ => query.query.as_str().to_owned(),
    };
    let mut request = SearchRequest::new(text);
    request.mode = if query.regex {
        QueryMode::Regex
    } else {
        QueryMode::Text
    };
    request.kind = filter(query.kind);
    request.in_paths = query
        .scope
        .paths
        .iter()
        .map(|path| path.as_str().to_owned())
        .collect();
    request.languages = language_tags(&query.scope.languages);
    request.limit = offset
        .saturating_add(usize::from(query.budget.max_results))
        .min(se_atlas_search::MAX_LIMIT);
    request.max_bytes = se_atlas_search::MAX_MAX_BYTES;
    request.deadline = query.budget.work;
    request.walk = crate::engine::walk_options();
    request
}

pub(crate) fn admits(scope: &SearchScope, path: &str) -> bool {
    let in_path = scope.paths.is_empty()
        || RelativePath::new(path).is_ok_and(|relative| scope.includes_path(&relative));
    let tags = language_tags(&scope.languages);
    in_path && (tags.is_empty() || tags.contains(&LanguageTag::detect(path)))
}

/// One merged row before mapping.
enum Row<'h> {
    Fresh(FreshHit),
    Indexed(&'h Hit),
}

impl Row<'_> {
    fn key(&self) -> (&str, u32) {
        match self {
            Self::Fresh(hit) => (&hit.path, hit.line),
            Self::Indexed(hit) => (&hit.path, hit.line),
        }
    }
}

fn assemble(
    shared: &Shared,
    reader: &Reader,
    source: &IndexSourceRoot,
    index: &IndexSummary,
    query: &FindQuery,
    offset: usize,
    outcome: &SearchOutcome,
) -> Result<Answer<Read<SearchResults>>> {
    let (dirty, overflowed) = {
        let dirty = shared.dirty()?;
        (dirty.snapshot(), dirty.overflowed())
    };
    let kinds = filter(query.kind);
    let terms = Terms::new(
        query.query.as_str(),
        query.regex,
        matches!(kinds, KindFilter::All | KindFilter::Text),
        matches!(kinds, KindFilter::All | KindFilter::Path),
    );
    let mut fresh = Overlay::default();
    fresh.read(source, &terms, &dirty, &|path| admits(&query.scope, path));
    let checked_files = answer_files(outcome, &fresh.stale);
    let stale = overlay::stale_files(reader.connection(), source, &checked_files, now_ns());
    if !stale.is_empty() {
        if let Ok(mut set) = shared.dirty() {
            for path in &stale {
                set.mark(path, Change::Modified);
            }
        }
        shared.send(Msg::Wake);
        for path in &stale {
            fresh.file(source, &terms, path);
        }
    }
    let verified: BTreeSet<&str> = checked_files
        .iter()
        .map(String::as_str)
        .filter(|path| !fresh.stale.contains(*path))
        .collect();
    let mut rows: Vec<Row<'_>> = fresh.hits.drain(..).map(Row::Fresh).collect();
    rows.extend(
        outcome
            .hits
            .iter()
            .filter(|hit| !fresh.stale.contains(&hit.path))
            .map(Row::Indexed),
    );
    let mut seen = BTreeSet::new();
    rows.retain(|row| {
        let (path, line) = row.key();
        seen.insert((path.to_owned(), line))
    });
    let partial = outcome.stopped_early() || fresh.unread > 0 || overflowed;
    let mut index = index.clone();
    if outcome.deadline_reached {
        index.note(CoverageReason::TimeLimit);
    }
    if fresh.unread > 0 || overflowed {
        index.degrade(CoverageReason::StaleSnapshot);
    }
    let context = Context {
        conn: reader.connection(),
        source,
        verified: &verified,
        full: query.full,
    };
    let mut shape = Shape {
        offset,
        partial,
        stats: stats(outcome, &fresh),
        guesses: false,
        more_ranked: outcome.omitted > 0 || outcome.omitted_at_least,
    };
    if rows.is_empty() && !outcome.guesses.is_empty() {
        let guesses: Vec<Row<'_>> = outcome.guesses.iter().map(Row::Indexed).collect();
        shape.offset = 0;
        shape.guesses = true;
        shape.more_ranked = false;
        return finish(&context, &index, query, &guesses, &shape);
    }
    finish(&context, &index, query, &rows, &shape)
}

/// How one page is cut and labelled.
struct Shape {
    offset: usize,
    partial: bool,
    stats: TextSearchStats,
    guesses: bool,
    /// The search ranked more hits than it returned.
    more_ranked: bool,
}

/// Distinct files of the answer, in rank order, not already read live.
fn answer_files(outcome: &SearchOutcome, read: &BTreeSet<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for hit in &outcome.hits {
        if out.len() >= overlay::MAX_STAT_FILES {
            break;
        }
        if !read.contains(&hit.path) && !out.contains(&hit.path) {
            out.push(hit.path.clone());
        }
    }
    out
}

fn stats(outcome: &SearchOutcome, fresh: &Overlay) -> TextSearchStats {
    let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    TextSearchStats {
        scanned_files: count(outcome.files_read),
        matching_files: 0,
        binary_files: 0,
        non_utf8_files: 0,
        oversized_files: count(outcome.files_partly_read),
        changed_files: count(fresh.stale.len()),
        unavailable_files: count(
            outcome.files_absent + outcome.files_refused + outcome.files_read_failed + fresh.unread,
        ),
        time_limited_files: count(outcome.files_unread),
        line_limited_files: 0,
        omitted_matches: outcome.omitted as u64,
    }
}

struct Context<'a> {
    conn: &'a Connection,
    source: &'a IndexSourceRoot,
    verified: &'a BTreeSet<&'a str>,
    full: bool,
}

fn finish(
    context: &Context<'_>,
    index: &IndexSummary,
    query: &FindQuery,
    rows: &[Row<'_>],
    shape: &Shape,
) -> Result<Answer<Read<SearchResults>>> {
    let mut budget = query.budget;
    if query.full {
        budget.max_bytes = budget.max_bytes.min(FULL_RESPONSE as u32);
    }
    let empty = results(index, query, Vec::new(), None, 0, shape)?;
    let mut bytes = size(&answer(index, Read::Present { value: empty }));
    let (mut items, mut bodies_omitted) = (Vec::new(), 0u16);
    let mut body_bytes = 0usize;
    let mut stopped_at = None;
    for (at, row) in rows.iter().enumerate().skip(shape.offset) {
        if items.len() >= usize::from(budget.max_results) {
            stopped_at = Some(at);
            break;
        }
        let mut hit = search_hit(context, row)?;
        if let Some(body) = &hit.body
            && body_bytes + body.text.len() > FULL_RESPONSE / 2
        {
            hit.body = None;
            bodies_omitted += 1;
        }
        let cost = size(&hit) + 1;
        if bytes + cost > budget.max_bytes as usize {
            stopped_at = Some(at);
            break;
        }
        body_bytes += hit.body.as_ref().map_or(0, |body| body.text.len());
        bytes += cost;
        items.push(hit);
    }
    let resume_at = stopped_at
        .or_else(|| (shape.more_ranked && !items.is_empty()).then_some(shape.offset + items.len()));
    let next = resume_at
        .filter(|at| *at < se_atlas_search::MAX_LIMIT)
        .map(|at| cursor::wrap('f', &at.to_string()))
        .transpose()?;
    let mut value = results(index, query, items, next, bytes, shape)?;
    value.bodies_omitted = bodies_omitted;
    value.validate()?;
    checked(answer(index, Read::Present { value }), query.budget)
}

fn results(
    index: &IndexSummary,
    query: &FindQuery,
    items: Vec<SearchHit>,
    next: Option<se_types::code::AtlasCursor>,
    bytes: usize,
    shape: &Shape,
) -> Result<SearchResults> {
    let mode = if shape.guesses {
        SearchMode::Broad
    } else if query.regex {
        SearchMode::Literal
    } else {
        items
            .first()
            .map_or(SearchMode::Exact, |hit| hit.reason.mode)
    };
    let truncated = u64::from(shape.stats.time_limited_files);
    Ok(SearchResults {
        mode,
        fallback_from: shape.guesses.then_some(SearchMode::Exact),
        page: page(
            items,
            PageFacts {
                index,
                budget: query.budget,
                after: query.next.as_ref(),
                next,
                partial: shape.partial,
                bytes,
            },
        )?,
        truncated_candidates: Some(truncated),
        full: query.full,
        bodies_omitted: 0,
        text: Some(shape.stats.clone()),
    })
}

fn search_hit(context: &Context<'_>, row: &Row<'_>) -> Result<SearchHit> {
    let (path, line, text, field, kind_of, matched) = match row {
        Row::Fresh(hit) => (
            hit.path.as_str(),
            hit.line,
            hit.text.as_str(),
            if hit.line == 0 {
                HitField::Path
            } else {
                HitField::Body
            },
            None,
            MatchKind::Exact,
        ),
        Row::Indexed(hit) => (
            hit.path.as_str(),
            hit.line,
            hit.text.as_str(),
            hit.field,
            hit.symbol_kind,
            hit.match_kind,
        ),
    };
    let live = matches!(row, Row::Fresh(_))
        || matches!(field, HitField::Body | HitField::Signature)
        || context.verified.contains(path);
    let freshness = if live {
        SnapshotFreshness::Current
    } else {
        SnapshotFreshness::Unknown
    };
    let hash = indexed_hash(context.conn, path)?.filter(|_| !matches!(row, Row::Fresh(_)));
    let symbol = if field == HitField::Symbol {
        symbol_key(context.conn, path, line)?
    } else {
        None
    };
    let lines = (line > 0).then_some((line, line));
    let mode = mode_of(matched);
    let body = if context.full && line > 0 {
        body(context.source, path, line)
    } else {
        None
    };
    Ok(SearchHit {
        target: HitTarget::Code(CodeHit {
            pointer: pointer(path, lines, hash, freshness)?,
            symbol: symbol.map(SymbolId),
            name: text.to_owned(),
            kind: kind_of.map(kind),
            method: method(field, matched),
            accuracy: None,
        }),
        reason: HitReason {
            mode,
            match_tier: matched.evidence(),
            last_touch_unix_ms: None,
            edited_by: None,
            cited_messages: 0,
            text_only: matches!(field, HitField::Body | HitField::Signature),
            related: false,
        },
        rank_version: RANK_VERSION,
        body,
    })
}

fn mode_of(matched: MatchKind) -> SearchMode {
    match matched {
        MatchKind::Exact | MatchKind::Compact => SearchMode::Exact,
        MatchKind::Literal | MatchKind::Regex => SearchMode::Literal,
        MatchKind::Fuzzy { .. } | MatchKind::Partial | MatchKind::Guess => SearchMode::Broad,
    }
}

fn method(field: HitField, matched: MatchKind) -> FindMethod {
    match field {
        HitField::Symbol if matches!(matched, MatchKind::Exact) => FindMethod::ExactName,
        HitField::Symbol => FindMethod::SplitIdentifier,
        HitField::Path => FindMethod::MetadataFts,
        HitField::Signature | HitField::Body => FindMethod::Text,
    }
}

fn indexed_hash(conn: &Connection, path: &str) -> Result<Option<[u8; 32]>> {
    let blob: Option<Vec<u8>> = conn
        .prepare_cached("SELECT hash FROM files WHERE path=?1")
        .and_then(|mut select| select.query_row([path], |row| row.get(0)).optional())
        .map_err(|e| sqlite(&e))?;
    Ok(super::hash(blob))
}

fn symbol_key(conn: &Connection, path: &str, line: u32) -> Result<Option<[u8; 32]>> {
    let blob: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT s.key FROM sym s JOIN files f ON f.id = s.file
             WHERE f.path=?1 AND s.line=?2 ORDER BY s.id LIMIT 1",
        )
        .and_then(|mut select| {
            select
                .query_row(rusqlite::params![path, line], |row| row.get(0))
                .optional()
        })
        .map_err(|e| sqlite(&e))?;
    Ok(super::hash(blob))
}

/// Up to two lines either side of a hit, read live through custody.
fn body(source: &IndexSourceRoot, path: &str, line: u32) -> Option<HitBody> {
    let Ok(GuardedRead::Source(file)) = source.read_guarded_file(path) else {
        return None;
    };
    let text = String::from_utf8_lossy(&file.bytes);
    let first = line.saturating_sub(2).max(1);
    let lines: Vec<&str> = text
        .lines()
        .skip(first as usize - 1)
        .take(5)
        .map(|line| line.trim_start_matches('\u{feff}'))
        .collect();
    let last = first + lines.len().saturating_sub(1) as u32;
    let excerpt = lines.join("\n");
    let origin = BodyOrigin::LiveSource {
        file: file_id(path),
        path: RelativePath::new(path).ok()?,
        span: span(first, last),
        range_hash: ContentHash(*blake3::hash(excerpt.as_bytes()).as_bytes()),
        content_hash: None,
        matches_index: None,
    };
    HitBody::new(origin, excerpt, !file.prefix_only).ok()
}

fn now_ns() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i128::try_from(elapsed.as_nanos()).unwrap_or(i128::MAX)
        })
}

/// Records of one kind whose title or body holds every query word. Core
/// rechecks each against the viewer before it becomes a hit.
fn record_find(
    shared: &Shared,
    index: &IndexSummary,
    query: &FindQuery,
    kind: RecordKind,
    records: &dyn RecordCheck,
) -> Result<Answer<Read<SearchResults>>> {
    let offset = match &query.next {
        Some(next) => cursor::number('m', next)?,
        None => 0,
    };
    let limit = u64::from(query.budget.max_results);
    let reader = shared.reader()?;
    let rows = record_rows(reader.connection(), query, kind, offset, limit + 1);
    shared.give_back(reader);
    let rows = rows?;
    let more = rows.len() as u64 > limit;
    let mut items = Vec::new();
    let mut bytes = 0;
    for (key, event) in rows.into_iter().take(limit as usize) {
        let (Ok(key), Ok(source_event)) = (RecordKey::new(key), event.parse()) else {
            continue;
        };
        let pointer = RecordPointer {
            key,
            kind,
            source_event,
        };
        if let Read::Present { value } = records.hit(&pointer, Some(&query.query))? {
            let hit = SearchHit {
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
            };
            bytes += size(&hit) + 1;
            items.push(hit);
        }
    }
    let next = more
        .then(|| cursor::wrap('m', &(offset + limit).to_string()))
        .transpose()?;
    let value = SearchResults {
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
    };
    checked(answer(index, Read::Present { value }), query.budget)
}

fn record_rows(
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
