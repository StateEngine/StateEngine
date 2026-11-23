//! `changes` and the resume digest on the wire. Generations order history;
//! a resume cursor is the shared `changes-range` position naming the last
//! generation a viewer was offered, so a later digest starts after it.
//! Building an offer never advances anything: core commits the cursor only
//! when the consumer acknowledges delivery.
use super::{
    Examined, PageFacts, answer, checked, cursor, envelope, find::admits, page, pointer, records,
    size, unknown,
};
use crate::{
    error::{index_error, sqlite},
    root::Shared,
};
use rusqlite::Connection;
use se_atlas_index::store::{ChangeKind as V5Change, Reader};
use se_atlas_query::changes::{ChangeEntry, ChangesAnswer, ChangesRequest, Since};
use se_types::code::AtlasText as _;
use se_types::{
    AgentId, Page, Read, Result, SeError,
    code::{
        Answer, AtlasCursor, AtlasPrincipal, AuthorHint, BulkChange, BulkReason, ChangeBaseline,
        ChangeId, ChangeKind, ChangesQuery, CodeChange, CodeCursorPosition, CodeEdit,
        CoverageReason, CursorKey, DependentCount, Generation, GitObjectId, IndexSummary,
        RelativePath, ResumeAdvance, ResumeChange, ResumeCode, ResumeCodeState, ResumeOfferId,
        ResumeRequest, SnapshotFreshness, cursor_digest,
    },
};

/// Bulk changes a resume digest lists.
const RESUME_BULK: usize = 5;
/// Change rows a resume digest scans.
const RESUME_SCAN: i64 = 513;
/// The cursor domain resume offers and change ranges share with core.
const RANGE: &str = "changes-range";

/// A `changes-range` cursor from `lower` (exclusive), bounded by `fence`.
/// `index` must carry the generation the cursor is issued at.
pub(crate) fn range_cursor(
    index: &IndexSummary,
    viewer: &AtlasPrincipal,
    lower: u64,
    fence: Option<Generation>,
) -> Result<AtlasCursor> {
    CodeCursorPosition::new(
        index,
        RANGE,
        cursor_digest(&(RANGE, viewer))?,
        CursorKey {
            integers: vec![lower, u64::from(u32::MAX)],
            bytes: Vec::new(),
        },
        fence,
    )?
    .encode()
}

/// The delivered generation and optional fence a `changes-range` cursor names.
fn range(
    index: &IndexSummary,
    viewer: &AtlasPrincipal,
    saved: &AtlasCursor,
) -> Result<(u64, Option<Generation>)> {
    let position = CodeCursorPosition::decode(saved)?;
    position.validate(index, RANGE, cursor_digest(&(RANGE, viewer))?)?;
    let key = &position.last_key;
    if key.integers.len() != 2 || !key.bytes.is_empty() || key.integers[1] != u64::from(u32::MAX) {
        return Err(se_types::code::cursor_invalid(
            "a changes range cursor, not a page of another query",
        ));
    }
    Ok((key.integers[0], position.change_fence))
}

pub(crate) fn changes(
    shared: &Shared,
    index: &IndexSummary,
    query: &ChangesQuery,
    viewer: &AtlasPrincipal,
) -> Result<Answer<Read<Page<CodeChange>>>> {
    query.scope.validate()?;
    let (since, found) = shared.with_reader(|reader| read_changes(reader, index, query, viewer))?;
    let found = match found {
        ChangesAnswer::Found(found) => found,
        ChangesAnswer::CommitNotObserved { commit } => {
            return Ok(unknown(
                index,
                &format!(
                    "commit {commit} was not observed by this index; ask for changes since a duration such as 10m or a time instead"
                ),
            ));
        }
    };
    let mut index = index.clone();
    if found.pruned {
        index.note(CoverageReason::RetentionGap);
    }
    let facts = |next, bytes| PageFacts {
        index: &index,
        budget: query.budget,
        after: query.next.as_ref(),
        next,
        examined: Examined::All,
        bytes,
    };
    // Sized with the widest cursor, so a page that gains one still fits.
    let widest = se_atlas_query::changes::resume_after(&since, i64::MAX, i64::MAX, i64::MAX);
    let mut bytes = envelope::<CodeChange>(facts(Some(cursor::wrap('c', &widest)?), 0))?;
    let max_bytes = query.budget.max_bytes as usize;
    let at = Generation(u64::try_from(found.through_generation).unwrap_or(0));
    let mut items = Vec::new();
    // The listed change the page ends on once the item or byte limit cuts it.
    let mut cut = None;
    let mut last = None;
    for entry in &found.entries {
        if entry
            .path
            .as_deref()
            .is_some_and(|path| !admits(&query.scope, path))
        {
            continue;
        }
        let Some(change) = change(entry, at)? else {
            continue;
        };
        let cost = size(&change) + 1;
        if items.is_empty() && bytes + cost > max_bytes {
            return Err(records::over_budget(bytes + cost, query.budget.max_bytes));
        }
        if items.len() >= usize::from(query.budget.max_results) || bytes + cost > max_bytes {
            cut = last;
            break;
        }
        bytes += cost;
        items.push(change);
        last = Some(entry);
    }
    let next = match cut {
        Some(entry) => Some(se_atlas_query::changes::resume_after(
            &since,
            found.through_generation,
            entry.generation,
            entry.ordinal,
        )),
        None => found.next_cursor.clone(),
    };
    let next = next.map(|next| cursor::wrap('c', &next)).transpose()?;
    let value = page(items, facts(next, bytes))?;
    checked(answer(&index, Read::Present { value }), query.budget)
}

/// One page from the store, with the start it was read from: a cursor for
/// the same request is minted from it.
fn read_changes(
    reader: &Reader,
    index: &IndexSummary,
    query: &ChangesQuery,
    viewer: &AtlasPrincipal,
) -> Result<(Since, ChangesAnswer)> {
    let since = baseline(reader.connection(), index, viewer, &query.since)?;
    let request = ChangesRequest {
        since,
        limit: usize::from(query.budget.max_results),
        cursor: query
            .next
            .as_ref()
            .map(|next| cursor::unwrap('c', next))
            .transpose()?,
    };
    let found = se_atlas_query::changes::changes(reader, &request).map_err(|e| index_error(&e))?;
    Ok((request.since, found))
}

/// The v5 start. A resume cursor starts after the generation it delivered
/// and, for an offer's retrieval cursor, stops at the offer's fence.
fn baseline(
    conn: &Connection,
    index: &IndexSummary,
    viewer: &AtlasPrincipal,
    since: &ChangeBaseline,
) -> Result<Since> {
    Ok(match since {
        ChangeBaseline::RelativeMillis(ms) => Since::RelativeMillis(*ms),
        ChangeBaseline::ObservedUnixMillis(at) => Since::ObservedUnixMillis(*at),
        ChangeBaseline::ObservedCommit(oid) => Since::Commit(hex(oid)),
        ChangeBaseline::ObservedCommitPrefix(prefix) => Since::Commit(prefix.clone()),
        ChangeBaseline::Cursor(saved) => {
            let current = at_published(conn, index)?;
            let (delivered, fence) = range(&current, viewer, saved)?;
            Since::AfterGeneration {
                after: i64::try_from(delivered).unwrap_or(i64::MAX),
                through: fence.map(|fence| i64::try_from(fence.0).unwrap_or(i64::MAX)),
            }
        }
    })
}

/// The summary at the generation this connection reads, so a cursor issued
/// from the store is judged against the store, not a cached summary.
fn at_published(conn: &Connection, index: &IndexSummary) -> Result<IndexSummary> {
    let published: i64 = conn
        .query_row("SELECT generation FROM meta WHERE singleton=1", [], |row| {
            row.get(0)
        })
        .map_err(|e| sqlite(&e))?;
    let mut current = index.clone();
    current.generation = Some(Generation(u64::try_from(published).unwrap_or(0)));
    Ok(current)
}

fn hex(oid: &GitObjectId) -> String {
    let bytes: &[u8] = match oid {
        GitObjectId::Sha1(bytes) => bytes,
        GitObjectId::Sha256(bytes) => bytes,
    };
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn change(entry: &ChangeEntry, at: Generation) -> Result<Option<CodeChange>> {
    let id = ChangeId {
        generation: Generation(u64::try_from(entry.generation).unwrap_or(0)),
        ordinal: u32::try_from(entry.ordinal).unwrap_or(u32::MAX),
    };
    let kind = match entry.kind {
        Some(V5Change::Added) => ChangeKind::Added,
        Some(V5Change::Removed) => ChangeKind::Removed,
        Some(V5Change::SignatureChanged) => ChangeKind::SignatureChanged,
        Some(V5Change::BodyChanged) => ChangeKind::BodyChanged,
        Some(V5Change::FileOnly) => ChangeKind::FileOnly,
        Some(V5Change::Bulk) | None => return bulk(entry, id).map(|b| b.map(CodeChange::Bulk)),
    };
    let Some(path) = entry.path.as_deref() else {
        return Ok(None);
    };
    Ok(Some(CodeChange::Edit(Box::new(CodeEdit {
        id,
        pointer: pointer(
            path,
            entry.line.map(|line| (line, line)),
            None,
            SnapshotFreshness::Current,
        )?,
        symbol: None,
        kind,
        baseline_reset: entry.baseline_reset,
        previous_hash: None,
        author: AuthorHint::Unknown,
        dependents: DependentCount {
            count: 0,
            at_generation: at,
            complete: false,
            reason: None,
        },
    }))))
}

fn bulk(entry: &ChangeEntry, id: ChangeId) -> Result<Option<BulkChange>> {
    let Some(text) = entry.bulk_json.as_deref() else {
        return Ok(None);
    };
    let detail: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| SeError::invalid("Atlas change", "a stored bulk summary"))?;
    let rebuild = detail.get("reason").and_then(serde_json::Value::as_str) == Some("cold_build");
    let files = detail
        .get("files")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    Ok(Some(BulkChange {
        id,
        reason: if rebuild {
            BulkReason::WatchReconcile
        } else {
            BulkReason::FilesystemBurst
        },
        files,
        semantic_changes: detail
            .get("symbol_changes")
            .and_then(serde_json::Value::as_u64),
        sample_paths: entry
            .path
            .as_deref()
            .and_then(|path| RelativePath::new(path).ok())
            .into_iter()
            .collect(),
        complete: true,
    }))
}

/// The resume digest for one viewer. The store does not attribute edits to
/// agents, so edits are counted as unattributed rather than shown as
/// another agent's work; rebuilds and bursts are listed.
pub(crate) fn resume(
    shared: &Shared,
    index: &IndexSummary,
    request: &ResumeRequest,
) -> Result<ResumeCode> {
    let viewer = AtlasPrincipal::Agent(request.viewer.clone());
    let scan = shared.with_reader(|reader| scan_resume(reader.connection(), index, request))?;
    // Cursors are issued at the generation the scan read, never a later one.
    let mut issued = index.clone();
    issued.generation = Some(Generation(scan.published));
    let mut output = ResumeCode {
        index: issued.clone(),
        state: ResumeCodeState::Available,
        items: scan.bulk.into_iter().map(ResumeChange::Bulk).collect(),
        omitted: (!scan.limited).then_some(scan.omitted_bulk),
        unattributed_omitted: Some(scan.unattributed),
        complete: false,
        omitted_since: None,
        advance: None,
        diagnostic: None,
    };
    output.complete = index.negative_complete()
        && !scan.gap
        && scan.unattributed == 0
        && output.omitted == Some(0);
    let fence = Generation(scan.published);
    if !output.complete {
        output.omitted_since = Some(range_cursor(&issued, &viewer, scan.lower, Some(fence))?);
    }
    output.state = if scan.gap {
        ResumeCodeState::BaselineGap
    } else if output.items.is_empty() && output.complete {
        ResumeCodeState::Zero
    } else if !index.negative_complete() {
        ResumeCodeState::Updating
    } else {
        ResumeCodeState::Available
    };
    let next = range_cursor(&issued, &viewer, scan.published, None)?;
    let mut offer = blake3::Hasher::new();
    offer.update(request.viewer.as_str().as_bytes());
    offer.update(
        request
            .saved_cursor
            .as_ref()
            .map_or("", |c| c.as_str())
            .as_bytes(),
    );
    offer.update(&request.cursor_revision.to_le_bytes());
    offer.update(next.as_str().as_bytes());
    offer.update(&(output.items.len() as u64).to_le_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&offer.finalize().as_bytes()[..16]);
    output.advance = Some(ResumeAdvance {
        offer: ResumeOfferId(id),
        expected_cursor: request.saved_cursor.clone(),
        expected_revision: request.cursor_revision,
        next_cursor: next,
        fence,
    });
    Ok(output)
}

/// The retrieval cursor for an offer that is about to lose items it listed:
/// everything after the viewer's saved position, up to the offer's fence.
/// `None` when the offer carries no advance to bound it.
pub fn retrieval(output: &ResumeCode, viewer: &AgentId) -> Result<Option<AtlasCursor>> {
    let Some(advance) = &output.advance else {
        return Ok(None);
    };
    let viewer = AtlasPrincipal::Agent(viewer.clone());
    let mut issued = output.index.clone();
    issued.generation = Some(advance.fence);
    let lower = match &advance.expected_cursor {
        Some(saved) => range(&issued, &viewer, saved).map_or(0, |(lower, _)| lower),
        None => 0,
    };
    range_cursor(&issued, &viewer, lower, Some(advance.fence)).map(Some)
}

struct ResumeScan {
    lower: u64,
    published: u64,
    /// No usable saved cursor, or it predates retained history.
    gap: bool,
    bulk: Vec<BulkChange>,
    omitted_bulk: u64,
    unattributed: u64,
    limited: bool,
}

fn scan_resume(
    conn: &Connection,
    index: &IndexSummary,
    request: &ResumeRequest,
) -> Result<ResumeScan> {
    let current = at_published(conn, index)?;
    let published = current.generation.map_or(0, |generation| {
        i64::try_from(generation.0).unwrap_or(i64::MAX)
    });
    let floor: i64 = conn
        .query_row(
            "SELECT coalesce(min(generation), 0) FROM generations",
            [],
            |row| row.get(0),
        )
        .map_err(|e| sqlite(&e))?;
    let viewer = AtlasPrincipal::Agent(request.viewer.clone());
    // A cursor from another epoch, viewer or query is a gap, never an error:
    // the digest then starts at the oldest retained change.
    let saved = request
        .saved_cursor
        .as_ref()
        .and_then(|saved| range(&current, &viewer, saved).ok())
        .filter(|(_, fence)| fence.is_none())
        .and_then(|(value, _)| i64::try_from(value).ok());
    let (lower, gap) = match saved {
        Some(saved) if saved + 1 >= floor && saved <= published => (saved, false),
        _ => (floor.saturating_sub(1).max(0), true),
    };
    let mut select = conn
        .prepare_cached(
            "SELECT generation, ordinal, kind, path, bulk_json FROM changes
             WHERE generation > ?1 AND generation <= ?2
             ORDER BY generation DESC, ordinal DESC LIMIT ?3",
        )
        .map_err(|e| sqlite(&e))?;
    let rows = select
        .query_map(rusqlite::params![lower, published, RESUME_SCAN], |row| {
            Ok(ChangeEntry {
                generation: row.get(0)?,
                ordinal: row.get(1)?,
                observed_unix_ms: 0,
                kind: V5Change::parse(&row.get::<_, String>(2)?),
                kind_text: String::new(),
                path: row.get(3)?,
                symbol: None,
                symbol_kind: None,
                line: None,
                baseline_reset: false,
                bulk_json: row.get(4)?,
            })
        })
        .map_err(|e| sqlite(&e))?;
    let mut scan = ResumeScan {
        lower: u64::try_from(lower).unwrap_or(0),
        published: u64::try_from(published).unwrap_or(0),
        gap,
        bulk: Vec::new(),
        omitted_bulk: 0,
        unattributed: 0,
        limited: false,
    };
    let mut seen = 0i64;
    for row in rows {
        let entry = row.map_err(|e| sqlite(&e))?;
        seen += 1;
        let id = ChangeId {
            generation: Generation(u64::try_from(entry.generation).unwrap_or(0)),
            ordinal: u32::try_from(entry.ordinal).unwrap_or(u32::MAX),
        };
        match entry.kind {
            Some(V5Change::Bulk) | None => match bulk(&entry, id)? {
                Some(change) if scan.bulk.len() < RESUME_BULK => scan.bulk.push(change),
                Some(_) => scan.omitted_bulk += 1,
                None => {}
            },
            Some(_) => scan.unattributed += 1,
        }
    }
    scan.limited = seen >= RESUME_SCAN;
    Ok(scan)
}
