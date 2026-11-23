//! `changes` and the resume digest on the wire. Generations order history;
//! a resume cursor names the last generation a viewer was offered, so a
//! later digest starts after it. Building an offer never advances anything:
//! core commits the cursor only when the consumer acknowledges delivery.
use super::{PageFacts, answer, checked, cursor, find::admits, page, pointer, size, unknown};
use crate::{
    error::{index_error, sqlite},
    root::Shared,
};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::store::{ChangeKind as V5Change, Reader};
use se_atlas_query::changes::{ChangeEntry, ChangesAnswer, ChangesRequest, Since};
use se_types::code::AtlasText as _;
use se_types::{
    Page, Read, Result, SeError,
    code::{
        Answer, AuthorHint, BulkChange, BulkReason, ChangeBaseline, ChangeId, ChangeKind,
        ChangesQuery, CodeChange, CodeEdit, CoverageReason, DependentCount, Generation,
        GitObjectId, IndexSummary, RelativePath, ResumeAdvance, ResumeChange, ResumeCode,
        ResumeCodeState, ResumeOfferId, ResumeRequest, SnapshotFreshness,
    },
};

/// Serialized bytes assumed per change when sizing a page.
const ROW_BYTES: usize = 420;
/// Bulk changes a resume digest lists.
const RESUME_BULK: usize = 5;
/// Change rows a resume digest scans.
const RESUME_SCAN: i64 = 513;

pub(crate) fn changes(
    shared: &Shared,
    index: &IndexSummary,
    query: &ChangesQuery,
) -> Result<Answer<Read<Page<CodeChange>>>> {
    query.scope.validate()?;
    let fit = (query.budget.max_bytes as usize / ROW_BYTES).max(1);
    let reader = shared.reader()?;
    let read = read_changes(&reader, query, fit);
    shared.give_back(reader);
    let (found, lower) = read?;
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
    let at = Generation(u64::try_from(found.through_generation).unwrap_or(0));
    let mut items = Vec::new();
    for entry in &found.entries {
        if entry.generation <= lower
            || entry
                .path
                .as_deref()
                .is_some_and(|path| !admits(&query.scope, path))
        {
            continue;
        }
        if let Some(change) = change(entry, at)? {
            items.push(change);
        }
    }
    let next = found
        .next_cursor
        .as_deref()
        .map(|next| cursor::wrap('c', next))
        .transpose()?;
    let bytes = items.iter().map(|item| size(item) + 1).sum();
    let value = page(
        items,
        PageFacts {
            index: &index,
            budget: query.budget,
            after: query.next.as_ref(),
            next,
            partial: false,
            bytes,
        },
    )?;
    checked(answer(&index, Read::Present { value }), query.budget)
}

fn read_changes(reader: &Reader, query: &ChangesQuery, fit: usize) -> Result<(ChangesAnswer, i64)> {
    let (since, lower) = baseline(reader.connection(), &query.since)?;
    let request = ChangesRequest {
        since,
        limit: usize::from(query.budget.max_results).min(fit),
        cursor: query
            .next
            .as_ref()
            .map(|next| cursor::unwrap('c', next))
            .transpose()?,
    };
    let found = se_atlas_query::changes::changes(reader, &request).map_err(|e| index_error(&e))?;
    Ok((found, lower))
}

/// The v5 start, and the generation a resume cursor already delivered.
fn baseline(conn: &Connection, since: &ChangeBaseline) -> Result<(Since, i64)> {
    Ok(match since {
        ChangeBaseline::RelativeMillis(ms) => (Since::RelativeMillis(*ms), 0),
        ChangeBaseline::ObservedUnixMillis(at) => (Since::ObservedUnixMillis(*at), 0),
        ChangeBaseline::ObservedCommit(oid) => (Since::Commit(hex(oid)), 0),
        ChangeBaseline::ObservedCommitPrefix(prefix) => (Since::Commit(prefix.clone()), 0),
        ChangeBaseline::Cursor(saved) => {
            let delivered = i64::try_from(cursor::number('g', saved)?).unwrap_or(i64::MAX);
            let observed: Option<i64> = conn
                .query_row(
                    "SELECT observed_unix_ms FROM generations WHERE generation <= ?1
                     ORDER BY generation DESC LIMIT 1",
                    [delivered],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| sqlite(&e))?;
            (Since::ObservedUnixMillis(observed.unwrap_or(0)), delivered)
        }
    })
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
    let reader = shared.reader()?;
    let scanned = scan_resume(reader.connection(), request);
    shared.give_back(reader);
    let scan = scanned?;
    let mut output = ResumeCode {
        index: index.clone(),
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
    if !output.complete {
        output.omitted_since = Some(cursor::wrap('g', &scan.lower.to_string())?);
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
    let next = cursor::wrap('g', &scan.published.to_string())?;
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
        fence: Generation(scan.published),
    });
    Ok(output)
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

fn scan_resume(conn: &Connection, request: &ResumeRequest) -> Result<ResumeScan> {
    let published: i64 = conn
        .query_row("SELECT generation FROM meta WHERE singleton=1", [], |row| {
            row.get(0)
        })
        .map_err(|e| sqlite(&e))?;
    let floor: i64 = conn
        .query_row(
            "SELECT coalesce(min(generation), 0) FROM generations",
            [],
            |row| row.get(0),
        )
        .map_err(|e| sqlite(&e))?;
    let saved = request
        .saved_cursor
        .as_ref()
        .and_then(|saved| cursor::number('g', saved).ok())
        .and_then(|value| i64::try_from(value).ok());
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
