//! Regex search: required literals of the expression narrow the files
//! through the trigram index, and the best candidates are confirmed by
//! running the expression over their lines.
use super::{
    Budget, HitField, MatchKind, ScanReason, Scope, SearchOutcome, SearchRequest, confirm,
    index::{FileRows, Reads, choose, page_into},
    rank::{Candidate, Candidates, TermHit},
};
use crate::{Result, custody::IndexSourceRoot, extract::tokens, store::ReadSnapshot};
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashSet;

/// A piece found in more tokens than this does not narrow anything.
const PIECE_TOKEN_CAP: usize = 1_024;
/// Pieces intersected, fewest tokens first.
const PIECES_USED: usize = 3;

/// Regex search through literal anchors, or why the tree must be scanned
/// instead.
pub(crate) fn search(
    snapshot: &ReadSnapshot<'_>,
    root: &IndexSourceRoot,
    request: &SearchRequest,
    pattern: &str,
    pieces: &[String],
    budget: &Budget,
) -> Result<std::result::Result<SearchOutcome, ScanReason>> {
    let matcher = confirm::regex(pattern)?;
    let conn = snapshot.connection();
    // Trigrams land only when a cold build finishes; until then an empty
    // trigram answer proves nothing.
    if cold_build_publishing(conn)? {
        return Ok(Err(ScanReason::TrigramsPending));
    }
    let Some(holders) = regex_files(snapshot, pieces)? else {
        return Ok(Err(ScanReason::NoLiteralAnchor));
    };
    let scope = Scope::new(request);
    let mut rows = FileRows::new(conn);
    let mut outcome = SearchOutcome::default();
    let mut ranked: Vec<i64> = holders.into_iter().collect();
    ranked.sort_unstable();
    let chosen = choose(&ranked, &scope, &mut rows, budget, &mut outcome)?;
    let mut candidates = Candidates::default();
    let hit = TermHit {
        kind: MatchKind::Regex,
        evidence: MatchKind::Regex.evidence(),
        idf: 0,
    };
    let judge = |file: i64, path: &str, line: u32, field: HitField, text: &str| {
        let mut candidate = Candidate::new(file, path, line, field, 1);
        candidate.record(0, hit);
        candidate.text = confirm::hit_text(text);
        Some(candidate)
    };
    let reads = Reads {
        conn,
        root,
        matcher: &matcher,
        budget,
    };
    reads.confirm(&chosen, &mut outcome, &mut candidates, judge)?;
    page_into(request, &mut outcome, candidates);
    Ok(Ok(outcome))
}

fn cold_build_publishing(conn: &Connection) -> Result<bool> {
    let watermark: Option<i64> = conn
        .prepare_cached(
            "SELECT json_extract(state_json, '$.cold_posted_through') FROM meta WHERE singleton=1",
        )?
        .query_row([], |row| row.get(0))
        .optional()?
        .flatten();
    Ok(watermark.is_some())
}

/// Files holding a token that contains every usable piece, using the
/// pieces found in the fewest tokens. `None` when no piece is usable.
///
/// A piece no trigram-indexed token contains proves nothing: the text may
/// hold it inside a part the trigram index leaves out (non-ASCII, longer
/// than 48 bytes, or a long hex run). Such a piece is skipped, never read as
/// an empty answer.
fn regex_files(snapshot: &ReadSnapshot<'_>, pieces: &[String]) -> Result<Option<HashSet<i64>>> {
    let mut narrowing: Vec<Vec<i64>> = Vec::new();
    for piece in pieces {
        if let Some(ids) = piece_tokens(snapshot, piece)?
            && !ids.is_empty()
        {
            narrowing.push(ids);
        }
    }
    if narrowing.is_empty() {
        return Ok(None);
    }
    narrowing.sort_by_key(Vec::len);
    let mut holders: Option<HashSet<i64>> = None;
    for ids in narrowing.into_iter().take(PIECES_USED) {
        let mut files = HashSet::new();
        for id in ids {
            files.extend(
                snapshot
                    .read_postings(id)?
                    .into_iter()
                    .map(|(file, _)| file),
            );
        }
        holders = Some(match holders {
            None => files,
            Some(known) => known.intersection(&files).copied().collect(),
        });
    }
    Ok(holders)
}

/// Vocab ids of identifier tokens containing `piece`, or `None` when too
/// many do for the piece to narrow anything.
fn piece_tokens(snapshot: &ReadSnapshot<'_>, piece: &str) -> Result<Option<Vec<i64>>> {
    let mut common: Option<Vec<i64>> = None;
    for gram in tokens::trigrams(piece) {
        let ids = snapshot.gram_tokens(gram)?;
        common = Some(match common {
            None => ids,
            Some(known) => known
                .into_iter()
                .filter(|id| ids.binary_search(id).is_ok())
                .collect(),
        });
    }
    let common = common.unwrap_or_default();
    if common.len() > PIECE_TOKEN_CAP {
        return Ok(None);
    }
    let mut text_of = snapshot
        .connection()
        .prepare_cached("SELECT tok FROM vocab WHERE id=?1")?;
    let mut out = Vec::new();
    for id in common {
        let text: Option<String> = text_of.query_row([id], |row| row.get(0)).optional()?;
        if text.is_some_and(|text| text.contains(piece)) {
            out.push(id);
        }
    }
    Ok(Some(out))
}
