//! Regex search: required literals of the expression narrow the files
//! through the index, and the best candidates, densest first, are confirmed
//! by running the expression over their lines.
//!
//! A piece narrows only through every indexed token that may hold it. The
//! trigram index covers identifier tokens of 3 to 48 lowercase ASCII bytes;
//! every other token holding the piece (a longer run such as a 64-digit hash,
//! a joined name such as `a::b`, a part with other letters) is found by one
//! scan of the vocabulary, so a match inside one is never dropped. A piece of
//! hex digits alone never narrows: it may lie inside a hex run longer than the
//! index's 128-byte token cap, which no row records.
//!
//! Not covered: a piece inside a single unbroken run of letters longer than
//! 128 bytes, a case-insensitive piece that the text's own casing splits
//! inside a token longer than 128 bytes, or a joined name such as `a_b` whose
//! only occurrence is inside a token longer than 128 bytes. The index records
//! none of them.
use crate::{
    Budget, HitField, MatchKind, ScanReason, Scope, SearchOutcome, SearchRequest, confirm,
    rank::{Candidate, Candidates, TermHit},
    read::{FileRows, Reads, choose, page_into},
};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::{Result, custody::IndexSourceRoot, extract::tokens, store::ReadSnapshot};
use std::collections::HashMap;

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
    let holders = match regex_files(snapshot, pieces, budget)? {
        Ok(holders) => holders,
        Err(reason) => return Ok(Err(reason)),
    };
    let scope = Scope::new(request);
    let mut rows = FileRows::new(conn);
    let mut outcome = SearchOutcome::default();
    let mut dense: Vec<(u32, i64)> = holders.into_iter().map(|(file, tf)| (tf, file)).collect();
    dense.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let ranked: Vec<i64> = dense.into_iter().map(|(_, file)| file).collect();
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

/// Files holding a token that contains every usable piece, each with the
/// smallest summed tf among the pieces, using the pieces found in the fewest
/// tokens. `None` when no piece is usable.
///
/// A piece no indexed token contains proves nothing and is skipped, never
/// read as an empty answer; so is a piece of hex digits alone.
fn regex_files(
    snapshot: &ReadSnapshot<'_>,
    pieces: &[String],
    budget: &Budget,
) -> Result<std::result::Result<HashMap<i64, u32>, ScanReason>> {
    let mut narrowing: Vec<(&str, Vec<i64>)> = Vec::new();
    for piece in pieces {
        if piece.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Some(ids) = piece_tokens(snapshot, piece)?
            && !ids.is_empty()
        {
            narrowing.push((piece, ids));
        }
    }
    if narrowing.is_empty() {
        return Ok(Err(ScanReason::NoLiteralAnchor));
    }
    narrowing.sort_by_key(|(_, ids)| ids.len());
    narrowing.truncate(PIECES_USED);
    if let Err(reason) = add_untrigrammed(snapshot, &mut narrowing, budget)? {
        return Ok(Err(reason));
    }
    if narrowing.is_empty() {
        return Ok(Err(ScanReason::NoLiteralAnchor));
    }
    let mut holders: Option<HashMap<i64, u32>> = None;
    for (_, ids) in narrowing {
        let mut files: HashMap<i64, u32> = HashMap::new();
        for id in ids {
            for (file, tf) in snapshot.read_postings(id)? {
                let sum = files.entry(file).or_insert(0);
                *sum = sum.saturating_add(tf);
            }
        }
        holders = Some(match holders {
            None => files,
            Some(known) => files
                .into_iter()
                .filter_map(|(file, tf)| known.get(&file).map(|held| (file, tf.min(*held))))
                .collect(),
        });
    }
    Ok(holders.ok_or(ScanReason::NoLiteralAnchor))
}

/// Maximum matching vocabulary rows returned per piece when supplementing
/// trigram hits with untrigrammed tokens. A piece exceeding this cap is
/// dropped individually so rarer pieces still narrow the query.
const UNTRIGRAMMED_PIECE_CAP: usize = PIECE_TOKEN_CAP * 4;
/// Keyset window of `vocab(id)` rows inspected per SQLite step so the shared
/// deadline is checked frequently even when a rare piece matches few rows.
const VOCAB_SCAN_CHUNK: i64 = 4_096;

/// Add to each piece the indexed tokens holding it that the trigram index
/// leaves out, scanning `vocab` in bounded primary-key chunks so the shared
/// budget is enforced on large vocabularies. Drops only an overflowing piece
/// rather than discarding all narrowing.
fn add_untrigrammed(
    snapshot: &ReadSnapshot<'_>,
    narrowing: &mut Vec<(&str, Vec<i64>)>,
    budget: &Budget,
) -> Result<std::result::Result<(), ScanReason>> {
    let conn = snapshot.connection();
    let max_id: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM vocab", [], |r| r.get(0))?;
    let mut select = conn.prepare_cached(
        "SELECT id, tok FROM vocab WHERE id > ?1 AND id <= ?2 AND instr(tok, ?3) > 0 LIMIT ?4",
    )?;
    let mut keep = Vec::with_capacity(narrowing.len());
    for (piece, ids) in narrowing.iter_mut() {
        let mut matched = 0usize;
        let mut overflowed = false;
        let mut cursor = 0i64;
        while cursor < max_id {
            if budget.expired() {
                return Ok(Err(ScanReason::VocabBudgetExceeded));
            }
            let upper = cursor.saturating_add(VOCAB_SCAN_CHUNK).min(max_id);
            let limit = (UNTRIGRAMMED_PIECE_CAP - matched + 1) as i64;
            let rows = select
                .query_map(rusqlite::params![cursor, upper, *piece, limit], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?;
            for row in rows {
                matched += 1;
                if matched > UNTRIGRAMMED_PIECE_CAP {
                    overflowed = true;
                    break;
                }
                let (id, token) = row?;
                // Trigram tokens were found already; the sets never overlap.
                if tokens::is_gram_token(&token) {
                    continue;
                }
                if ids.len() >= PIECE_TOKEN_CAP {
                    overflowed = true;
                    break;
                }
                ids.push(id);
            }
            if overflowed {
                break;
            }
            cursor = upper;
        }
        keep.push(!overflowed);
    }
    let mut idx = 0usize;
    narrowing.retain(|_| {
        let retained = keep[idx];
        idx += 1;
        retained
    });
    Ok(Ok(()))
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
