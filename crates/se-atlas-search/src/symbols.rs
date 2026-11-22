//! Symbol definitions from the index: those a matched word names, those a
//! literal names (`app-server`, `QueryReader::new`, `Reader.open`), and the
//! labelled guesses offered when nothing matched.
use crate::{
    Hit, HitField, HitSource, MatchKind, Scope,
    confirm::Covers,
    index::Plan,
    query::Literal,
    rank::{Candidate, Candidates},
    read::{FileRow, FileRows},
};
use rusqlite::Connection;
use se_atlas_index::{Result, extract::SymbolKind, store::ReadSnapshot};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

/// Symbol rows read per matched token.
const SYMBOLS_PER_TOKEN: i64 = 512;
const SCOPED_SYMBOLS_PER_TOKEN: i64 = 8_192;
const BY_NAME: &str =
    "SELECT file, line, kind, sig FROM sym WHERE name=?1 ORDER BY file, line LIMIT ?2";
/// Definitions named `?1` with their parent symbol's name, if any, and path.
const BY_NAME_IN_CONTEXT: &str = "SELECT s.file, s.line, s.kind, s.sig, v.tok, f.path
 FROM sym s JOIN files f ON f.id = s.file
 LEFT JOIN sym p ON p.id = s.parent LEFT JOIN vocab v ON v.id = p.name
 WHERE s.name=?1 ORDER BY s.file, s.line LIMIT ?2";

/// The limit applies before the scope filter, so a filtered search reads
/// further to find definitions inside its scope.
fn limit(scope: &Scope) -> i64 {
    if scope.filters() {
        SCOPED_SYMBOLS_PER_TOKEN
    } else {
        SYMBOLS_PER_TOKEN
    }
}

/// One `sym` row: file, line, kind code and declaration header.
type SymbolRow = (i64, i64, i64, Option<String>);

fn symbol_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SymbolRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn candidate(plan: &Plan, row: &FileRow, symbol: SymbolRow, file: i64) -> Candidate {
    let (_, line, kind, sig) = symbol;
    let line = u32::try_from(line).unwrap_or(0);
    let mut candidate = Candidate::new(file, &row.path, line, HitField::Symbol, plan.terms);
    candidate.symbol_kind = SymbolKind::from_code(kind);
    candidate.text = sig.unwrap_or_default();
    candidate
}

/// Symbol definitions named by a matched token. Returns the files holding one.
pub(crate) fn token_hits(
    conn: &Connection,
    plan: &Plan,
    scope: &Scope,
    rows: &mut FileRows<'_>,
    candidates: &mut Candidates,
) -> Result<HashSet<i64>> {
    let mut files = HashSet::new();
    let mut select = conn.prepare_cached(BY_NAME)?;
    for token in &plan.symbol_tokens {
        for symbol in select.query_map(rusqlite::params![token.id, limit(scope)], symbol_row)? {
            let symbol = symbol?;
            let file = symbol.0;
            let Some(row) = rows.admitted(file, scope)? else {
                continue;
            };
            let mut candidate = candidate(plan, &row, symbol, file);
            plan.apply(&mut candidate, token.covers, token.hit);
            candidate.full_compact = token.full;
            candidates.add(candidate);
            files.insert(file);
        }
    }
    Ok(files)
}

/// Symbol definitions a literal names: the literal as one name, or a
/// qualified name whose last segment is the symbol and whose qualifier ends
/// in its parent's name. Only that last qualifier segment is compared; for a
/// top-level definition it names the module, so it must match the file's
/// stem or directory. A hit must satisfy every literal of the query.
/// Returns the files holding one.
pub(crate) fn literal_hits(
    snapshot: &ReadSnapshot<'_>,
    plan: &Plan,
    literals: &[Literal],
    scope: &Scope,
    rows: &mut FileRows<'_>,
    candidates: &mut Candidates,
) -> Result<HashSet<i64>> {
    let conn = snapshot.connection();
    let mut by_name = conn.prepare_cached(BY_NAME)?;
    let mut in_context = conn.prepare_cached(BY_NAME_IN_CONTEXT)?;
    let mut by_place: HashMap<(i64, i64), Candidate> = HashMap::new();
    for (offset, literal) in literals.iter().enumerate() {
        let term = plan.words + offset;
        let Some(pattern) = plan
            .patterns
            .iter()
            .find(|pattern| pattern.covers == Covers::Term(term))
        else {
            continue;
        };
        let mut found: Vec<SymbolRow> = Vec::new();
        if let Some(id) = snapshot.token_id(&literal.text)? {
            for symbol in by_name.query_map(rusqlite::params![id, limit(scope)], symbol_row)? {
                found.push(symbol?);
            }
        }
        if let Some((parent, name)) = qualified(&literal.text)
            && let Some(id) = snapshot.token_id(name)?
        {
            let named = in_context.query_map(rusqlite::params![id, limit(scope)], |row| {
                Ok((
                    symbol_row(row)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;
            for symbol in named {
                let (symbol, parent_name, path) = symbol?;
                if qualifies(parent, parent_name.as_deref(), &path) {
                    found.push(symbol);
                }
            }
        }
        for symbol in found {
            let place = (symbol.0, symbol.1);
            if let Some(known) = by_place.get_mut(&place) {
                known.record(term, pattern.hit);
                continue;
            }
            let Some(row) = rows.admitted(symbol.0, scope)? else {
                continue;
            };
            let mut candidate = candidate(plan, &row, symbol, place.0);
            plan.match_text(&candidate.text.clone(), &mut candidate);
            candidate.record(term, pattern.hit);
            candidate.full_compact |= pattern.full;
            by_place.insert(place, candidate);
        }
    }
    let mut files = HashSet::new();
    for candidate in by_place.into_values() {
        if plan.satisfied(&candidate) {
            files.insert(candidate.file);
            candidates.add(candidate);
        }
    }
    Ok(files)
}

/// `(parent, name)` of a qualified literal such as `queryreader::new` or
/// `reader.open`, cut at its last `::` or `.`.
fn qualified(text: &str) -> Option<(&str, &str)> {
    let cut = |separator: &str| text.rfind(separator).map(|at| (at, separator.len()));
    let (at, width) = [cut("::"), cut(".")]
        .into_iter()
        .flatten()
        .max_by_key(|(at, _)| *at)?;
    let parent = last_segment(&text[..at]);
    let name = &text[at + width..];
    let word =
        |part: &str| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_');
    (word(parent) && word(name)).then_some((parent, name))
}

/// Whether `parent`, a qualifier's last segment, names a definition's parent
/// symbol or, for a top-level definition, its module: the file (`store.rs`)
/// or its directory (`store/mod.rs`, a Go package).
fn qualifies(parent: &str, parent_name: Option<&str>, path: &str) -> bool {
    if let Some(name) = parent_name {
        return last_segment(name) == parent;
    }
    let mut components = path.rsplit('/');
    let file = components.next().unwrap_or(path);
    let stem = file.split('.').next().unwrap_or(file);
    let directory = components.next().unwrap_or_default();
    [stem, directory]
        .iter()
        .any(|module| module.to_lowercase() == parent)
}

/// The last `::` or `.` segment of a name (`crate::store::reader` gives
/// `reader`).
fn last_segment(name: &str) -> &str {
    let tail = name.rsplit("::").next().unwrap_or(name);
    tail.rsplit('.').next().unwrap_or(tail)
}

/// Up to three labelled close spellings, each placed at its first symbol
/// definition or first file in scope.
pub(crate) fn guesses(
    snapshot: &ReadSnapshot<'_>,
    plan: &Plan,
    scope: &Scope,
    rows: &mut FileRows<'_>,
) -> Result<Vec<Hit>> {
    let mut out: Vec<Hit> = Vec::new();
    let mut seen = HashSet::new();
    let mut symbols = snapshot.connection().prepare_cached(
        "SELECT file, line, kind FROM sym WHERE name=?1 ORDER BY file, line LIMIT 16",
    )?;
    for token in &plan.near {
        if out.len() == 3 || !seen.insert(token.id) {
            continue;
        }
        let mut place = None;
        let found = symbols.query_map([token.id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for symbol in found {
            let (file, line, kind) = symbol?;
            if let Some(row) = rows.admitted(file, scope)? {
                let line = u32::try_from(line).unwrap_or(0);
                place = Some((row, line, HitField::Symbol, SymbolKind::from_code(kind)));
                break;
            }
        }
        if place.is_none() {
            place = first_file(snapshot, token.id, scope, rows)?
                .map(|row| (row, 0, HitField::Path, None));
        }
        if let Some((row, line, field, symbol_kind)) = place {
            out.push(Hit {
                path: row.path.clone(),
                line,
                field,
                symbol_kind,
                text: token.text.clone(),
                match_kind: MatchKind::Guess,
                terms_matched: 0,
                terms: plan.terms,
                score: 0,
                source: HitSource::Index,
            });
        }
    }
    Ok(out)
}

fn first_file(
    snapshot: &ReadSnapshot<'_>,
    token: i64,
    scope: &Scope,
    rows: &mut FileRows<'_>,
) -> Result<Option<Rc<FileRow>>> {
    for (file, _) in snapshot.read_postings(token)? {
        if let Some(row) = rows.admitted(file, scope)? {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_literals_cut_at_their_last_separator() {
        assert_eq!(qualified("queryreader::new"), Some(("queryreader", "new")));
        assert_eq!(
            qualified("crate::store::reader.open"),
            Some(("reader", "open"))
        );
        assert_eq!(qualified("self.conn.run"), Some(("conn", "run")));
        assert_eq!(qualified("a::"), None);
        assert_eq!(qualified("open the door"), None);
        assert_eq!(qualified("->"), None);
        assert_eq!(last_segment("crate::cache::connection"), "connection");
        assert!(!qualifies("reader", Some("crate::queryreader"), "a.rs"));
        assert!(qualifies("queryreader", Some("crate::queryreader"), "a.rs"));
        assert!(qualifies("store", None, "src/Store.rs"));
        assert!(qualifies("store", None, "src/store/mod.rs"));
        assert!(!qualifies("store", Some("reader"), "src/store.rs"));
    }
}
