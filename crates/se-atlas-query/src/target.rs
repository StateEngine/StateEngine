//! Positional target resolution, shared by every query.
//!
//! An automatic target is tried, inside one snapshot, as: an indexed path
//! (a path the private-file policy denies is refused, never looked up), then
//! `path:line` for the innermost symbol spanning that line (the file itself
//! when none does), then an exact symbol name (case-insensitive, optionally
//! qualified as `Parent::name` or `Parent.name`). When nothing matches, up
//! to three close spellings come back from the typo-tolerant matcher.
use super::dir_of;
use rusqlite::{OptionalExtension, Row, params};
use se_atlas_index::{
    Result,
    extract::{SymbolKind, display_name},
    policy,
    store::{ReadSnapshot, Reader},
};

/// Close spellings offered for a target that matched nothing.
pub const MAX_SUGGESTIONS: usize = 3;
/// Definitions kept for one name.
pub const MAX_DEFINITIONS: usize = 64;
/// Definitions of one name judged for an exact spelling.
pub const MAX_SCANNED_DEFINITIONS: usize = 4_096;

/// What the caller asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A path, `path:line`, or symbol name, resolved in that order.
    Auto(String),
    /// A root-relative path only.
    File(String),
    /// A symbol name only.
    Symbol(String),
}

/// One indexed file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
    pub id: i64,
    pub path: String,
    pub key: Vec<u8>,
    pub lang: String,
    /// `files.flags`; see [`se_atlas_index::extract::flags`].
    pub flags: u32,
}

/// One symbol definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolRef {
    pub id: i64,
    pub key: Vec<u8>,
    pub file: FileRef,
    /// The name as declared when the signature still shows it; otherwise
    /// the indexed lowercase form.
    pub name: String,
    pub kind: Option<SymbolKind>,
    pub line: u32,
    pub end_line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    File(FileRef),
    /// Every definition of the name (at least one), or the one symbol that
    /// encloses a `path:line`. `capped` says the name has more than
    /// [`MAX_DEFINITIONS`] definitions and only the first are listed.
    Symbols {
        symbols: Vec<SymbolRef>,
        capped: bool,
    },
    Refused {
        path: String,
    },
    NotFound {
        suggestions: Vec<String>,
    },
}

/// Resolve a target against the index behind `reader`.
pub fn resolve(reader: &Reader, target: &Target) -> Result<Resolved> {
    resolve_in(&reader.snapshot()?, target)
}

pub(crate) fn resolve_in(snapshot: &ReadSnapshot<'_>, target: &Target) -> Result<Resolved> {
    match target {
        Target::File(path) => {
            let path = normalize(path);
            if policy::file_denied(&path) {
                return Ok(Resolved::Refused { path });
            }
            Ok(match file_by_path(snapshot, &path)? {
                Some(file) => Resolved::File(file),
                None => Resolved::NotFound {
                    suggestions: path_suggestions(snapshot, &path)?,
                },
            })
        }
        Target::Symbol(name) => match symbols_named(snapshot, name.trim())? {
            (symbols, capped) if !symbols.is_empty() => Ok(Resolved::Symbols { symbols, capped }),
            _ => Ok(Resolved::NotFound {
                suggestions: symbol_suggestions(snapshot, name.trim())?,
            }),
        },
        Target::Auto(text) => auto(snapshot, text.trim()),
    }
}

fn auto(snapshot: &ReadSnapshot<'_>, text: &str) -> Result<Resolved> {
    let path = normalize(text);
    // Judged before `./` is stripped, so `./credentials` stays a path.
    let path_like = text.contains(['/', '\\', '.']);
    if path_like && policy::file_denied(&path) {
        return Ok(Resolved::Refused { path });
    }
    if let Some(file) = file_by_path(snapshot, &path)? {
        return Ok(Resolved::File(file));
    }
    if let Some((file_part, line)) = split_line(&path) {
        if policy::file_denied(file_part) {
            return Ok(Resolved::Refused {
                path: file_part.to_owned(),
            });
        }
        if let Some(file) = file_by_path(snapshot, file_part)? {
            return Ok(match enclosing(snapshot, &file, line)? {
                Some(symbol) => Resolved::Symbols {
                    symbols: vec![symbol],
                    capped: false,
                },
                None => Resolved::File(file),
            });
        }
    }
    let (symbols, capped) = symbols_named(snapshot, text)?;
    if !symbols.is_empty() {
        return Ok(Resolved::Symbols { symbols, capped });
    }
    if policy::file_denied(&path) {
        return Ok(Resolved::Refused { path });
    }
    let mut suggestions = if path.contains('/') {
        path_suggestions(snapshot, split_line(&path).map_or(&path, |(file, _)| file))?
    } else {
        Vec::new()
    };
    for spelling in symbol_suggestions(snapshot, text)? {
        if suggestions.len() < MAX_SUGGESTIONS && !suggestions.contains(&spelling) {
            suggestions.push(spelling);
        }
    }
    Ok(Resolved::NotFound { suggestions })
}

/// Slash-separated, without a leading `./` or trailing slash.
pub(crate) fn normalize(path: &str) -> String {
    let path = path.trim().replace('\\', "/");
    let mut path = path.as_str();
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    path.trim_end_matches('/').to_owned()
}

/// `path:line` with a positive line number.
fn split_line(text: &str) -> Option<(&str, u32)> {
    let (path, line) = text.rsplit_once(':')?;
    let line: u32 = line.parse().ok().filter(|line| *line > 0)?;
    (!path.is_empty()).then_some((path, line))
}

const FILE_COLUMNS: &str = "f.id, f.path, f.key, f.lang, f.flags";

fn file_row(row: &Row<'_>, at: usize) -> rusqlite::Result<FileRef> {
    Ok(FileRef {
        id: row.get(at)?,
        path: row.get(at + 1)?,
        key: row.get(at + 2)?,
        lang: row.get(at + 3)?,
        flags: row.get::<_, Option<u32>>(at + 4)?.unwrap_or(0),
    })
}

pub(crate) fn file_by_path(snapshot: &ReadSnapshot<'_>, path: &str) -> Result<Option<FileRef>> {
    if path.is_empty() {
        return Ok(None);
    }
    let sql = format!("SELECT {FILE_COLUMNS} FROM files f WHERE f.path=?1");
    Ok(snapshot
        .connection()
        .prepare_cached(&sql)?
        .query_row([path], |row| file_row(row, 0))
        .optional()?)
}

/// `s.*` then the file columns, joined with the symbol's vocab name.
const SYMBOL_SELECT: &str = "SELECT s.id, s.key, v.tok, s.sig, s.kind, s.line, s.end_line,
    f.id, f.path, f.key, f.lang, f.flags
    FROM sym s JOIN vocab v ON v.id = s.name JOIN files f ON f.id = s.file";

fn symbol_row(row: &Row<'_>) -> rusqlite::Result<SymbolRef> {
    let lower: String = row.get(2)?;
    let sig: Option<String> = row.get(3)?;
    Ok(SymbolRef {
        id: row.get(0)?,
        key: row.get(1)?,
        name: display_name(sig.as_deref(), &lower),
        kind: row
            .get::<_, Option<i64>>(4)?
            .and_then(SymbolKind::from_code),
        line: row.get::<_, Option<u32>>(5)?.unwrap_or(0),
        end_line: row.get::<_, Option<u32>>(6)?.unwrap_or(0),
        file: file_row(row, 7)?,
    })
}

/// The innermost symbol spanning `line` in `file`: the shortest span, and
/// of equal spans the one with no child spanning the line.
fn enclosing(snapshot: &ReadSnapshot<'_>, file: &FileRef, line: u32) -> Result<Option<SymbolRef>> {
    let sql = format!(
        "{SYMBOL_SELECT} WHERE s.file=?1 AND s.line<=?2 AND s.end_line>=?2
         ORDER BY (s.end_line - s.line),
           EXISTS(SELECT 1 FROM sym c WHERE c.file=?1 AND c.line<=?2 AND c.end_line>=?2
             AND c.parent=s.id),
           s.id DESC LIMIT 1"
    );
    Ok(snapshot
        .connection()
        .prepare_cached(&sql)?
        .query_row(params![file.id, line], symbol_row)
        .optional()?)
}

/// Every definition of a name, by path then line, up to [`MAX_DEFINITIONS`];
/// the flag says more exist. A qualified name keeps only definitions whose
/// parent has the qualifier's last segment. When some definitions are
/// declared with the spelling given, only those are kept, and the flag
/// speaks for the set returned. At most [`MAX_SCANNED_DEFINITIONS`] rows are
/// judged; past that the flag is set.
pub(crate) fn symbols_named(
    snapshot: &ReadSnapshot<'_>,
    text: &str,
) -> Result<(Vec<SymbolRef>, bool)> {
    let (qualifier, name) = split_qualified(text);
    let none = Ok((Vec::new(), false));
    if name.is_empty() {
        return none;
    }
    let Some(token) = snapshot.token_id(&name.to_lowercase())? else {
        return none;
    };
    let parent = match qualifier {
        None => None,
        Some(qualifier) => match snapshot.token_id(&qualifier.to_lowercase())? {
            Some(parent) => Some(parent),
            None => return none,
        },
    };
    let sql = format!(
        "{SYMBOL_SELECT} WHERE s.name=?1
           AND (?2 IS NULL OR s.parent IN (SELECT id FROM sym WHERE name=?2))
         ORDER BY f.path, s.line, s.id LIMIT ?3"
    );
    let mut select = snapshot.connection().prepare_cached(&sql)?;
    let scan = MAX_SCANNED_DEFINITIONS as i64 + 1;
    let (mut exact, mut any, mut scanned) = (Vec::new(), Vec::new(), 0usize);
    for row in select.query_map(params![token, parent, scan], symbol_row)? {
        let symbol = row?;
        scanned += 1;
        if scanned > MAX_SCANNED_DEFINITIONS || exact.len() > MAX_DEFINITIONS {
            break;
        }
        if symbol.name == name {
            exact.push(symbol);
        } else if any.len() <= MAX_DEFINITIONS {
            any.push(symbol);
        }
    }
    let unjudged = scanned > MAX_SCANNED_DEFINITIONS;
    let mut found = if exact.is_empty() { any } else { exact };
    let capped = found.len() > MAX_DEFINITIONS || unjudged;
    found.truncate(MAX_DEFINITIONS);
    Ok((found, capped))
}

/// `A::b`, `A.b` and `A#b` split at the last separator; a path never is.
fn split_qualified(text: &str) -> (Option<&str>, &str) {
    if text.contains('/') {
        return (None, text);
    }
    let split = text
        .rfind("::")
        .map(|at| (at, 2))
        .or_else(|| text.rfind(['.', '#']).map(|at| (at, 1)));
    match split {
        Some((at, width)) if at > 0 && at + width < text.len() => {
            let qualifier = &text[..at];
            let qualifier = qualifier
                .rsplit([':', '.', '#'])
                .next()
                .unwrap_or(qualifier);
            (Some(qualifier), &text[at + width..])
        }
        _ => (None, text),
    }
}

/// Names of indexed symbols close to `text`, best first.
fn symbol_suggestions(snapshot: &ReadSnapshot<'_>, text: &str) -> Result<Vec<String>> {
    let (_, name) = split_qualified(text);
    let lower = name.to_lowercase();
    if lower.is_empty() {
        return Ok(Vec::new());
    }
    let conn = snapshot.connection();
    let mut sig = conn.prepare_cached("SELECT sig FROM sym WHERE name=?1 ORDER BY id LIMIT 1")?;
    let mut out: Vec<String> = Vec::new();
    for (id, text) in se_atlas_search::spellings(snapshot, &lower)? {
        if out.len() >= MAX_SUGGESTIONS {
            break;
        }
        let Some(signature) = sig
            .query_row([id], |row| row.get::<_, Option<String>>(0))
            .optional()?
        else {
            continue;
        };
        let shown = display_name(signature.as_deref(), &text);
        if !out.contains(&shown) {
            out.push(shown);
        }
    }
    Ok(out)
}

/// Indexed paths with the same file name, or in the same directory.
fn path_suggestions(snapshot: &ReadSnapshot<'_>, path: &str) -> Result<Vec<String>> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.is_empty() {
        return Ok(Vec::new());
    }
    let conn = snapshot.connection();
    let mut out = Vec::new();
    let mut by_name = conn.prepare_cached(
        "SELECT path FROM files WHERE path=?1 OR path LIKE '%/' || ?2 ESCAPE '\\'
         ORDER BY length(path), path LIMIT ?3",
    )?;
    let escaped = escape_like(name);
    let rows = by_name.query_map(params![name, escaped, MAX_SUGGESTIONS as i64], |row| {
        row.get(0)
    })?;
    for row in rows {
        out.push(row?);
    }
    let dir = dir_of(path);
    if out.is_empty() && !dir.is_empty() {
        let mut in_dir = conn.prepare_cached(
            "SELECT path FROM files WHERE path > ?1 AND path < ?2 ORDER BY path LIMIT ?3",
        )?;
        let (low, high) = (format!("{dir}/"), format!("{dir}0"));
        for row in in_dir.query_map(params![low, high, MAX_SUGGESTIONS as i64], |row| row.get(0))? {
            out.push(row?);
        }
    }
    Ok(out)
}

fn escape_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
