//! The query-time freshness overlay for `find`.
//!
//! Dirty paths the writer has not committed are read through custody, at
//! most [`MAX_OVERLAY_BYTES`] per query, and their matching lines replace
//! whatever the index still holds for them, so a new or edited file is
//! visible at once. Dirty files past the byte cap stay unread and are
//! reported, so an empty answer is incomplete rather than absent.
//!
//! The top [`MAX_STAT_FILES`] files of an answer are also checked against
//! the index by size and modification time (and by content hash when the
//! file changed within the last two seconds, inside coarse timestamp
//! granularity), which covers an edit the watcher has not reported yet.
use crate::{dirty::DirtyPath, reconcile};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::custody::{GuardedRead, IndexSourceRoot};
use se_atlas_search::{FileRead, LiteralLines, hit_text};
use std::collections::BTreeSet;

/// Bytes of dirty files one query reads.
pub const MAX_OVERLAY_BYTES: u64 = 4 << 20;
/// Answer files whose stats are checked against the index.
pub const MAX_STAT_FILES: usize = 25;
/// Changes this recent may share a timestamp with the indexed version.
const COARSE_MTIME_NS: i128 = 2_000_000_000;
/// Lines kept from one overlaid file.
const LINES_PER_FILE: usize = 20;

/// One line or path matched in a file read live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FreshHit {
    pub path: String,
    /// 0 for a path hit.
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Default)]
pub(crate) struct Overlay {
    pub hits: Vec<FreshHit>,
    /// Paths whose index rows must not be shown.
    pub stale: BTreeSet<String>,
    /// Dirty files left unread by the byte cap or a failed read.
    pub unread: usize,
    pub bytes: u64,
}

/// What a query looks for in live text: every term, ignoring case.
pub(crate) struct Terms {
    terms: Vec<String>,
    /// `None` when the query cannot be matched line by line (a regex).
    anchor: Option<String>,
    pub lines: bool,
    pub paths: bool,
}

impl Terms {
    pub fn new(query: &str, regex: bool, lines: bool, paths: bool) -> Self {
        let terms: Vec<String> = query
            .split_whitespace()
            .map(|term| term.trim_matches('"').to_lowercase())
            .filter(|term| !term.is_empty())
            .collect();
        let anchor = if regex {
            None
        } else {
            terms.iter().max_by_key(|term| term.len()).cloned()
        };
        Self {
            terms,
            anchor,
            lines,
            paths,
        }
    }

    fn matches(&self, text: &str) -> bool {
        let text = text.to_lowercase();
        !self.terms.is_empty() && self.terms.iter().all(|term| text.contains(term.as_str()))
    }
}

impl Overlay {
    /// Read the dirty paths the scope admits, in order, within the byte cap.
    pub fn read(
        &mut self,
        source: &IndexSourceRoot,
        terms: &Terms,
        paths: &[DirtyPath],
        admits: &dyn Fn(&str) -> bool,
    ) {
        // A removed name is read too: some watchers report a rename onto it as
        // a removal, and a name that is really gone reads as absent.
        for dirty in paths.iter().filter(|dirty| admits(&dirty.path)) {
            self.file(source, terms, &dirty.path);
        }
    }

    /// Read one file live and keep its matching lines.
    pub fn file(&mut self, source: &IndexSourceRoot, terms: &Terms, path: &str) {
        self.stale.insert(path.to_owned());
        if terms.paths
            && terms.matches(path)
            && matches!(reconcile::stat(source, path), Ok(Some(_)))
        {
            self.hits.push(FreshHit {
                path: path.to_owned(),
                line: 0,
                text: path.to_owned(),
            });
        }
        if !terms.lines {
            return;
        }
        let Some(anchor) = &terms.anchor else {
            self.unread += 1;
            return;
        };
        if self.bytes >= MAX_OVERLAY_BYTES {
            self.unread += 1;
            return;
        }
        let Ok(mut lines) = LiteralLines::new(anchor, false) else {
            self.unread += 1;
            return;
        };
        let mut kept = Vec::new();
        let read = lines.read(source, path, |line, text| {
            if kept.len() < LINES_PER_FILE && terms.matches(text) {
                kept.push(FreshHit {
                    path: path.to_owned(),
                    line,
                    text: hit_text(text),
                });
                return true;
            }
            false
        });
        match read {
            FileRead::Done { bytes, .. } => {
                self.bytes += bytes;
                self.hits.extend(kept);
            }
            FileRead::Absent | FileRead::Refused => {}
            FileRead::Failed => self.unread += 1,
        }
    }
}

/// Files among `paths` whose indexed version is no longer what is on disk.
pub(crate) fn stale_files(
    conn: &Connection,
    source: &IndexSourceRoot,
    paths: &[String],
    now_ns: i128,
) -> Vec<String> {
    let mut out = Vec::new();
    for path in paths.iter().take(MAX_STAT_FILES) {
        let indexed: Option<(i64, i64, Vec<u8>)> = conn
            .prepare_cached(
                "SELECT coalesce(size, -1), coalesce(mtime_ns, -1), hash FROM files WHERE path=?1",
            )
            .and_then(|mut select| {
                select
                    .query_row([path], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                    .optional()
            })
            .ok()
            .flatten();
        let Some((size, mtime, hash)) = indexed else {
            continue;
        };
        let stale = match reconcile::stat(source, path) {
            Ok(Some(facts)) if facts != (size, mtime) => true,
            Ok(Some(_)) if now_ns - i128::from(mtime) <= COARSE_MTIME_NS => {
                content_differs(source, path, &hash)
            }
            Ok(Some(_)) => false,
            // Gone, refused or unreadable: the indexed rows cannot be confirmed.
            Ok(None) | Err(_) => true,
        };
        if stale {
            out.push(path.clone());
        }
    }
    out
}

fn content_differs(source: &IndexSourceRoot, path: &str, hash: &[u8]) -> bool {
    match source.read_guarded_file(path) {
        Ok(GuardedRead::Source(file)) => blake3::hash(&file.bytes).as_bytes().as_slice() != hash,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::Terms;

    #[test]
    fn live_lines_need_every_term_and_a_regex_is_never_guessed() {
        let terms = Terms::new("live Added", false, true, true);
        assert!(terms.matches("fn live_added() {}"));
        assert!(!terms.matches("fn live() {}"));
        assert_eq!(terms.anchor.as_deref(), Some("added"));
        assert!(Terms::new("a.*b", true, true, false).anchor.is_none());
    }
}
