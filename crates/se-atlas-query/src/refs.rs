//! References to a symbol (or a file), grouped by file with the matching
//! line as context.
//!
//! Candidate files come from the index in two phases, and phase 1 is always
//! ordered first so a common name (`new`, `read`, `run`) never loses a real
//! importer to the per-page scan cap:
//!
//! 1. [`RefAccuracy::ImportedFile`]: the defining files, files whose
//!    resolved imports name a defining file (`imp_target`) and that hold the
//!    name token, and files in a defining file's directory that hold it.
//! 2. [`RefAccuracy::NameOnly`]: every other file holding the name token.
//!
//! Each page reads at most [`MAX_SCAN_FILES`] files or [`MAX_SCAN_BYTES`]
//! through [`IndexSourceRoot`] custody and keeps only lines where the name
//! stands as a whole identifier. Declaration lines are not references.
use super::{
    Answer, SymbolRef, Target, TargetOf, dir_of, importers, name_postings, page_limit,
    target::resolve_in,
};
use se_atlas_index::{
    Result,
    custody::IndexSourceRoot,
    extract::find_word,
    store::{ReadSnapshot, Reader},
};
use se_atlas_search::{Budget, DEFAULT_DEADLINE, FileRead, LiteralLines, hit_text};
use std::{collections::HashSet, time::Duration};

pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;
/// Files read per page.
pub const MAX_SCAN_FILES: usize = 25;
/// Bytes read per page.
pub const MAX_SCAN_BYTES: u64 = 4 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefAccuracy {
    /// The file defines the target, imports a defining file, or shares a
    /// defining file's directory; it holds the name.
    ImportedFile,
    /// The file only holds the name.
    NameOnly,
}

#[derive(Clone, Debug)]
pub struct RefsRequest {
    pub target: Target,
    /// Reference lines per page, at most [`MAX_LIMIT`]; zero means the default.
    pub limit: usize,
    /// `next_cursor` of the previous page.
    pub cursor: Option<usize>,
    pub deadline: Duration,
}

impl RefsRequest {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            limit: DEFAULT_LIMIT,
            cursor: None,
            deadline: DEFAULT_DEADLINE,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefLine {
    pub line: u32,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefGroup {
    pub path: String,
    pub accuracy: RefAccuracy,
    pub lines: Vec<RefLine>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Refs {
    /// The name matched in text.
    pub name: String,
    pub definitions: Vec<SymbolRef>,
    /// The name has more definitions than `definitions` lists; see
    /// [`super::target::MAX_DEFINITIONS`].
    pub definitions_capped: bool,
    pub groups: Vec<RefGroup>,
    /// Confirmed lines left off this page inside files it read.
    pub omitted_lines: usize,
    /// Candidate files across both phases.
    pub candidates: usize,
    /// Phase 1 candidates; they come first.
    pub imported_candidates: usize,
    pub files_read: usize,
    pub files_absent: usize,
    pub files_refused: usize,
    pub files_read_failed: usize,
    /// Files past the full-read limit or a line cap.
    pub files_partly_read: usize,
    /// Where the next page starts; `None` when every candidate was read.
    pub next_cursor: Option<usize>,
    pub deadline_reached: bool,
}

struct Candidate {
    file: i64,
    path: String,
    accuracy: RefAccuracy,
}

impl Candidate {
    fn new(file: i64, path: String, accuracy: RefAccuracy) -> Self {
        Self {
            file,
            path,
            accuracy,
        }
    }
}

/// Find references to the target, one page at a time.
pub fn refs(
    reader: &Reader,
    root: &IndexSourceRoot,
    request: &RefsRequest,
) -> Result<Answer<Refs>> {
    let budget = Budget::start(request.deadline);
    let snapshot = reader.snapshot()?;
    let target = match Answer::unresolved(resolve_in(&snapshot, &request.target)?) {
        Ok(target) => target,
        Err(answer) => return Ok(answer),
    };
    let (name, candidates) = candidates(&snapshot, &target)?;
    drop(snapshot);
    let mut out = Refs {
        imported_candidates: candidates
            .iter()
            .filter(|c| c.accuracy == RefAccuracy::ImportedFile)
            .count(),
        candidates: candidates.len(),
        definitions: target.symbols().to_vec(),
        definitions_capped: target.capped(),
        ..Refs::default()
    };
    let declarations: HashSet<(i64, u32)> = out
        .definitions
        .iter()
        .map(|symbol| (symbol.file.id, symbol.line))
        .collect();
    let case_exact = name.bytes().any(|b| b.is_ascii_uppercase());
    let mut lines_of = LiteralLines::new(&name, case_exact)?;
    let limit = page_limit(request.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let (mut kept, mut files, mut bytes) = (0usize, 0usize, 0u64);
    let start = request.cursor.unwrap_or(0).min(candidates.len());
    for (at, candidate) in candidates.iter().enumerate().skip(start) {
        if kept >= limit || files >= MAX_SCAN_FILES || bytes >= MAX_SCAN_BYTES {
            out.next_cursor = Some(at);
            break;
        }
        if budget.expired() {
            out.deadline_reached = true;
            out.next_cursor = Some(at);
            break;
        }
        let mut lines = Vec::new();
        let read = lines_of.read(root, &candidate.path, |line, text| {
            let whole = if case_exact {
                find_word(text, &name).is_some()
            } else {
                find_word(&text.to_ascii_lowercase(), &name).is_some()
            };
            let declared = declarations.contains(&(candidate.file, line));
            if whole && !declared {
                lines.push(RefLine {
                    line,
                    text: hit_text(text),
                });
            }
            whole && !declared
        });
        files += 1;
        tally(&read, &mut out, &mut bytes);
        if lines.is_empty() {
            continue;
        }
        let room = limit - kept;
        out.omitted_lines += lines.len().saturating_sub(room);
        lines.truncate(room);
        kept += lines.len();
        out.groups.push(RefGroup {
            path: candidate.path.clone(),
            accuracy: candidate.accuracy,
            lines,
        });
    }
    out.name = name;
    Ok(Answer::Found(out))
}

fn tally(read: &FileRead, out: &mut Refs, bytes: &mut u64) {
    match read {
        FileRead::Done {
            bytes: read,
            partial,
        } => {
            out.files_read += 1;
            out.files_partly_read += usize::from(*partial);
            *bytes += read;
        }
        FileRead::Absent => out.files_absent += 1,
        FileRead::Refused => out.files_refused += 1,
        FileRead::Failed => out.files_read_failed += 1,
    }
}

/// The name to match and every candidate file, phase 1 first.
fn candidates(snapshot: &ReadSnapshot<'_>, target: &TargetOf) -> Result<(String, Vec<Candidate>)> {
    let defining = target.files();
    let mut imported: Vec<i64> = Vec::new();
    let name = match target.symbols().first() {
        // A file target: its importers, matched on the name they import it by.
        None => {
            imported.extend(importers(snapshot, defining[0].id)?);
            import_name(&defining[0].path)
        }
        Some(symbol) => {
            let postings = name_postings(snapshot, target)?;
            imported.extend(defining.iter().map(|file| file.id));
            for file in &defining {
                imported.extend(
                    importers(snapshot, file.id)?
                        .into_iter()
                        .filter(|importer| postings.contains(importer)),
                );
            }
            let mut seen = HashSet::new();
            imported.retain(|file| seen.insert(*file));
            let mut rest = paths(snapshot, postings.into_iter().filter(|f| !seen.contains(f)))?;
            rest.sort_unstable();
            let dirs: HashSet<&str> = defining.iter().map(|file| dir_of(&file.path)).collect();
            let mut out = paths(snapshot, imported)?
                .into_iter()
                .map(|(path, file)| Candidate::new(file, path, RefAccuracy::ImportedFile))
                .collect::<Vec<_>>();
            let (siblings, others): (Vec<_>, Vec<_>) = rest
                .into_iter()
                .partition(|(path, _)| dirs.contains(dir_of(path)));
            out.extend(
                siblings
                    .into_iter()
                    .map(|(path, file)| Candidate::new(file, path, RefAccuracy::ImportedFile)),
            );
            out.extend(
                others
                    .into_iter()
                    .map(|(path, file)| Candidate::new(file, path, RefAccuracy::NameOnly)),
            );
            return Ok((symbol.name.clone(), out));
        }
    };
    let out = paths(snapshot, imported)?
        .into_iter()
        .map(|(path, file)| Candidate::new(file, path, RefAccuracy::ImportedFile))
        .collect();
    Ok((name, out))
}

/// `(path, id)` of each file, in the order given.
fn paths(
    snapshot: &ReadSnapshot<'_>,
    files: impl IntoIterator<Item = i64>,
) -> Result<Vec<(String, i64)>> {
    let mut path_of = snapshot
        .connection()
        .prepare_cached("SELECT path FROM files WHERE id=?1")?;
    files
        .into_iter()
        .map(|file| Ok((path_of.query_row([file], |row| row.get(0))?, file)))
        .collect()
}

/// The name a file is imported by: its stem, or its directory's name for a
/// module index file. A Rust crate root (`<crate>/src/lib.rs`) is named by
/// its crate, written with `_` for `-`.
fn import_name(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.split('.').next().unwrap_or(name);
    if matches!(stem, "mod" | "lib" | "index" | "__init__" | "main") {
        let mut dir = dir_of(path);
        let rust = name.ends_with(".rs");
        if rust && dir.rsplit('/').next() == Some("src") {
            dir = dir_of(dir);
        }
        let parent = dir.rsplit('/').next().unwrap_or(dir);
        if !parent.is_empty() && parent != "src" {
            return if rust {
                parent.replace('-', "_")
            } else {
                parent.to_owned()
            };
        }
    }
    stem.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Repo, TestResult};

    #[test]
    fn importers_are_read_before_name_only_files_under_the_scan_cap() -> TestResult {
        let noise: Vec<(String, String)> = (0..MAX_SCAN_FILES + 5)
            .map(|n| {
                let text = format!("run();\nexport const n{n} = 1;\n");
                (format!("a/noise{n:02}.js"), text)
            })
            .collect();
        let mut files: Vec<(&str, &str)> = noise
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        files.push(("lib/def.js", "export function run() {}\n"));
        files.push((
            "z/user.js",
            "import { run } from '../lib/def.js';\nrun();\n",
        ));
        let repo = Repo::build(&files)?;
        let request = RefsRequest::new(Target::Symbol("run".into()));
        let Answer::Found(found) = refs(&repo.reader()?, &repo.root, &request)? else {
            return Err("run must resolve".into());
        };
        assert_eq!(found.candidates, MAX_SCAN_FILES + 7);
        assert_eq!(
            found.imported_candidates, 2,
            "the defining file and its importer"
        );
        let user = found.groups.iter().find(|group| group.path == "z/user.js");
        let user = user.ok_or("the importer must be read on the first page")?;
        assert_eq!(user.accuracy, RefAccuracy::ImportedFile);
        let lines: Vec<u32> = user.lines.iter().map(|line| line.line).collect();
        assert_eq!(lines, [1, 2]);
        assert_eq!(
            found.groups[0].path, "z/user.js",
            "the declaration is not a reference"
        );
        assert!(
            found.groups[1..]
                .iter()
                .all(|group| group.accuracy == RefAccuracy::NameOnly)
        );
        assert_eq!(found.files_read, MAX_SCAN_FILES);
        assert_eq!(found.next_cursor, Some(MAX_SCAN_FILES));
        Ok(())
    }
}
