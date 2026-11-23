//! The edit-time summary an agent hook shows before a file or symbol is
//! changed. It reads SQLite only, inside one snapshot, and never opens a
//! source file: importers that hold the name (`imp_target` intersected with
//! the name's postings), covering tests (`covers_target`), the latest index
//! changes, and how many project-visible records mention the target.
use super::{
    Answer, Section, Target, TargetOf,
    impact::{CoveringTest, RecentChange, cover_how, keys, recent_changes},
    importers, name_postings,
    target::{FileRef, resolve_in},
};
use rusqlite::params;
use se_atlas_index::{Result, store::Reader};
use std::collections::HashSet;

/// Importers and tests listed; the rest are counted.
pub const MAX_LISTED: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hooks {
    pub files: Vec<FileRef>,
    /// Display names of the symbols the target resolved to.
    pub symbols: Vec<String>,
    /// The name has more definitions than `symbols` lists; see
    /// [`super::target::MAX_DEFINITIONS`].
    pub definitions_capped: bool,
    /// Paths of files importing a defining file (and, for a symbol,
    /// holding its name).
    pub importers: Section<String>,
    pub tests: Section<CoveringTest>,
    pub changes: Section<RecentChange>,
    /// Project-visible records that mention the defining files or symbols,
    /// each counted once, as impact lists them. Restricted records are not
    /// counted, so this never reveals that one exists.
    pub mentions: usize,
}

/// Summarise the target for an edit hook.
pub fn hooks(reader: &Reader, target: &Target) -> Result<Answer<Hooks>> {
    let snapshot = reader.snapshot()?;
    let target = match Answer::unresolved(resolve_in(&snapshot, target)?) {
        Ok(target) => target,
        Err(answer) => return Ok(answer),
    };
    let conn = snapshot.connection();
    let postings = name_postings(&snapshot, &target)?;
    let symbol = !target.symbols().is_empty();
    let mut path_of = conn.prepare_cached("SELECT path FROM files WHERE id=?1")?;
    let mut importer_ids = Vec::new();
    // A defining file is never listed as an importer of another one.
    let mut seen: HashSet<i64> = target.files().iter().map(|file| file.id).collect();
    for file in target.files() {
        for importer in importers(&snapshot, file.id)? {
            if (!symbol || postings.contains(&importer)) && seen.insert(importer) {
                importer_ids.push(importer);
            }
        }
    }
    let more = importer_ids.len().saturating_sub(MAX_LISTED);
    let mut listed = Vec::new();
    for file in importer_ids.into_iter().take(MAX_LISTED) {
        listed.push(path_of.query_row([file], |row| row.get(0))?);
    }
    let mut covers = conn.prepare_cached(
        "SELECT f.path, c.how, c.via_helper FROM covers c JOIN files f ON f.id = c.test_file
         WHERE c.target_file=?1 ORDER BY c.how, c.via_helper, f.path",
    )?;
    let mut tests = Vec::new();
    let mut test_paths = HashSet::new();
    for file in target.files() {
        let rows = covers.query_map([file.id], |row| {
            Ok(CoveringTest {
                path: row.get(0)?,
                how: cover_how(row.get(1)?),
                via_helper: row.get(2)?,
            })
        })?;
        for row in rows {
            let test = row?;
            if test_paths.insert(test.path.clone()) {
                tests.push(test);
            }
        }
    }
    let mentions = mention_count(conn, &target)?;
    Ok(Answer::Found(Hooks {
        files: target.files().into_iter().cloned().collect(),
        symbols: target.symbols().iter().map(|s| s.name.clone()).collect(),
        definitions_capped: target.capped(),
        importers: Section {
            items: listed,
            more,
            more_is_floor: false,
        },
        tests: Section::capped(tests, MAX_LISTED),
        changes: recent_changes(&snapshot, &target)?,
        mentions,
    }))
}

fn mention_count(conn: &rusqlite::Connection, target: &TargetOf) -> Result<usize> {
    let mut select = conn.prepare_cached(
        "SELECT m.source_id FROM mentions m JOIN records r ON r.id = m.source_id
         WHERE m.target_kind=?1 AND m.target_key=?2 AND m.source_kind='record'
           AND r.visibility='project'",
    )?;
    let mut records = HashSet::new();
    for (kind, key) in keys(target) {
        for record in select.query_map(params![kind, key], |row| row.get::<_, i64>(0))? {
            records.insert(record?);
        }
    }
    Ok(records.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Repo, TestResult};

    #[test]
    fn hooks_answer_from_the_index_with_no_source_left() -> TestResult {
        let repo = Repo::build(&[
            ("src/door.js", "export function scan() {}\n"),
            (
                "src/user.js",
                "import { scan } from './door.js';\nscan();\n",
            ),
            ("src/other.js", "import './door.js';\n"),
            (
                "test/door.test.js",
                "import { scan } from '../src/door.js';\nscan();\n",
            ),
        ])?;
        repo.delete_sources()?;
        let reader = repo.reader()?;
        let Answer::Found(file) = hooks(&reader, &Target::Auto("src/door.js".into()))? else {
            return Err("the file must resolve".into());
        };
        let importers = ["src/other.js", "src/user.js", "test/door.test.js"];
        assert_eq!(file.importers.items, importers);
        assert_eq!(file.tests.items.len(), 1);
        assert_eq!(file.tests.items[0].path, "test/door.test.js");
        let Answer::Found(symbol) = hooks(&reader, &Target::Auto("scan".into()))? else {
            return Err("the symbol must resolve".into());
        };
        assert_eq!(symbol.symbols, ["scan"]);
        assert_eq!(symbol.importers.items, ["src/user.js", "test/door.test.js"]);
        Ok(())
    }
}
