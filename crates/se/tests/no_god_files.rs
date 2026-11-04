//! Protects: Jimmy rulings 2026-11-04 — no god files. No non-test .rs source file under
//! `crates/*/src` may exceed 800 lines (a split is planned once a file reaches 600), and no test
//! .rs file under `crates/*/tests` may exceed 1000 lines. Each check walks its tree and fails
//! naming every over-limit file and its line count.

use std::fs;
use std::path::{Path, PathBuf};

const SOURCE_LIMIT: usize = 800;
const TEST_LIMIT: usize = 1000;

fn count_lines(path: &Path) -> usize {
    let bytes = fs::read(path)
        .unwrap_or_else(|error| panic!("no-god-files: cannot read {}: {}", path.display(), error));
    String::from_utf8_lossy(&bytes).lines().count()
}

fn collect_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!(
            "no-god-files: cannot read directory {}: {}",
            dir.display(),
            error
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "no-god-files: cannot read entry in {}: {}",
                dir.display(),
                error
            )
        });
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Every `crates/*/<tree>/**/*.rs` file over `limit` lines, sorted, with its line count.
fn offenders(tree: &str, limit: usize) -> Vec<(PathBuf, usize)> {
    let workspace = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .unwrap_or_else(|error| panic!("no-god-files: cannot resolve workspace root: {error}"));
    let crates_dir = workspace.join("crates");
    let mut offenders = Vec::new();
    let crate_entries = fs::read_dir(&crates_dir).unwrap_or_else(|error| {
        panic!(
            "no-god-files: cannot read {}: {}",
            crates_dir.display(),
            error
        )
    });
    for crate_entry in crate_entries {
        let crate_entry = crate_entry.unwrap_or_else(|error| {
            panic!(
                "no-god-files: cannot read entry in {}: {}",
                crates_dir.display(),
                error
            )
        });
        let root = crate_entry.path().join(tree);
        if !root.is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        collect_sources(&root, &mut sources);
        for source in sources {
            let lines = count_lines(&source);
            if lines > limit {
                offenders.push((source, lines));
            }
        }
    }
    offenders.sort();
    offenders
}

fn assert_within(tree: &str, limit: usize, what: &str) {
    let offenders = offenders(tree, limit);
    if !offenders.is_empty() {
        let named = offenders
            .iter()
            .map(|(path, lines)| format!("{}: {} lines", path.display(), lines))
            .collect::<Vec<_>>()
            .join("; ");
        panic!("god-file limit of {limit} {what} lines exceeded: {named}");
    }
}

#[test]
fn no_source_file_exceeds_the_god_file_limit() {
    assert_within("src", SOURCE_LIMIT, "non-test source");
}

#[test]
fn no_test_file_exceeds_the_god_file_limit() {
    assert_within("tests", TEST_LIMIT, "test");
}
