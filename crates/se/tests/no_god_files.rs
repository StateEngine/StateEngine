//! Protects: Jimmy ruling 2026-11-04 — no god files: no non-test .rs source file over 800
//! lines (a split is planned once a file reaches 600). This check walks every
//! `crates/*/src/**/*.rs` file in the workspace and fails naming each over-limit file and its
//! line count. It starts red on `crates/se-store/src/read.rs` until its split lands.

use std::fs;
use std::path::{Path, PathBuf};

const LIMIT: usize = 800;

fn count_lines(path: &Path) -> usize {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        panic!("no-god-files: cannot read {}: {}", path.display(), error)
    });
    String::from_utf8_lossy(&bytes).lines().count()
}

fn collect_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!("no-god-files: cannot read directory {}: {}", dir.display(), error)
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("no-god-files: cannot read entry in {}: {}", dir.display(), error)
        });
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn no_source_file_exceeds_the_god_file_limit() {
    let workspace = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .expect("no-god-files: cannot resolve workspace root");
    let crates_dir = workspace.join("crates");
    let mut offenders = Vec::new();
    for crate_entry in fs::read_dir(&crates_dir).expect("no-god-files: workspace crates directory") {
        let crate_entry = crate_entry.unwrap_or_else(|error| {
            panic!("no-god-files: cannot read entry in {}: {}", crates_dir.display(), error)
        });
        let src = crate_entry.path().join("src");
        if !src.is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        collect_sources(&src, &mut sources);
        for source in sources {
            let lines = count_lines(&source);
            if lines > LIMIT {
                offenders.push((source, lines));
            }
        }
    }
    if !offenders.is_empty() {
        offenders.sort();
        let named = offenders
            .iter()
            .map(|(path, lines)| format!("{}: {} lines", path.display(), lines))
            .collect::<Vec<_>>()
            .join("; ");
        panic!("god-file limit of {LIMIT} non-test source lines exceeded: {named}");
    }
}
