//! Protects: 2026-11-18 ruling — two mechanical test rules. Fixed sleeps in test code may only
//! go down: the number of thread::sleep and time::sleep call sites under `crates/*/tests` may
//! not grow past the checked-in ceiling, and a new wait must use a real signal instead of a
//! fixed delay. Every `#[ignore]` in the workspace must carry its reason using Rust's built-in
//! `#[ignore = "why"]` form; a bare `#[ignore]` refuses.

use std::fs;
use std::path::{Path, PathBuf};

/// Checked-in ceiling for fixed-sleep call sites under `crates/*/tests` (counted 2026-11-18 on
/// main 5431ba92b). It may only go down: when you remove fixed sleeps, lower it to the new total.
const MAX_FIXED_TEST_SLEEPS: usize = 110;

fn workspace_root() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap_or_else(|error| {
        panic!("test-hygiene-rules: cannot resolve workspace root: {error}")
    })
}

fn collect_rs(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!(
            "test-hygiene-rules: cannot read directory {}: {}",
            dir.display(),
            error
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "test-hygiene-rules: cannot read entry in {}: {}",
                dir.display(),
                error
            )
        });
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

fn crate_trees(crates_dir: &Path, trees: &[&str]) -> Vec<PathBuf> {
    let crate_entries = fs::read_dir(crates_dir).unwrap_or_else(|error| {
        panic!(
            "test-hygiene-rules: cannot read {}: {}",
            crates_dir.display(),
            error
        )
    });
    let mut files = Vec::new();
    for crate_entry in crate_entries {
        let crate_entry = crate_entry.unwrap_or_else(|error| {
            panic!(
                "test-hygiene-rules: cannot read entry in {}: {}",
                crates_dir.display(),
                error
            )
        });
        for tree in trees {
            let root = crate_entry.path().join(tree);
            if root.is_dir() {
                collect_rs(&root, &mut files);
            }
        }
    }
    files.sort();
    files
}

/// Fixed-sleep call sites per file, skipping this guard, which names the calls in its own text.
fn fixed_sleep_sites() -> Vec<(PathBuf, usize)> {
    let crates_dir = workspace_root().join("crates");
    let files = crate_trees(&crates_dir, &["tests"]);
    let mut sites = Vec::new();
    for path in files {
        if path
            .file_name()
            .is_some_and(|name| name == "test_hygiene_rules.rs")
        {
            continue;
        }
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "test-hygiene-rules: cannot read {}: {}",
                path.display(),
                error
            )
        });
        let text = String::from_utf8_lossy(&bytes);
        let count = text.matches("thread::sleep").count() + text.matches("time::sleep").count();
        if count > 0 {
            sites.push((path, count));
        }
    }
    sites
}

/// Bare `#[ignore]` lines (no reason), per file and line, across every Rust file in the workspace.
fn bare_ignores() -> Vec<(PathBuf, usize)> {
    let crates_dir = workspace_root().join("crates");
    let files = crate_trees(&crates_dir, &["src", "tests"]);
    let mut bare = Vec::new();
    for path in files {
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "test-hygiene-rules: cannot read {}: {}",
                path.display(),
                error
            )
        });
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("#[ignore]") {
                bare.push((path.clone(), index + 1));
            }
        }
    }
    bare
}

#[test]
fn fixed_test_sleeps_may_only_go_down() {
    let sites = fixed_sleep_sites();
    let total: usize = sites.iter().map(|(_, count)| count).sum();
    if total > MAX_FIXED_TEST_SLEEPS {
        let named = sites
            .iter()
            .map(|(path, count)| format!("{}: {count}", path.display()))
            .collect::<Vec<_>>()
            .join("; ");
        panic!(
            "fixed test sleeps at {total}, above the checked-in ceiling of {MAX_FIXED_TEST_SLEEPS} \
             ({named}). Wait on a real signal instead of a fixed delay: a channel, an event, or a \
             polled condition that the test is actually waiting for. If you removed fixed sleeps \
             and the total dropped, lower MAX_FIXED_TEST_SLEEPS to the new total."
        );
    }
}

#[test]
fn every_ignored_test_carries_a_reason() {
    let bare = bare_ignores();
    if !bare.is_empty() {
        let named = bare
            .iter()
            .map(|(path, line)| format!("{}:{}: #[ignore]", path.display(), line))
            .collect::<Vec<_>>()
            .join("; ");
        panic!(
            "bare #[ignore] attributes found ({named}). Every ignored test must carry its reason: \
             use Rust's built-in #[ignore = \"why\"] form, naming the condition that makes the \
             test unrunnable on ordinary CI."
        );
    }
}
