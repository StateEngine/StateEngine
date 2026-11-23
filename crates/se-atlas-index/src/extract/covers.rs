//! Test detection and bounded covering-test edges: direct imports, inline
//! Rust test modules, filename conventions, and imports made through a small
//! shared test helper.
use super::flags;
use std::collections::HashSet;

/// A helper module is expanded only when it imports at most this many files.
pub const MAX_HELPER_OUT_DEGREE: usize = 16;
/// At most this many helper-derived edges per test file.
pub const MAX_VIA_HELPER: usize = 32;

/// How a test covers a file; stored as `covers.how`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverHow {
    Import = 1,
    Inline = 2,
    Name = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cover {
    pub test_file: i64,
    pub target_file: i64,
    pub how: CoverHow,
    pub via_helper: bool,
}

/// What edge computation needs to know about one indexed file.
#[derive(Clone, Debug)]
pub struct CoverFile {
    pub id: i64,
    pub path: String,
    pub flags: u32,
    /// Resolved import targets.
    pub targets: Vec<i64>,
}

/// Lookup over the indexed file graph.
pub trait CoverGraph {
    fn file(&self, id: i64) -> crate::Result<Option<CoverFile>>;
    fn id_of(&self, path: &str) -> crate::Result<Option<i64>>;
}

const TEST_DIRS: &[&str] = &["tests", "test", "__tests__", "spec", "specs"];

/// Whether the path alone marks a test or test-support file.
pub fn is_test_path(path: &str) -> bool {
    let mut parts = path.rsplit('/');
    let name = parts.next().unwrap_or(path);
    if parts.any(|dir| TEST_DIRS.contains(&dir)) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    ["_test.go", "_tests.rs", "_spec.rb"]
        .iter()
        .any(|s| lower.ends_with(s))
        || ["Test.java", "Tests.java", "Test.kt", "Tests.cs"]
            .iter()
            .any(|s| name.ends_with(s))
        || (lower.ends_with(".py") && (lower.starts_with("test_") || lower.ends_with("_test.py")))
        || lower == "conftest.py"
        || lower.contains(".test.")
        || lower.contains(".spec.")
}

/// `TEST` and `INLINE_TESTS` flags from the path and test markers. A Rust
/// file with a test-gated item, such as `#[cfg(all(test, feature = ".."))]`,
/// holds inline tests and is not itself a test file.
pub fn test_flags(path: &str, text: &str) -> u32 {
    let inline = path.ends_with(".rs") && text.split("#[cfg(").skip(1).any(enables_test);
    let markers = ["#[test]", "describe(", "def test_", "func Test", "@Test"]
        .iter()
        .any(|marker| text.contains(marker));
    let mut out = if inline { flags::INLINE_TESTS } else { 0 };
    if is_test_path(path) || (markers && !inline) {
        out |= flags::TEST;
    }
    out
}

/// Whether the predicate after `#[cfg(` requires `test` (top level or under
/// `all(..)`, never inside `not(..)` or `any(..)`).
fn enables_test(mut rest: &str) -> bool {
    let (mut depth, mut blocked) = (1usize, None);
    while depth > 0 {
        let Some(ch) = rest.chars().next() else {
            break;
        };
        match ch {
            '"' => {
                let mut chars = rest[1..].chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        chars.next();
                    } else if c == '"' {
                        break;
                    }
                }
                rest = chars.as_str();
            }
            '(' | ')' => {
                depth = if ch == '(' { depth + 1 } else { depth - 1 };
                if blocked.is_some_and(|at| depth <= at) {
                    blocked = None;
                }
                rest = &rest[1..];
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let end = rest
                    .find(|x: char| !x.is_ascii_alphanumeric() && x != '_')
                    .unwrap_or(rest.len());
                let (word, tail) = rest.split_at(end);
                let next = tail.trim_start().as_bytes().first().copied();
                if matches!(word, "not" | "any") && next == Some(b'(') {
                    blocked.get_or_insert(depth);
                } else if word == "test" && blocked.is_none() && !matches!(next, Some(b'(' | b'='))
                {
                    return true;
                }
                rest = tail;
            }
            _ => rest = &rest[ch.len_utf8()..],
        }
    }
    false
}

/// Every edge from one file acting as a test.
pub fn covers_for(test: &CoverFile, graph: &dyn CoverGraph) -> crate::Result<Vec<Cover>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |out: &mut Vec<Cover>, target: i64, how: CoverHow, via_helper: bool| {
        seen.insert(target)
            .then(|| {
                out.push(Cover {
                    test_file: test.id,
                    target_file: target,
                    how,
                    via_helper,
                });
            })
            .is_some()
    };
    if test.flags & flags::INLINE_TESTS != 0 {
        add(&mut out, test.id, CoverHow::Inline, false);
    }
    if test.flags & flags::TEST == 0 {
        return Ok(out);
    }
    for target in &test.targets {
        add(&mut out, *target, CoverHow::Import, false);
    }
    let mut via = 0;
    for target in &test.targets {
        let Some(helper) = graph.file(*target)? else {
            continue;
        };
        let shared = helper.flags & flags::TEST != 0 || is_test_path(&helper.path);
        if !shared || helper.targets.len() > MAX_HELPER_OUT_DEGREE {
            continue;
        }
        for indirect in helper.targets.iter().filter(|id| **id != test.id) {
            if via >= MAX_VIA_HELPER {
                break;
            }
            if add(&mut out, *indirect, CoverHow::Import, true) {
                via += 1;
            }
        }
    }
    for candidate in name_candidates(&test.path) {
        if let Some(id) = graph.id_of(&candidate)?.filter(|id| *id != test.id) {
            add(&mut out, id, CoverHow::Name, false);
        }
    }
    Ok(out)
}

fn parent(dir: &str) -> &str {
    let trimmed = dir.trim_end_matches('/');
    trimmed.rfind('/').map_or("", |at| &trimmed[..=at])
}

/// Source files a test's name says it covers.
fn name_candidates(path: &str) -> Vec<String> {
    let (dir, name) = path
        .rfind('/')
        .map_or(("", path), |at| path.split_at(at + 1));
    let mut out = Vec::new();
    if let Some(stem) = name.strip_suffix("_test.go") {
        out.push(format!("{dir}{stem}.go"));
    }
    if let Some(stem) = name
        .strip_suffix(".py")
        .and_then(|r| r.strip_prefix("test_").or_else(|| r.strip_suffix("_test")))
    {
        let up = parent(dir);
        out.extend([
            format!("{dir}{stem}.py"),
            format!("{up}{stem}.py"),
            format!("{up}src/{stem}.py"),
        ]);
    }
    for marker in [".test.", ".spec."] {
        if let Some((stem, ext)) = name.split_once(marker) {
            let up = dir.ends_with("__tests__/").then(|| parent(dir));
            for base in std::iter::once(dir).chain(up) {
                for ext in [ext, "ts", "tsx", "js", "jsx"] {
                    out.push(format!("{base}{stem}.{ext}"));
                }
            }
        }
    }
    for (suffix, ext) in [
        ("Test.java", "java"),
        ("Tests.java", "java"),
        ("Test.kt", "kt"),
    ] {
        if let Some(stem) = name.strip_suffix(suffix) {
            out.push(format!("{dir}{stem}.{ext}"));
            out.push(format!("{}{stem}.{ext}", dir.replace("/test/", "/main/")));
        }
    }
    if let (Some(stem), Some(krate)) = (name.strip_suffix(".rs"), dir.strip_suffix("tests/")) {
        out.extend([
            format!("{krate}src/{stem}.rs"),
            format!("{krate}src/{stem}/mod.rs"),
        ]);
    }
    out
}
