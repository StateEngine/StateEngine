//! Protects: 2026-11-18 ruling — two mechanical test rules. Fixed sleeps in test code may only
//! go down: the number of thread::sleep and time::sleep call sites under `crates/*/tests` may
//! not grow past the checked-in ceiling, and a new wait must use a real signal instead of a
//! fixed delay. Every `#[ignore]` in the workspace must carry its reason using Rust's built-in
//! `#[ignore = "why"]` form; a bare `#[ignore]` refuses.
//!
//! Both checks recognize Rust syntax: each file is lexed first, so line and block comments and
//! string, raw string, and char literals are opaque — text inside them can neither hide a bare
//! ignore nor inflate the sleep count. Spaced call forms such as `std :: thread :: sleep(..)`
//! are counted, and a call made through an import (`use std::thread::sleep;` then `sleep(..)`)
//! is counted while the import alone is not. Files are scanned per file; an import in one file
//! never counts calls in another.

use std::fs;
use std::path::{Path, PathBuf};

/// Checked-in ceiling for fixed-sleep call sites under `crates/*/tests`, counted 2026-11-18 on
/// main bbec2cfa5 with the syntax-aware lexer. It may only go down: when you remove fixed
/// sleeps, lower it to the new total.
const MAX_FIXED_TEST_SLEEPS: usize = 109;

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

fn read_source(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        panic!(
            "test-hygiene-rules: cannot read {}: {}",
            path.display(),
            error
        )
    });
    String::from_utf8_lossy(&bytes).into_owned()
}

fn line_of(src: &str, byte_pos: usize) -> usize {
    src[..byte_pos.min(src.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ident,
    Colon,
    ColonColon,
    OpenParen,
    OpenBracket,
    CloseBracket,
    Hash,
    Eq,
    Star,
    Semi,
    Literal,
    Comment,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct Tok {
    kind: Kind,
    start: usize,
    len: usize,
}

impl Tok {
    fn text<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.start + self.len]
    }

    fn is_ident(&self, src: &str, name: &str) -> bool {
        self.kind == Kind::Ident && self.text(src) == name
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_part(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_raw_string_start(bytes: &[u8], i: usize) -> bool {
    if bytes.get(i) != Some(&b'r') {
        return false;
    }
    let mut j = i + 1;
    while bytes.get(j) == Some(&b'#') {
        j += 1;
    }
    bytes.get(j) == Some(&b'"')
}

fn char_literal_end(bytes: &[u8], src: &str, i: usize) -> Option<usize> {
    // i points at the opening quote. Returns the index just past the closing quote.
    let mut j = i + 1;
    if j >= bytes.len() {
        return None;
    }
    if bytes[j] == b'\\' {
        j += 1;
        if j >= bytes.len() {
            return None;
        }
        match bytes[j] {
            b'u' if bytes.get(j + 1) == Some(&b'{') => {
                j += 2;
                while j < bytes.len() && bytes[j] != b'}' {
                    j += 1;
                }
                if j >= bytes.len() {
                    return None;
                }
                j += 1;
            }
            b'x' => {
                j += 3;
                if j + 1 > bytes.len() {
                    return None;
                }
                j -= 1;
            }
            _ => j += 1,
        }
    } else {
        let c = src[j..].chars().next()?;
        if c == '\'' {
            return None; // not a literal: a lifetime
        }
        j += c.len_utf8();
    }
    if bytes.get(j) == Some(&b'\'') {
        Some(j + 1)
    } else {
        None
    }
}

fn line_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut j = start + 2;
    while j < bytes.len() && bytes[j] != b'\n' {
        j += 1;
    }
    j
}

fn block_comment_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start + 2;
    let mut depth = 1usize;
    while depth > 0 {
        if j >= bytes.len() {
            return None;
        }
        if bytes[j] == b'/' && bytes.get(j + 1) == Some(&b'*') {
            depth += 1;
            j += 2;
        } else if bytes[j] == b'*' && bytes.get(j + 1) == Some(&b'/') {
            depth -= 1;
            j += 2;
        } else {
            j += 1;
        }
    }
    Some(j)
}

/// Given the start of a string-literal token (a bare `"` or the `r`, `b`, `br`, or `c`
/// prefix), returns the index just past the literal's end. Returns None when the literal is
/// unterminated.
fn string_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let is_byte_raw = bytes.get(start) == Some(&b'b') && bytes.get(start + 1) == Some(&b'r');
    let raw = is_byte_raw || bytes.get(start) == Some(&b'r');
    let mut q = start + if is_byte_raw { 2 } else { 1 };
    if raw {
        let mut hashes = 0usize;
        while bytes.get(q) == Some(&b'#') {
            hashes += 1;
            q += 1;
        }
        if bytes.get(q) != Some(&b'"') {
            return None;
        }
        let mut k = q + 1;
        while k < bytes.len() {
            if bytes[k] == b'"' {
                let mut h = 0usize;
                let mut n = k + 1;
                while n < bytes.len() && bytes[n] == b'#' && h < hashes {
                    h += 1;
                    n += 1;
                }
                if h == hashes {
                    return Some(n);
                }
            }
            k += 1;
        }
        return None;
    }
    if bytes.get(start) != Some(&b'"') {
        // Called through a `b"..."` or `c"..."` prefix: q is on the opening quote.
        q += 1;
    }
    while q < bytes.len() && bytes[q] != b'"' {
        q += if bytes[q] == b'\\' { 2 } else { 1 };
    }
    (q < bytes.len()).then_some(q + 1)
}

fn ident_end(src: &str, i: usize) -> usize {
    let mut j = i + 1;
    while j < src.len() {
        let Some(next) = src[j..].chars().next() else {
            break;
        };
        if !is_ident_part(next) {
            break;
        }
        j += next.len_utf8();
    }
    j
}

/// Lexes Rust source into tokens. Comments and literals become opaque tokens whose text the
/// checks never inspect. String, byte string, C string, and their raw forms are all consumed
/// as single opaque literals. Panics with the file and line when the source is not even
/// tokenizable (an unterminated string, raw string, char literal, or block comment).
fn tokenize(src: &str, path: &Path) -> Vec<Tok> {
    let bytes = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let Some(c) = src[i..].chars().next() else {
            break;
        };
        // String-literal prefix: r" / r# (and hashes), b" (byte), br# (byte raw), c" (C).
        let prefix = match c {
            'r' if is_raw_string_start(bytes, i) => 1,
            'b' if bytes.get(i + 1) == Some(&b'"') => 1,
            'b' if is_raw_string_start(bytes, i + 1) => 2,
            'c' if bytes.get(i + 1) == Some(&b'"') => 1,
            _ => 0,
        };
        if prefix > 0 {
            let Some(end) = string_literal_end(bytes, i) else {
                panic!(
                    "test-hygiene-rules: unterminated string literal at {}:{}",
                    path.display(),
                    line_of(src, i)
                );
            };
            toks.push(Tok {
                kind: Kind::Literal,
                start: i,
                len: end - i,
            });
            i = end;
            continue;
        }
        let start = i;
        let kind = match c {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
                continue;
            }
            '/' if bytes.get(i + 1) == Some(&b'/') => {
                i = line_comment_end(bytes, i);
                Kind::Comment
            }
            '/' if bytes.get(i + 1) == Some(&b'*') => {
                let Some(end) = block_comment_end(bytes, i) else {
                    panic!(
                        "test-hygiene-rules: unterminated block comment at {}:{}",
                        path.display(),
                        line_of(src, i)
                    );
                };
                i = end;
                Kind::Comment
            }
            '"' => {
                let Some(end) = string_literal_end(bytes, i) else {
                    panic!(
                        "test-hygiene-rules: unterminated string at {}:{}",
                        path.display(),
                        line_of(src, i)
                    );
                };
                i = end;
                Kind::Literal
            }
            '\'' => match char_literal_end(bytes, src, i) {
                Some(end) => {
                    i = end;
                    Kind::Literal
                }
                None => {
                    i += 1;
                    Kind::Other // a lifetime
                }
            },
            _ => {
                let (next_kind, end) = simple_token(c, src, bytes, i);
                i = end;
                next_kind
            }
        };
        toks.push(Tok {
            kind,
            start,
            len: i - start,
        });
    }
    toks
}

/// Kind and end position of a token that neither opens a literal nor a comment: punctuation,
/// a lifetime quote, or an identifier.
fn simple_token(c: char, src: &str, bytes: &[u8], i: usize) -> (Kind, usize) {
    match c {
        ':' if bytes.get(i + 1) == Some(&b':') => (Kind::ColonColon, i + 2),
        ':' => (Kind::Colon, i + 1),
        '(' => (Kind::OpenParen, i + 1),
        '[' => (Kind::OpenBracket, i + 1),
        ']' => (Kind::CloseBracket, i + 1),
        '#' => (Kind::Hash, i + 1),
        '=' => (Kind::Eq, i + 1),
        '*' => (Kind::Star, i + 1),
        ';' => (Kind::Semi, i + 1),
        _ if is_ident_start(c) => (Kind::Ident, ident_end(src, i)),
        _ => (Kind::Other, i + c.len_utf8()),
    }
}

#[derive(Debug)]
struct ImportItem<'a> {
    path: Vec<&'a str>,
    alias: Option<&'a str>,
    glob: bool,
}

fn binding_for<'a>(item: ImportItem<'a>) -> Option<&'a str> {
    if item.glob {
        return item
            .path
            .last()
            .is_some_and(|seg| *seg == "thread" || *seg == "time")
            .then_some("sleep");
    }
    let n = item.path.len();
    let is_sleep =
        n >= 2 && item.path[n - 1] == "sleep" && matches!(item.path[n - 2], "thread" | "time");
    is_sleep.then(|| item.alias.unwrap_or("sleep"))
}

fn parse_brace_items<'a>(
    toks: &'a [Tok],
    src: &'a str,
    start: usize,
    prefix: &[&'a str],
) -> Option<(usize, Vec<ImportItem<'a>>)> {
    // start is just past the '['. Returns the index past ']' (and its ';') with the items.
    let mut items = Vec::new();
    let mut i = start;
    loop {
        if i >= toks.len() {
            return None;
        }
        match toks[i].kind {
            Kind::CloseBracket => {
                i += 1;
                break;
            }
            Kind::Ident => {
                let mut chain = vec![toks[i].text(src)];
                i += 1;
                while i + 1 < toks.len()
                    && toks[i].kind == Kind::ColonColon
                    && toks[i + 1].kind == Kind::Ident
                {
                    chain.push(toks[i + 1].text(src));
                    i += 2;
                }
                let alias = if i + 1 < toks.len()
                    && toks[i].is_ident(src, "as")
                    && toks[i + 1].kind == Kind::Ident
                {
                    let aliased = toks[i + 1].text(src);
                    i += 2;
                    Some(aliased)
                } else {
                    None
                };
                let mut path = prefix.to_vec();
                path.extend(chain);
                items.push(ImportItem {
                    path,
                    alias,
                    glob: false,
                });
            }
            _ => i += 1, // commas and separators
        }
    }
    if i < toks.len() && toks[i].kind == Kind::Semi {
        i += 1;
    }
    Some((i, items))
}

fn parse_use_items<'a>(
    toks: &'a [Tok],
    src: &'a str,
    start: usize,
) -> (usize, Vec<ImportItem<'a>>) {
    let mut i = start;
    let mut prefix: Vec<&'a str> = Vec::new();
    if i >= toks.len() || toks[i].kind != Kind::Ident {
        return (start, Vec::new());
    }
    loop {
        if i >= toks.len() || toks[i].kind != Kind::Ident {
            return (start, Vec::new());
        }
        prefix.push(toks[i].text(src));
        i += 1;
        if i < toks.len() && toks[i].kind == Kind::ColonColon {
            i += 1;
            match toks.get(i).map(|t| t.kind) {
                Some(Kind::Ident) => {
                    if i + 1 < toks.len() && toks[i + 1].kind == Kind::ColonColon {
                        continue; // a mid-path segment, pushed at the top of the loop
                    }
                    let name = toks[i].text(src);
                    i += 1;
                    let alias = if i + 1 < toks.len()
                        && toks[i].is_ident(src, "as")
                        && toks[i + 1].kind == Kind::Ident
                    {
                        let aliased = toks[i + 1].text(src);
                        i += 2;
                        Some(aliased)
                    } else {
                        None
                    };
                    let mut path = prefix;
                    path.push(name);
                    if i < toks.len() && toks[i].kind == Kind::Semi {
                        i += 1;
                    }
                    return (
                        i,
                        vec![ImportItem {
                            path,
                            alias,
                            glob: false,
                        }],
                    );
                }
                Some(Kind::Star) => {
                    i += 1;
                    if i < toks.len() && toks[i].kind == Kind::Semi {
                        i += 1;
                    }
                    return (
                        i,
                        vec![ImportItem {
                            path: prefix,
                            alias: None,
                            glob: true,
                        }],
                    );
                }
                Some(Kind::OpenBracket) => match parse_brace_items(toks, src, i + 1, &prefix) {
                    Some((end, items)) => return (end, items),
                    None => return (start, Vec::new()),
                },
                _ => return (start, Vec::new()),
            }
        } else {
            let alias = if i + 1 < toks.len()
                && toks[i].is_ident(src, "as")
                && toks[i + 1].kind == Kind::Ident
            {
                let aliased = toks[i + 1].text(src);
                i += 2;
                Some(aliased)
            } else {
                None
            };
            if i < toks.len() && toks[i].kind == Kind::Semi {
                i += 1;
            }
            return (
                i,
                vec![ImportItem {
                    path: prefix,
                    alias,
                    glob: false,
                }],
            );
        }
    }
}

/// Names that a `use` tree in this file binds, where the bound name stands for a sleep:
/// `use std::thread::sleep;` (or `time::sleep`), an `as` alias of either, or a glob of the
/// `thread` or `time` module.
fn import_bindings<'a>(toks: &'a [Tok], src: &'a str) -> Vec<&'a str> {
    let mut bindings: Vec<&'a str> = Vec::new();
    let mut i = 0usize;
    while i < toks.len() {
        if toks[i].is_ident(src, "use") {
            let (end, items) = parse_use_items(toks, src, i + 1);
            for item in items {
                if let Some(name) = binding_for(item) {
                    bindings.push(name);
                }
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
    bindings
}

/// Fixed-sleep call sites: a call whose path ends in `thread::sleep` or `time::sleep` in any
/// prefix and spacing, plus any bare call through a sleep import of this file.
fn count_sleep_calls(toks: &[Tok], src: &str, bindings: &[&str]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 1 < toks.len() {
        if toks[i].is_ident(src, "sleep") && toks[i + 1].kind == Kind::OpenParen {
            let direct = i >= 2
                && toks[i - 1].kind == Kind::ColonColon
                && matches!(toks[i - 2].text(src), "thread" | "time");
            if direct || bindings.contains(&"sleep") {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

/// Lines carrying a bare `#[ignore]` (whitespace and line breaks between the tokens are free);
/// `#[ignore = "why"]` and any other attribute pass.
fn bare_ignore_lines(toks: &[Tok], src: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    if toks.len() >= 4 {
        for i in 0..=(toks.len() - 4) {
            if toks[i].kind == Kind::Hash
                && toks[i + 1].kind == Kind::OpenBracket
                && toks[i + 2].is_ident(src, "ignore")
                && toks[i + 3].kind == Kind::CloseBracket
            {
                lines.push(line_of(src, toks[i].start));
            }
        }
    }
    lines
}

fn fixed_sleep_sites() -> Vec<(PathBuf, usize)> {
    let crates_dir = workspace_root().join("crates");
    let mut sites = Vec::new();
    for path in crate_trees(&crates_dir, &["tests"]) {
        let src = read_source(&path);
        let toks = tokenize(&src, &path);
        let count = count_sleep_calls(&toks, &src, &import_bindings(&toks, &src));
        if count > 0 {
            sites.push((path, count));
        }
    }
    sites
}

fn bare_ignores() -> Vec<(PathBuf, usize)> {
    let crates_dir = workspace_root().join("crates");
    let mut bare = Vec::new();
    for path in crate_trees(&crates_dir, &["src", "tests"]) {
        let src = read_source(&path);
        let toks = tokenize(&src, &path);
        for line in bare_ignore_lines(&toks, &src) {
            bare.push((path.clone(), line));
        }
    }
    bare
}

#[test]
fn fixed_test_sleeps_may_only_go_down() {
    let sites = fixed_sleep_sites();
    let total: usize = sites.iter().map(|(_, count)| *count).sum();
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

#[cfg(test)]
mod scanner_controls {
    use super::*;

    const CALL: &str = "    std::thread::sleep(std::time::Duration::ZERO);\n";

    fn fixture(body: &str, prefix: &str) -> String {
        format!("{prefix}#[test]\nfn fixture() {{\n{body}}}\n")
    }

    fn sleep_count(src: &str) -> usize {
        let toks = tokenize(src, Path::new("<control>"));
        count_sleep_calls(&toks, src, &import_bindings(&toks, src))
    }

    fn ignore_lines(src: &str) -> Vec<usize> {
        let toks = tokenize(src, Path::new("<control>"));
        bare_ignore_lines(&toks, src)
    }

    #[test]
    fn control_sleep_at_ceiling_is_exact() {
        let src = fixture(&CALL.repeat(MAX_FIXED_TEST_SLEEPS), "");
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_one_real_call_over() {
        let src = fixture(&CALL.repeat(MAX_FIXED_TEST_SLEEPS + 1), "");
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_sleep_in_comment_is_not_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS)
                + "    // std::thread::sleep(std::time::Duration::ZERO);\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_sleep_in_string_is_not_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS) + "    let _ = \"tokio::time::sleep(...)\";\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_sleep_in_import_is_not_counted() {
        let src = fixture(
            CALL.repeat(MAX_FIXED_TEST_SLEEPS).as_str(),
            "#[allow(unused_imports)]\nuse std::thread::sleep;\n",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS);
    }

    #[test]
    fn control_empty_string_keeps_the_scan_in_sync() {
        let src =
            "fn f() {\n    let _ = \"\";\n    std::thread::sleep(std::time::Duration::ZERO);\n}\n";
        assert_eq!(sleep_count(src), 1);
    }

    #[test]
    fn control_escaped_quote_start_keeps_the_scan_in_sync() {
        let src = "fn f() {\n    let _ = \"\\\"quoted\\\"\";\n    std::thread::sleep(std::time::Duration::ZERO);\n}\n";
        assert_eq!(sleep_count(src), 1);
    }

    #[test]
    fn control_spaced_real_call_is_counted() {
        let src = fixture(
            &(CALL.repeat(MAX_FIXED_TEST_SLEEPS)
                + "    std :: thread :: sleep(std::time::Duration::ZERO);\n"),
            "",
        );
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_imported_calls_are_counted() {
        let body = CALL.repeat(MAX_FIXED_TEST_SLEEPS - 1)
            + "    sleep(std::time::Duration::ZERO);\n    sleep(std::time::Duration::ZERO);\n";
        let src = fixture(&body, "use std::thread::sleep;\n");
        assert_eq!(sleep_count(&src), MAX_FIXED_TEST_SLEEPS + 1);
    }

    #[test]
    fn control_reasoned_ignore_passes() {
        let src = "#[test]\n#[ignore = \"requires a dedicated runner\"]\nfn sample() {}\n";
        assert!(ignore_lines(src).is_empty());
    }

    #[test]
    fn control_literal_bare_ignore_is_found() {
        let src = "#[test]\n#[ignore]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_formatted_bare_ignore_is_found() {
        let src = "#[test]\n#[ignore ]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_multiline_bare_ignore_is_found() {
        let src = "#[test]\n#[\n    ignore\n]\nfn sample() {}\n";
        assert_eq!(ignore_lines(src), vec![2]);
    }

    #[test]
    fn control_ignore_in_raw_string_is_not_found() {
        let src = "#[test]\nfn sample() { let _ = r#\"\n#[ignore]\n\"#; }\n";
        assert!(ignore_lines(src).is_empty());
    }

    #[test]
    fn control_lexer_edges_stay_opaque() {
        let src = "/* thread::sleep( /* nested */ still a comment) */\n\
                   let a = \"/* not a comment \\\" quoted\";\n\
                   let b = '(';\nlet c = 'x';\nfn f<'a>(_: &'a u8) {}\n";
        let toks = tokenize(src, Path::new("<control>"));
        assert_eq!(toks.iter().filter(|t| t.kind == Kind::OpenParen).count(), 1);
        assert!(!toks.iter().any(|t| t.is_ident(src, "thread")));
        assert_eq!(sleep_count(src), 0);
    }
}
