//! Workspace-wide structure guardrails, adopted from SE Code.
//!
//! SE Code's structure law rejects god files, stitched source, sideways
//! directory sprawl and deep upward reach. This suite is the mechanical
//! carrier of that law for this repository:
//!
//! * every source file under `crates/` has an 800 physical-line ceiling and
//!   every test file a 1,000-line one, the implementation rules of AGENTS.md.
//!   Existing overages sit in one reviewed baseline
//!   (`module-size-baseline.json`) with an exact line count, an owner and a
//!   remediation: the checked-in baseline is the record, the test compares
//!   today's tree against it and fails on any growth, and a reviewed change
//!   to that file is how a limit moves;
//! * each crate and each `src/` directory at depth one and two has a line
//!   budget (`module-budgets.json`) set at the establishment size plus the
//!   larger of 5 percent or 300 lines. Raising a budget is a reviewed change;
//! * each `src/` directory has a file-count budget (`files-per-dir.json`) so a
//!   folder cannot grow sideways into hundreds of files;
//! * `include!` of Rust source is refused except for the shrink-only carrier
//!   list (`include-ratchet.json`);
//! * reaching three levels up with `super::super::super` is refused except for
//!   the shrink-only list (`deep-super-ratchet.json`).
//!
//! Limits are warning signs, not goals: when one trips, extract a distinct
//! responsibility. A forced split that scatters one idea is as bad as a grab
//! bag, and the budget files above are the review surface where that call is
//! made.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const BASELINE: &str = include_str!("module-size-baseline.json");
const SOURCE_MAX_LINES: usize = 800;
const TEST_MAX_LINES: usize = 1_000;

/// Source files carry the 800-line ceiling and files under a crate's
/// `tests/` directory the 1,000-line one, matching AGENTS.md.
fn ceiling_for(file: &str) -> usize {
    if file.split('/').nth(2) == Some("tests") {
        TEST_MAX_LINES
    } else {
        SOURCE_MAX_LINES
    }
}
const MAX_FILES: usize = 8_192;
const MAX_FILE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Exception {
    max_lines: usize,
    owner: String,
    remediation: String,
}

type Baseline = BTreeMap<String, Exception>;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn required_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}

fn required_array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label} must be an array"))
}

fn required_str(value: &Value, label: &str) -> Result<String, String> {
    value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("{label} must be a non-empty string"))
}

fn required_usize(value: &Value, label: &str) -> Result<usize, String> {
    let raw = value
        .as_u64()
        .ok_or_else(|| format!("{label} must be a positive integer"))?;
    usize::try_from(raw).map_err(|_| format!("{label} does not fit usize"))
}

fn parse_baseline(source: &str) -> Result<Baseline, String> {
    let value: Value = serde_json::from_str(source)
        .map_err(|error| format!("module-size baseline is not JSON: {error}"))?;
    let root = required_object(&value, "baseline")?;
    let schema = required_usize(
        root.get("schema_version")
            .ok_or_else(|| "baseline.schema_version is required".to_owned())?,
        "baseline.schema_version",
    )?;
    if schema != 1 {
        return Err(format!("unsupported module-size baseline schema {schema}"));
    }
    let default_max = required_usize(
        root.get("default_max_lines")
            .ok_or_else(|| "baseline.default_max_lines is required".to_owned())?,
        "baseline.default_max_lines",
    )?;
    if default_max != SOURCE_MAX_LINES {
        return Err(format!(
            "baseline.default_max_lines must remain exactly {SOURCE_MAX_LINES}, found {default_max}"
        ));
    }
    let test_max = required_usize(
        root.get("test_max_lines")
            .ok_or_else(|| "baseline.test_max_lines is required".to_owned())?,
        "baseline.test_max_lines",
    )?;
    if test_max != TEST_MAX_LINES {
        return Err(format!(
            "baseline.test_max_lines must remain exactly {TEST_MAX_LINES}, found {test_max}"
        ));
    }

    let rows = required_array(
        root.get("exceptions")
            .ok_or_else(|| "baseline.exceptions is required".to_owned())?,
        "baseline.exceptions",
    )?;
    let mut exceptions = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let label = format!("baseline.exceptions[{index}]");
        let object = required_object(row, &label)?;
        let path = required_str(
            object
                .get("path")
                .ok_or_else(|| format!("{label}.path is required"))?,
            &format!("{label}.path"),
        )?;
        if path.contains('\\') || path.starts_with('/') || path.contains("..") {
            return Err(format!(
                "{label}.path must be a normalized repository-relative path"
            ));
        }
        let exception = Exception {
            max_lines: required_usize(
                object
                    .get("max_lines")
                    .ok_or_else(|| format!("{label}.max_lines is required"))?,
                &format!("{label}.max_lines"),
            )?,
            owner: required_str(
                object
                    .get("owner")
                    .ok_or_else(|| format!("{label}.owner is required"))?,
                &format!("{label}.owner"),
            )?,
            remediation: required_str(
                object
                    .get("remediation")
                    .ok_or_else(|| format!("{label}.remediation is required"))?,
                &format!("{label}.remediation"),
            )?,
        };
        if exception.max_lines <= ceiling_for(&path) {
            return Err(format!(
                "{label}.max_lines must exceed the {}-line ceiling for {path}; remove stale exceptions",
                ceiling_for(&path)
            ));
        }
        if exceptions.insert(path.clone(), exception).is_some() {
            return Err(format!("duplicate module-size exception for {path}"));
        }
    }
    Ok(exceptions)
}

fn entry_is_link_or_reparse(path: &Path, kind: fs::FileType) -> Result<bool, String> {
    if kind.is_symlink() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(false)
    }
}

fn collect_rust_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|error| format!("cannot read {}: {error}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        if entry_is_link_or_reparse(&path, kind)? {
            return Err(format!(
                "source census refuses link or reparse point {}",
                path.display()
            ));
        }
        if kind.is_dir() {
            collect_rust_files(root, &path, files)?;
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?;
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

/// Every `.rs` file under `crates/`, as repository-relative normalized paths
/// with their bytes. Links and reparse points are refused, reads are bounded,
/// so a hostile or accidental entry cannot make the census follow outside the
/// tree or grow without limit.
fn rust_source_inventory(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let crates = root.join("crates");
    let crate_entries = fs::read_dir(&crates)
        .map_err(|error| format!("cannot read {}: {error}", crates.display()))?;
    let mut files = Vec::new();
    for entry in crate_entries {
        let entry = entry.map_err(|error| format!("cannot read crate entry: {error}"))?;
        let crate_root = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot stat {}: {error}", crate_root.display()))?;
        if entry_is_link_or_reparse(&crate_root, kind)? {
            return Err(format!(
                "source census refuses link or reparse-point crate root {}",
                crate_root.display()
            ));
        }
        if kind.is_dir() {
            collect_rust_files(root, &crate_root, &mut files)?;
        }
    }
    files.sort();
    if files.len() > MAX_FILES {
        return Err(format!("source census exceeds {MAX_FILES} files"));
    }

    let mut inventory = BTreeMap::new();
    for relative in files {
        let path = root.join(&relative);
        let source =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if source.len() > MAX_FILE_BYTES {
            return Err(format!(
                "{} is {} bytes; the census caps a file at {MAX_FILE_BYTES}",
                relative.display(),
                source.len()
            ));
        }
        std::str::from_utf8(&source)
            .map_err(|error| format!("cannot read {} as UTF-8: {error}", relative.display()))?;
        let normalized = relative.to_string_lossy().replace('\\', "/");
        inventory.insert(normalized, source);
    }
    Ok(inventory)
}

/// Physical lines: LF, CRLF and lone CR all end a line, and a final line
/// without a newline still counts.
fn physical_line_count(source: &[u8]) -> usize {
    let mut lines = 0;
    let mut cursor = 0;
    let mut has_unterminated_bytes = false;
    while cursor < source.len() {
        match source[cursor] {
            b'\r' => {
                lines += 1;
                cursor += 1;
                if cursor < source.len() && source[cursor] == b'\n' {
                    cursor += 1;
                }
                has_unterminated_bytes = false;
            }
            b'\n' => {
                lines += 1;
                cursor += 1;
                has_unterminated_bytes = false;
            }
            _ => {
                cursor += 1;
                has_unterminated_bytes = true;
            }
        }
    }
    lines + usize::from(has_unterminated_bytes)
}

fn evaluate(
    inventory: &BTreeMap<String, Vec<u8>>,
    exceptions: &BTreeMap<String, Exception>,
) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    let mut used = BTreeSet::new();
    for (path, source) in inventory {
        let lines = physical_line_count(source);
        let max = ceiling_for(path);
        match exceptions.get(path.as_str()) {
            Some(exception) => {
                used.insert(path.clone());
                if lines <= max {
                    failures.push(format!(
                        "{path} is now {lines} lines; remove its stale exception"
                    ));
                } else if lines > exception.max_lines {
                    failures.push(format!(
                        "{path} grew to {lines} lines above its ratcheted ceiling {} ({}, {})",
                        exception.max_lines, exception.owner, exception.remediation
                    ));
                } else if lines < exception.max_lines {
                    failures.push(format!(
                        "{path} shrank to {lines} lines below its recorded ceiling {}; lower the exact ceiling in the same change ({}, {})",
                        exception.max_lines, exception.owner, exception.remediation
                    ));
                }
            }
            None if lines > max => failures.push(format!(
                "{path} is {lines} lines; a new module may not exceed its {max}-line ceiling"
            )),
            None => {}
        }
    }
    for path in exceptions.keys() {
        if !used.contains(path) {
            failures.push(format!(
                "module-size exception names missing Rust source file {path}"
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Shared trivia scanners for the byte-level source checks.
pub(crate) fn is_ident(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

pub(crate) fn quoted_end(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor = cursor.checked_add(2)?,
            byte if byte == quote => return cursor.checked_add(1),
            b'\n' if quote == b'\'' => return None,
            _ => cursor += 1,
        }
    }
    None
}

pub(crate) fn raw_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hash_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let hashes = cursor - hash_start;
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes.get(cursor + 1..cursor + 1 + hashes)
                == Some(&bytes[hash_start..hash_start + hashes])
        {
            return cursor.checked_add(1 + hashes);
        }
        cursor += 1;
    }
    None
}

pub(crate) fn block_comment_end(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut depth = 1_usize;
    let mut cursor = start + 2;
    while cursor + 1 < bytes.len() {
        if &bytes[cursor..cursor + 2] == b"/*" {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| "block-comment depth overflow".to_owned())?;
            cursor += 2;
        } else if &bytes[cursor..cursor + 2] == b"*/" {
            depth -= 1;
            cursor += 2;
            if depth == 0 {
                return Ok(cursor);
            }
        } else {
            cursor += 1;
        }
    }
    Err("unterminated block comment".to_owned())
}

pub(crate) fn skip_trivia(bytes: &[u8], mut cursor: usize) -> Result<usize, String> {
    loop {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"//") {
            cursor = bytes[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| cursor + offset + 1);
        } else if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            cursor = block_comment_end(bytes, cursor)?;
        } else {
            return Ok(cursor);
        }
    }
}

#[test]
fn rust_sources_do_not_create_or_grow_god_files() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let exceptions = parse_baseline(BASELINE)?;
    let inventory = rust_source_inventory(&root)?;
    evaluate(&inventory, &exceptions).map_err(|failures| failures.join("\n").into())
}

#[test]
fn baseline_ceilings_cannot_be_weakened() -> Result<(), Box<dyn Error>> {
    let weakened = BASELINE.replacen(
        "\"default_max_lines\": 800",
        "\"default_max_lines\": 801",
        1,
    );
    let error = match parse_baseline(&weakened) {
        Ok(_) => return Err("an 801-line source ceiling was admitted".into()),
        Err(error) => error,
    };
    assert!(error.contains("must remain exactly 800"));

    let weakened = BASELINE.replacen("\"test_max_lines\": 1000", "\"test_max_lines\": 1001", 1);
    let error = match parse_baseline(&weakened) {
        Ok(_) => return Err("a 1,001-line test ceiling was admitted".into()),
        Err(error) => error,
    };
    assert!(error.contains("must remain exactly 1000"));
    Ok(())
}
#[test]
fn physical_lines_count_lf_crlf_and_lone_cr() {
    assert_eq!(physical_line_count(b"first\nsecond\nthird\n"), 3);
    assert_eq!(physical_line_count(b"first\r\nsecond\r\nthird\r\n"), 3);
    assert_eq!(physical_line_count(b"first\rsecond\rthird"), 3);
    let escaped = "line\r".repeat(TEST_MAX_LINES + 1);
    assert_eq!(physical_line_count(escaped.as_bytes()), TEST_MAX_LINES + 1);
}

#[test]
fn a_new_over_limit_module_is_refused() -> Result<(), Box<dyn Error>> {
    let exceptions = parse_baseline(BASELINE)?;
    let inventory = BTreeMap::from([(
        "crates/example/src/god.rs".to_owned(),
        vec![b'\n'; SOURCE_MAX_LINES + 1],
    )]);
    let failures = match evaluate(&inventory, &BTreeMap::new()) {
        Ok(()) => return Err("the over-limit control was not refused".into()),
        Err(failures) => failures,
    };
    assert!(failures[0].contains("a new module may not exceed its 800-line ceiling"));
    assert!(exceptions.is_empty());
    Ok(())
}

#[test]
fn existing_debt_cannot_grow_and_stale_exceptions_refuse() -> Result<(), Box<dyn Error>> {
    let ceiling = SOURCE_MAX_LINES;
    let path = "crates/example/src/large.rs".to_owned();
    let exceptions = BTreeMap::from([(
        path.clone(),
        Exception {
            max_lines: 1_500,
            owner: "example".to_owned(),
            remediation: "split responsibilities".to_owned(),
        },
    )]);

    let at_cap = BTreeMap::from([(path.clone(), vec![b'\n'; 1_500])]);
    assert!(evaluate(&at_cap, &exceptions).is_ok());

    let grown = BTreeMap::from([(path.clone(), vec![b'\n'; 1_501])]);
    let growth = match evaluate(&grown, &exceptions) {
        Ok(()) => return Err("growth above a ratcheted ceiling was not refused".into()),
        Err(failures) => failures,
    };
    assert!(growth[0].contains("above its ratcheted ceiling"));

    let reduced = BTreeMap::from([(path.clone(), vec![b'\n'; 1_400])]);
    let reduction = match evaluate(&reduced, &exceptions) {
        Ok(()) => return Err("a reduction retained obsolete regrowth headroom".into()),
        Err(failures) => failures,
    };
    assert!(reduction[0].contains("lower the exact ceiling in the same change"));

    let split = BTreeMap::from([(path, vec![b'\n'; ceiling])]);
    let stale = match evaluate(&split, &exceptions) {
        Ok(()) => return Err("a split module retained a stale exception".into()),
        Err(failures) => failures,
    };
    assert!(stale[0].contains("remove its stale exception"));
    Ok(())
}

#[test]
fn the_ceiling_depends_on_the_file_role() -> Result<(), Box<dyn Error>> {
    assert_eq!(ceiling_for("crates/example/src/lib.rs"), SOURCE_MAX_LINES);
    assert_eq!(ceiling_for("crates/example/tests/suite.rs"), TEST_MAX_LINES);
    assert_eq!(
        ceiling_for("crates/example/tests/support/helper.rs"),
        TEST_MAX_LINES
    );
    assert_eq!(
        ceiling_for("crates/example/examples/demo.rs"),
        SOURCE_MAX_LINES
    );
    let src = BTreeMap::from([("crates/example/src/big.rs".to_owned(), vec![b'\n'; 900])]);
    assert!(evaluate(&src, &BTreeMap::new()).is_err());
    let test = BTreeMap::from([("crates/example/tests/big.rs".to_owned(), vec![b'\n'; 900])]);
    assert!(evaluate(&test, &BTreeMap::new()).is_ok());
    Ok(())
}

#[path = "structure_guardrails/budgets.rs"]
mod budgets;

#[path = "structure_guardrails/includes.rs"]
mod includes;

#[path = "structure_guardrails/deep_super.rs"]
mod deep_super;
