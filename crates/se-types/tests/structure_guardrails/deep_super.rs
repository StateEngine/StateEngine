//! Reaching three levels up with `super::super::super` means the module is
//! reaching past two boundary layers into a distant ancestor's private state.
//! The files that do so today are listed in `deep-super-ratchet.json` and the
//! list may only shrink: a new file reaching that far is refused, and a listed
//! file that stopped reaching that far has a stale entry.
use super::*;

const RATCHET: &str = include_str!("../deep-super-ratchet.json");
const RATCHET_PATH: &str = "crates/se-types/tests/deep-super-ratchet.json";
const MARKER: &[u8] = b"super::super::super";

fn listed(source: &str) -> Result<BTreeSet<String>, String> {
    let document: Value =
        serde_json::from_str(source).map_err(|error| format!("{RATCHET_PATH}: {error}"))?;
    let rows = document["files"]
        .as_array()
        .ok_or_else(|| format!("{RATCHET_PATH}: files must be an array"))?;
    let mut out = BTreeSet::new();
    for (index, row) in rows.iter().enumerate() {
        let path = row
            .as_str()
            .ok_or_else(|| format!("{RATCHET_PATH}: files[{index}] must be a string"))?;
        if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains("..") {
            return Err(format!(
                "{RATCHET_PATH}: files[{index}] must be a normalized repository-relative path"
            ));
        }
        out.insert(path.to_owned());
    }
    Ok(out)
}

/// Code positions of `super::super::super` in the file: comments, string,
/// byte, C and raw literals never count, so a mention of the marker in prose
/// is not a reach.
fn deep_super_sites(bytes: &[u8]) -> Result<Vec<usize>, String> {
    let mut sites = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes.get(cursor..cursor + 2) == Some(b"//") {
            cursor = bytes[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| cursor + offset + 1);
            continue;
        }
        if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            cursor = block_comment_end(bytes, cursor)?;
            continue;
        }
        if let Some(end) = raw_end(bytes, cursor) {
            cursor = end;
            continue;
        }
        let quoted = if bytes[cursor] == b'"' {
            quoted_end(bytes, cursor, b'"')
        } else if matches!(bytes.get(cursor..cursor + 2), Some(b"b\"") | Some(b"c\"")) {
            quoted_end(bytes, cursor + 1, b'"')
        } else if bytes[cursor] == b'\'' {
            quoted_end(bytes, cursor, b'\'')
        } else {
            None
        };
        if let Some(end) = quoted {
            cursor = end;
            continue;
        }
        if bytes.get(cursor..cursor + MARKER.len()) == Some(MARKER) {
            sites.push(cursor);
            cursor += MARKER.len();
            continue;
        }
        cursor += 1;
    }
    Ok(sites)
}

#[test]
fn deep_super_reach_only_shrinks() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let inventory = rust_source_inventory(&root)?;
    let allowed = listed(RATCHET)?;
    let mut found = BTreeSet::new();
    for (path, bytes) in &inventory {
        if !deep_super_sites(bytes)?.is_empty() {
            found.insert(path.clone());
        }
    }
    let mut problems = Vec::new();
    for path in &found {
        if !allowed.contains(path) {
            problems.push(format!(
                "{path}: new file reaches three levels up with super::super::super; move the responsibility or re-export the boundary"
            ));
        }
    }
    for path in &allowed {
        if !found.contains(path) {
            problems.push(format!(
                "{path}: no longer reaches three levels up; delete it from {RATCHET_PATH}"
            ));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("\n").into())
}

#[test]
fn deep_super_detection_ignores_prose_and_counts_code() -> Result<(), Box<dyn Error>> {
    let prose = br#"
// super::super::super::x in a comment
/* super::super::super::x in a block comment */
fn main() {
    let a = "super::super::super::x";
    let b = b"super::super::super::x";
    let c = r"super::super::super::x";
}
"#;
    assert!(deep_super_sites(prose)?.is_empty());

    let code = br#"
fn main() {
    let a = super::super::super::value;
}
"#;
    let sites = deep_super_sites(code)?;
    assert_eq!(sites.len(), 1);
    Ok(())
}
