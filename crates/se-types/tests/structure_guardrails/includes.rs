//! Stitching Rust source together with `include!` hides a module's real size
//! from the per-file ceiling and gives its parts no interface. Existing
//! carriers are listed in `include-ratchet.json`; the list and each carrier's
//! stitched size may only shrink, and new carriers or fragments are refused.
use super::*;

const RATCHET: &str = include_str!("../include-ratchet.json");
const RATCHET_PATH: &str = "crates/se-types/tests/include-ratchet.json";
const MAX_SITES: usize = 1_024;

struct Site {
    target: String,
}

struct Listed {
    lines: usize,
    fragments: BTreeSet<String>,
}

fn listed(source: &str) -> Result<BTreeMap<String, Listed>, String> {
    let document: Value =
        serde_json::from_str(source).map_err(|error| format!("{RATCHET_PATH}: {error}"))?;
    let carriers = document["carriers"]
        .as_object()
        .ok_or_else(|| format!("{RATCHET_PATH}: carriers must be an object"))?;
    let mut out = BTreeMap::new();
    for (carrier, entry) in carriers {
        let lines = entry["lines"]
            .as_u64()
            .and_then(|lines| usize::try_from(lines).ok())
            .ok_or_else(|| format!("{RATCHET_PATH}: {carrier} needs a line count"))?;
        let fragments = entry["fragments"]
            .as_array()
            .ok_or_else(|| format!("{RATCHET_PATH}: {carrier} needs fragments"))?
            .iter()
            .map(|fragment| {
                fragment
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{RATCHET_PATH}: {carrier} has a non-string fragment"))
            })
            .collect::<Result<_, _>>()?;
        out.insert(carrier.clone(), Listed { lines, fragments });
    }
    Ok(out)
}

fn validate_include_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(format!("invalid include path {path:?}"));
    }
    if !path.ends_with(".rs") {
        return Err(format!("include target is not .rs: {path:?}"));
    }
    for segment in path.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") || segment.contains(':') {
            return Err(format!("invalid include path segment in {path:?}"));
        }
    }
    Ok(())
}

/// The macro must occupy one canonical `include!("path.rs");` line, so a
/// multi-line or decorated call cannot slip past the ratchet.
fn parse_include_line(line: &[u8]) -> Result<String, String> {
    let trimmed = line.strip_suffix(b"\n").unwrap_or(line);
    let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
    let start = trimmed
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(trimmed.len());
    let end = trimmed
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    let canonical = &trimmed[start..end];
    let prefix = b"include!(\"";
    let suffix = b"\");";
    if !canonical.starts_with(prefix) || !canonical.ends_with(suffix) {
        return Err(
            "include macro must occupy one canonical include!(\"path.rs\"); line".to_owned(),
        );
    }
    let path = &canonical[prefix.len()..canonical.len() - suffix.len()];
    let path = std::str::from_utf8(path).map_err(|_| "include path is not UTF-8".to_owned())?;
    validate_include_path(path)?;
    Ok(path.to_owned())
}

/// Every `include!` site in the carrier. Comments, string literals, byte and
/// C strings and raw strings are skipped, and `include_str!`/`include_bytes!`
/// are not `include!` of Rust source, so their identifiers never match. The
/// target is resolved against the carrier's directory, as the macro resolves
/// it.
fn detect_sites(carrier: &str, bytes: &[u8]) -> Result<Vec<Site>, String> {
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
        if bytes.get(cursor..cursor + 7) == Some(b"include")
            && (cursor == 0 || !is_ident(bytes[cursor - 1]))
            && bytes.get(cursor + 7).is_none_or(|byte| !is_ident(*byte))
        {
            let bang = skip_trivia(bytes, cursor + 7)?;
            if bytes.get(bang) == Some(&b'!') {
                let line_start = bytes[..cursor]
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .map_or(0, |index| index + 1);
                let line_end = bytes[cursor..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| cursor + offset + 1);
                let relative = parse_include_line(&bytes[line_start..line_end])?;
                let parent = Path::new(carrier)
                    .parent()
                    .ok_or_else(|| format!("carrier has no parent: {carrier}"))?;
                let resolved = parent.join(&relative);
                if resolved
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
                {
                    return Err(format!("include target escapes its carrier: {relative:?}"));
                }
                let resolved = resolved.to_string_lossy().replace('\\', "/");
                if sites.len() >= MAX_SITES {
                    return Err(format!("include sites exceeds bound {MAX_SITES}"));
                }
                sites.push(Site { target: resolved });
                cursor = line_end;
                continue;
            }
        }
        cursor += 1;
    }
    Ok(sites)
}

/// Every carrier's fragments and its size counted with them.
fn stitched(files: &BTreeMap<String, Vec<u8>>) -> Result<BTreeMap<String, Listed>, String> {
    let mut out: BTreeMap<String, Listed> = BTreeMap::new();
    for (path, bytes) in files {
        for site in detect_sites(path, bytes)? {
            let fragment = files
                .get(&site.target)
                .ok_or_else(|| format!("{path} includes missing {}", site.target))?;
            let entry = out.entry(path.clone()).or_insert_with(|| Listed {
                lines: physical_line_count(bytes),
                fragments: BTreeSet::new(),
            });
            entry.lines += physical_line_count(fragment);
            entry.fragments.insert(site.target);
        }
    }
    Ok(out)
}

#[test]
fn stitched_rust_source_only_shrinks() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let inventory = rust_source_inventory(&root)?;
    let allowed = listed(RATCHET)?;
    let found = stitched(&inventory)?;
    let mut problems = Vec::new();
    for (carrier, now) in &found {
        let Some(limit) = allowed.get(carrier) else {
            problems.push(format!(
                "{carrier}: new include! of Rust source; use a submodule with a real interface"
            ));
            continue;
        };
        for fragment in now.fragments.difference(&limit.fragments) {
            problems.push(format!(
                "{carrier}: new include!(\"{fragment}\"); use a submodule with a real interface"
            ));
        }
        if now.lines > limit.lines {
            problems.push(format!(
                "{carrier}: stitched size grew from {} to {} lines; split it by responsibility",
                limit.lines, now.lines
            ));
        }
    }
    for (carrier, limit) in &allowed {
        let now = found.get(carrier);
        for fragment in &limit.fragments {
            if now.is_none_or(|now| !now.fragments.contains(fragment)) {
                problems.push(format!(
                    "{carrier}: {fragment} is no longer stitched; delete it from {RATCHET_PATH}"
                ));
            }
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("\n").into())
}

#[test]
fn stitched_size_counts_the_carrier_and_its_fragments() -> Result<(), Box<dyn Error>> {
    let mut files = BTreeMap::new();
    files.insert(
        "crates/example/src/lib.rs".to_owned(),
        b"include!(\"part.rs\");\n".to_vec(),
    );
    files.insert(
        "crates/example/src/part.rs".to_owned(),
        b"fn a() {}\nfn b() {}\n".to_vec(),
    );
    let found = stitched(&files)?;
    let carrier = found
        .get("crates/example/src/lib.rs")
        .ok_or("the carrier must be found")?;
    assert_eq!(carrier.lines, 3);
    assert!(carrier.fragments.contains("crates/example/src/part.rs"));
    Ok(())
}

#[test]
fn the_site_detector_skips_literals_and_comments() -> Result<(), Box<dyn Error>> {
    let source = br#"
// include!("gone.rs");
/* include!("gone.rs"); */
fn main() {
    let a = "include!(\"gone.rs\");";
    let b = b"include!(\"gone.rs\");";
    let c = c"include!(\"gone.rs\");";
    let d = r"include!(gone.rs)";
    let e = include_str!("gone.rs");
    let f = include_bytes!("gone.bin");
    let g = includemod!("gone.rs");
    include!("part.rs");
}
"#;
    let sites = detect_sites("crates/example/src/lib.rs", source)?;
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].target, "crates/example/src/part.rs");
    Ok(())
}
