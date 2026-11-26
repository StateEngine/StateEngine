//! Describe a trust change the owner makes by hand, as the exact line changes
//! the format-preserving editor would make, so it fits whatever table layout
//! the file already uses.
use super::*;

/// The line changes that would set each entry's `trusted_hash`: an inline
/// table gains its entry in place, and an existing entry changes only that key.
pub fn trust_repair(path: &Path, entries: &[(String, String)]) -> Result<String> {
    let (_, before, mut document) = read_document(path)?;
    let state = document
        .as_object_mut()
        .ok_or_else(|| invalid("settings object"))?
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid("hooks table"))?
        .entry("state")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid("hook state table"))?;
    let mut edits = Vec::new();
    for (key, hash) in entries {
        state
            .entry(key.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| invalid("hook state entries as tables"))?
            .insert("trusted_hash".into(), json!(hash));
        edits.push(text::Edit::Trust(key.clone(), hash.clone()));
    }
    let after = render(path, &before, &document, &edits)?;
    let text = |bytes: &[u8]| {
        std::str::from_utf8(bytes)
            .map(|text| text.replace('\r', ""))
            .map_err(|_| invalid("UTF-8 provider configuration"))
    };
    Ok(changes(path, &text(&before)?, &text(&after)?))
}

fn changes(path: &Path, before: &str, after: &str) -> String {
    let old: Vec<_> = before.lines().collect();
    let new: Vec<_> = after.lines().collect();
    let span = |range: &std::ops::Range<usize>| match range.len() {
        1 => format!("line {}", range.start + 1),
        _ => format!("lines {}-{}", range.start + 1, range.end),
    };
    let mut steps = vec![format!(
        "In {}, counting lines as the file is now:",
        path.display()
    )];
    for op in similar::TextDiff::from_lines(before, after).ops() {
        let (tag, removed, added) = op.as_tag_tuple();
        let (removed_text, added_text) = (
            old[removed.clone()].join("\n"),
            new[added.clone()].join("\n"),
        );
        steps.push(match tag {
            similar::DiffTag::Equal => continue,
            similar::DiffTag::Insert if removed.start == old.len() => {
                format!("At the end, add:\n\n{added_text}\n")
            }
            similar::DiffTag::Insert if removed.start == 0 => {
                format!("At the start, add:\n\n{added_text}\n")
            }
            similar::DiffTag::Insert => {
                format!("After line {}, add:\n\n{added_text}\n", removed.start)
            }
            similar::DiffTag::Delete => format!("Delete {}:\n\n{removed_text}\n", span(&removed)),
            similar::DiffTag::Replace => format!(
                "Replace {}:\n\n{removed_text}\n\nwith:\n\n{added_text}\n",
                span(&removed)
            ),
        });
    }
    steps.join("\n")
}
