//! Preserve unrelated TOML text while editing exact journaled hook entries.
use super::*;
use toml_edit::{DocumentMut, Item, Table};

fn parse(path: &Path, bytes: &[u8]) -> Result<DocumentMut> {
    std::str::from_utf8(bytes)
        .map_err(|_| invalid("UTF-8 provider configuration"))?
        .parse()
        .map_err(|error: toml_edit::TomlError| {
            let at = error.span().map_or(0, |span| span.start.min(bytes.len()));
            let line = 1 + bytes[..at].iter().filter(|b| **b == b'\n').count();
            let expected = format!(
                "valid TOML at line {line}: {}; existing bytes were preserved",
                error.message().escape_debug()
            );
            let mut error = SeError::invalid(&path.display().to_string(), &expected);
            error.body = error.body.with_remedy(se_types::Remedy {
                text: format!(
                    "Fix line {line} of {} and retry se init --adopt --provider codex.",
                    path.display()
                ),
                command: None,
            });
            error
        })
}
pub(super) fn read(path: &Path, bytes: &[u8]) -> Result<Value> {
    toml_edit::de::from_document(parse(path, bytes)?).map_err(|_| invalid("provider TOML settings"))
}
fn group(value: &Value) -> Result<Table> {
    toml_edit::ser::to_document(value)
        .map(|doc| doc.as_table().clone())
        .map_err(|_| invalid("serializable provider hook"))
}
fn hooks(doc: &mut DocumentMut) -> Result<&mut dyn toml_edit::TableLike> {
    if !doc.contains_key("hooks") {
        let mut table = Table::new();
        table.set_implicit(true);
        doc.insert("hooks", Item::Table(table));
    }
    doc.get_mut("hooks")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| invalid("a provider hooks table"))
}
fn append(hooks: &mut Item, event: &str, value: &Value) -> Result<()> {
    let inline = hooks.is_inline_table();
    let hooks = hooks
        .as_table_like_mut()
        .ok_or_else(|| invalid("a provider hooks table"))?;
    if !hooks.contains_key(event) {
        hooks.insert(
            event,
            if inline {
                toml_edit::value(toml_edit::Array::new())
            } else {
                Item::ArrayOfTables(toml_edit::ArrayOfTables::new())
            },
        );
    }
    let item = hooks
        .get_mut(event)
        .ok_or_else(|| invalid("hook event array"))?;
    if let Some(array) = item.as_array_mut() {
        array.push(toml_edit::Value::InlineTable(
            group(value)?.into_inline_table(),
        ));
    } else if let Some(array) = item.as_array_of_tables_mut() {
        array.push(group(value)?);
    } else {
        return Err(invalid("array-valued hook events"));
    }
    Ok(())
}
fn remove(hooks: &mut dyn toml_edit::TableLike, event: &str, index: usize) -> Result<()> {
    let item = hooks
        .get_mut(event)
        .ok_or_else(|| invalid("hook event array"))?;
    if let Some(array) = item.as_array_mut() {
        array.remove(index);
    } else if let Some(array) = item.as_array_of_tables_mut() {
        array.remove(index);
    } else {
        return Err(invalid("array-valued hook events"));
    }
    Ok(())
}
pub(super) fn apply(
    path: &Path,
    before: &[u8],
    expected: &Value,
    edits: &[text::Edit],
) -> Result<Vec<u8>> {
    let mut doc = parse(path, before)?;
    for edit in edits {
        match edit {
            text::Edit::Append(event, value) => {
                hooks(&mut doc)?;
                append(
                    doc.get_mut("hooks")
                        .ok_or_else(|| invalid("a provider hooks table"))?,
                    event,
                    value,
                )?;
            }
            text::Edit::Remove(event, index) => {
                remove(hooks(&mut doc)?, event, *index)?;
            }
            text::Edit::RemoveEvent(event) => {
                hooks(&mut doc)?.remove(event);
            }
            text::Edit::RemoveHooks => {
                doc.remove("hooks");
            }
            text::Edit::Trust(key, hash) => {
                let hooks = hooks(&mut doc)?;
                if !hooks.contains_key("state") {
                    hooks.insert("state", Item::Table(Table::new()));
                }
                let state = hooks
                    .get_mut("state")
                    .and_then(Item::as_table_like_mut)
                    .ok_or_else(|| invalid("hook state table"))?;
                let mut row = Table::new();
                row.insert("trusted_hash", toml_edit::value(hash));
                state.insert(key, Item::Table(row));
            }
            text::Edit::RemoveTrust(key) => {
                let hooks = hooks(&mut doc)?;
                if let Some(state) = hooks.get_mut("state").and_then(Item::as_table_like_mut) {
                    state.remove(key);
                }
                if expected.get("hooks").and_then(|h| h.get("state")).is_none() {
                    hooks.remove("state");
                }
            }
        }
    }
    let bytes = newlines(before, &doc.to_string())?;
    if read(path, &bytes)? != *expected {
        return Err(invalid(
            "exact owned TOML edits with unrelated values preserved",
        ));
    }
    Ok(bytes)
}

fn newlines(before: &[u8], rendered: &str) -> Result<Vec<u8>> {
    // The serializer drops CR, even from untouched text. Retain original lines
    // wherever their normalized text is unchanged, including mixed LF/CRLF.
    let before =
        std::str::from_utf8(before).map_err(|_| invalid("UTF-8 provider configuration"))?;
    let lines: Vec<_> = before.split_inclusive('\n').collect();
    let normalized = before.replace('\r', "");
    let mut crlf = lines
        .iter()
        .find(|line| line.ends_with('\n'))
        .is_some_and(|line| line.ends_with("\r\n"));
    let diff = similar::TextDiff::configure()
        .algorithm(similar::Algorithm::Patience)
        .diff_lines(normalized.as_str(), rendered);
    let mut result = Vec::new();
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Equal | similar::ChangeTag::Delete => {
                let line = lines
                    .get(
                        change
                            .old_index()
                            .ok_or_else(|| invalid("original TOML line index"))?,
                    )
                    .ok_or_else(|| invalid("original TOML line"))?;
                if line.ends_with('\n') {
                    crlf = line.ends_with("\r\n");
                }
                if change.tag() == similar::ChangeTag::Equal {
                    result.extend_from_slice(line.as_bytes());
                }
            }
            similar::ChangeTag::Insert => {
                let line = change.value();
                if crlf {
                    result.extend_from_slice(line.replace('\n', "\r\n").as_bytes());
                } else {
                    result.extend_from_slice(line.as_bytes());
                }
            }
        }
    }
    Ok(result)
}
