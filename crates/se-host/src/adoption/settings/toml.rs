//! Preserve unrelated TOML text while editing exact journaled hook entries.
use super::*;
use toml_edit::{DocumentMut, Item, Table};

fn parse(bytes: &[u8]) -> Result<DocumentMut> {
    std::str::from_utf8(bytes)
        .map_err(|_| invalid("UTF-8 provider configuration"))?
        .parse()
        .map_err(|_| invalid("valid TOML; existing provider configuration was preserved"))
}
pub(super) fn read(bytes: &[u8]) -> Result<Value> {
    toml_edit::de::from_document(parse(bytes)?).map_err(|_| invalid("provider TOML settings"))
}
fn group(value: &Value) -> Result<Table> {
    toml_edit::ser::to_document(value)
        .map(|doc| doc.as_table().clone())
        .map_err(|_| invalid("serializable provider hook"))
}
fn hooks(doc: &mut DocumentMut) -> Result<&mut dyn toml_edit::TableLike> {
    if !doc.contains_key("hooks") {
        doc.insert("hooks", Item::Table(Table::new()));
    }
    doc.get_mut("hooks")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| invalid("a provider hooks table"))
}
fn append(hooks: &mut dyn toml_edit::TableLike, event: &str, value: &Value) -> Result<()> {
    if !hooks.contains_key(event) {
        hooks.insert(event, toml_edit::value(toml_edit::Array::new()));
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
pub(super) fn apply(before: &[u8], expected: &Value, edits: &[text::Edit]) -> Result<Vec<u8>> {
    let mut doc = parse(before)?;
    for edit in edits {
        match edit {
            text::Edit::Append(event, value) => append(hooks(&mut doc)?, event, value)?,
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
    let bytes = doc.to_string().into_bytes();
    if read(&bytes)? != *expected {
        return Err(invalid(
            "exact owned TOML edits with unrelated values preserved",
        ));
    }
    Ok(bytes)
}
