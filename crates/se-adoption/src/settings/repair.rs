//! Tell the owner how to restore StateEngine's own hook trust by hand. The
//! steps are built only from StateEngine's keys and hashes; text already in the
//! file is never echoed, because it can hold unrelated owner secrets.
use super::*;
use toml_edit::{DocumentMut, InlineTable, Item, Key, Table};

/// Steps that set each entry's `trusted_hash`, shaped to fit how the file
/// already writes `hooks` and `hooks.state`.
pub fn trust_repair(path: &Path, entries: &[(String, String)]) -> Result<String> {
    let (_, bytes, _) = read_document(path)?;
    let document = toml::parse(path, &bytes)?;
    let hooks = document.get("hooks");
    let state = hooks
        .and_then(Item::as_table_like)
        .and_then(|hooks| hooks.get("state"));
    let (existing, missing): (Vec<_>, Vec<_>) = entries.iter().partition(|(key, _)| {
        state
            .and_then(Item::as_table_like)
            .is_some_and(|state| state.contains_key(key))
    });
    let file = path.display();
    let mut steps = Vec::new();
    for (key, hash) in existing {
        steps.push(format!(
            "In the existing hooks.state entry {} of {file}, set only this value and keep its other keys:\n\ntrusted_hash = {}\n",
            quoted(key),
            toml_edit::Value::from(hash.as_str())
        ));
    }
    if missing.is_empty() {
        return Ok(steps.join("\n"));
    }
    // Inline tables written with dotted keys have no braces of their own to
    // add entries inside, so they take dotted entries in the enclosing table.
    let inline = |item: Option<&Item>| {
        item.and_then(Item::as_inline_table)
            .map(InlineTable::is_dotted)
    };
    let entries = |prefix: &str| {
        let entries: Vec<_> = missing
            .iter()
            .map(|(key, hash)| format!("{prefix}{} = {}", quoted(key), row(hash)))
            .collect();
        entries.join(", ")
    };
    steps.push(match (inline(hooks), inline(state)) {
        (_, Some(false)) => format!(
            "Inside the existing inline hooks.state table of {file}, add these entries on its line, separated by commas:\n\n{}\n",
            entries("")
        ),
        (_, Some(true)) => format!(
            "Inside the existing inline hooks table of {file}, add these entries on its line, separated by commas:\n\n{}\n",
            entries("state.")
        ),
        (Some(false), None) => {
            let mut rows = InlineTable::new();
            for (key, hash) in &missing {
                rows.insert(key, row(hash).into());
            }
            format!("Inside the existing inline hooks table of {file}, add:\n\nstate = {rows}\n")
        }
        // Absent, ordinary or dotted tables accept new subtables at the end.
        _ => {
            let tables: Vec<_> = missing.iter().map(|(key, hash)| table(key, hash)).collect();
            format!("At the end of {file}, add:\n\n{}", tables.join("\n"))
        }
    });
    Ok(steps.join("\n"))
}

fn quoted(key: &str) -> String {
    Key::new(key).display_repr().into_owned()
}

fn row(hash: &str) -> InlineTable {
    let mut row = InlineTable::new();
    row.insert("trusted_hash", hash.into());
    row
}

/// A standalone `[hooks.state."key"]` table.
fn table(key: &str, hash: &str) -> String {
    let mut state = Table::new();
    state.set_implicit(true);
    state.insert(key, Item::Table(row(hash).into_table()));
    let mut hooks = Table::new();
    hooks.set_implicit(true);
    hooks.insert("state", Item::Table(state));
    let mut document = DocumentMut::new();
    document.insert("hooks", Item::Table(hooks));
    document.to_string()
}
