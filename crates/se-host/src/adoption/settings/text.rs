//! Change owned hook entries without reserializing unrelated provider settings.
use super::*;
use std::ops::Range;

pub(super) enum Edit {
    Append(String, Value),
    Remove(String, usize),
    RemoveEvent(String),
    RemoveHooks,
}
struct Item {
    key: Option<String>,
    start: usize,
    value: Range<usize>,
    before: Option<usize>,
    after: Option<usize>,
}
fn malformed() -> SeError {
    invalid("unambiguous JSON settings with only owned hook entries changed")
}
fn whitespace(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}
fn string_end(bytes: &[u8], mut at: usize) -> Result<usize> {
    if bytes.get(at) != Some(&b'"') {
        return Err(malformed());
    }
    at += 1;
    while let Some(byte) = bytes.get(at) {
        match byte {
            b'"' => return Ok(at + 1),
            b'\\' => at += 2,
            _ => at += 1,
        }
    }
    Err(malformed())
}
// Full JSON validation happens before editing. This scanner only locates
// token boundaries, including strings nested inside containers.
fn value_end(bytes: &[u8], start: usize) -> Result<usize> {
    match bytes.get(start) {
        Some(b'"') => string_end(bytes, start),
        Some(b'{' | b'[') => {
            let mut depth = 1_usize;
            let mut at = start + 1;
            while let Some(byte) = bytes.get(at) {
                match byte {
                    b'"' => at = string_end(bytes, at)?,
                    b'{' | b'[' => {
                        depth += 1;
                        at += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        at += 1;
                        if depth == 0 {
                            return Ok(at);
                        }
                    }
                    _ => at += 1,
                }
            }
            Err(malformed())
        }
        Some(_) => {
            let mut at = start;
            while bytes
                .get(at)
                .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(b, b',' | b'}' | b']'))
            {
                at += 1;
            }
            if at == start {
                Err(malformed())
            } else {
                Ok(at)
            }
        }
        None => Err(malformed()),
    }
}
fn items(bytes: &[u8], container: Range<usize>, object: bool) -> Result<Vec<Item>> {
    let (open, close) = if object { (b'{', b'}') } else { (b'[', b']') };
    if bytes.get(container.start) != Some(&open)
        || bytes.get(container.end.saturating_sub(1)) != Some(&close)
    {
        return Err(malformed());
    }
    let mut result: Vec<Item> = vec![];
    let mut at = whitespace(bytes, container.start + 1);
    let mut before = None;
    while bytes.get(at) != Some(&close) {
        let start = at;
        let key = if object {
            let end = string_end(bytes, at)?;
            let key: String = serde_json::from_slice(&bytes[at..end]).map_err(|_| malformed())?;
            if result.iter().any(|item| item.key.as_ref() == Some(&key)) {
                return Err(malformed());
            }
            at = whitespace(bytes, end);
            if bytes.get(at) != Some(&b':') {
                return Err(malformed());
            }
            at = whitespace(bytes, at + 1);
            Some(key)
        } else {
            None
        };
        let end = value_end(bytes, at)?;
        let next = whitespace(bytes, end);
        let after = (bytes.get(next) == Some(&b',')).then_some(next);
        result.push(Item {
            key,
            start,
            value: at..end,
            before,
            after,
        });
        if after.is_none() {
            if next != container.end - 1 {
                return Err(malformed());
            }
            break;
        }
        before = after;
        at = whitespace(bytes, next + 1);
    }
    Ok(result)
}
fn root(bytes: &[u8]) -> Result<Range<usize>> {
    let start = whitespace(bytes, 0);
    Ok(start..value_end(bytes, start)?)
}
fn member(bytes: &[u8], object: Range<usize>, name: &str) -> Result<Option<Range<usize>>> {
    Ok(items(bytes, object, true)?
        .into_iter()
        .find(|item| item.key.as_deref() == Some(name))
        .map(|item| item.value))
}
fn append(bytes: &mut Vec<u8>, container: Range<usize>, object: bool, value: &[u8]) -> Result<()> {
    let comma = !items(bytes, container.clone(), object)?.is_empty();
    let mut added = Vec::with_capacity(value.len() + usize::from(comma));
    if comma {
        added.push(b',');
    }
    added.extend_from_slice(value);
    drop(bytes.splice(container.end - 1..container.end - 1, added));
    Ok(())
}
fn remove(bytes: &mut Vec<u8>, container: Range<usize>, object: bool, index: usize) -> Result<()> {
    let entries = items(bytes, container, object)?;
    let item = entries.get(index).ok_or_else(malformed)?;
    let span = if let Some(before) = item.before {
        before..item.value.end
    } else if let Some(after) = item.after {
        item.start..after + 1
    } else {
        item.start..item.value.end
    };
    drop(bytes.drain(span));
    Ok(())
}
fn remove_member(bytes: &mut Vec<u8>, container: Range<usize>, name: &str) -> Result<()> {
    let index = items(bytes, container.clone(), true)?
        .iter()
        .position(|item| item.key.as_deref() == Some(name))
        .ok_or_else(malformed)?;
    remove(bytes, container, true, index)
}
fn property(name: &str, value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(name).map_err(|_| malformed())?;
    bytes.push(b':');
    bytes.extend(serde_json::to_vec(value).map_err(|_| malformed())?);
    Ok(bytes)
}
pub(super) fn apply(before: &[u8], expected: &Value, edits: &[Edit]) -> Result<Vec<u8>> {
    let mut bytes = if before.is_empty() {
        b"{}".to_vec()
    } else {
        before.to_vec()
    };
    let _: Value = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
    for edit in edits {
        let document = root(&bytes)?;
        let hooks = member(&bytes, document.clone(), "hooks")?;
        match edit {
            Edit::Append(event, entry) => {
                if let Some(hooks) = hooks {
                    if let Some(array) = member(&bytes, hooks.clone(), event)? {
                        let value = serde_json::to_vec(entry).map_err(|_| malformed())?;
                        append(&mut bytes, array, false, &value)?;
                    } else {
                        append(&mut bytes, hooks, true, &property(event, &json!([entry]))?)?;
                    }
                } else {
                    let mut created = serde_json::Map::new();
                    created.insert(event.clone(), json!([entry]));
                    append(
                        &mut bytes,
                        document,
                        true,
                        &property("hooks", &Value::Object(created))?,
                    )?;
                }
            }
            Edit::Remove(event, index) => {
                let hooks = hooks.ok_or_else(malformed)?;
                let array = member(&bytes, hooks, event)?.ok_or_else(malformed)?;
                remove(&mut bytes, array, false, *index)?;
            }
            Edit::RemoveEvent(event) => {
                remove_member(&mut bytes, hooks.ok_or_else(malformed)?, event)?
            }
            Edit::RemoveHooks => remove_member(&mut bytes, document, "hooks")?,
        }
    }
    let actual: Value = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
    if &actual != expected {
        return Err(malformed());
    }
    if before.is_empty() {
        bytes.push(b'\n');
    }
    Ok(bytes)
}
