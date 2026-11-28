//! A published turn's decision and changed paths become one turn record. Its
//! chat text never does, and forgetting the turn removes the record.
use super::*;

pub(super) struct Published {
    /// The decision title first, then rationale, scope and the paths as given.
    pub body: String,
    pub paths: Vec<RelativePath>,
}

pub(super) fn key(event: &se_types::EventId) -> Result<RecordKey> {
    RecordKey::new(format!("turn:{}", event.as_str()))
}

/// None when the turn names no decision or paths, or its prose was erased.
pub(super) fn document(event: &StoredEvent) -> Result<Option<Published>> {
    let EventBody::SessionTurnPublished {
        body: Some(StoredText::Present(doc)),
        ..
    } = &event.body
    else {
        return Ok(None);
    };
    let prose: serde_json::Value = serde_json::from_str(doc)
        .map_err(|e| scope::unreadable("published turn prose", &e.to_string()))?;
    let decision = &prose["decision"];
    let mut lines: Vec<String> = ["title", "rationale", "scope"]
        .iter()
        .filter_map(|field| decision[field].as_str())
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .collect();
    let named: Vec<&str> = prose["paths"]
        .as_array()
        .map(|paths| paths.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    if lines.is_empty() && named.is_empty() {
        return Ok(None);
    }
    if decision["title"].as_str().is_none() {
        lines.insert(0, format!("Published turn changed {} paths", named.len()));
    }
    // Only repository-relative paths link to files; others stay searchable text.
    let paths = named
        .iter()
        .filter_map(|path| RelativePath::new(*path).ok())
        .collect();
    lines.extend(named.iter().map(|path| (*path).to_owned()));
    Ok(Some(Published {
        body: lines.join("\n"),
        paths,
    }))
}
