//! Only explicit path/query fields; shell commands and patch text grant no facts.
use super::*;
use serde_json::Value;

pub(super) fn paths(values: Vec<&Value>, cwd: Option<&Value>) -> Target {
    if values.len() > 16 {
        return Target::Unknown(UnknownReason::OverBudget);
    }
    if values.is_empty() {
        return Target::Unknown(UnknownReason::NoNativeTarget);
    }
    let cwd = match cwd {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if valid(text) => Some(text.clone()),
        Some(Value::String(text)) if text.len() > 1024 => {
            return Target::Unknown(UnknownReason::OverBudget);
        }
        _ => return Target::Unknown(UnknownReason::UnsupportedShape),
    };
    let mut paths = Vec::new();
    for value in values {
        let Some(text) = value.as_str() else {
            return Target::Unknown(UnknownReason::UnsupportedShape);
        };
        if text.len() > 1024 {
            return Target::Unknown(UnknownReason::OverBudget);
        }
        if !valid(text) {
            return Target::Unknown(UnknownReason::UnsupportedShape);
        }
        paths.push(ObservedPath {
            spelling: text.into(),
            cwd: cwd.clone(),
            content_revision: None,
        });
    }
    Target::Paths(paths)
}
fn valid(text: &str) -> bool {
    !text.is_empty() && text.len() <= 1024 && !text.contains('\0')
}

pub(super) fn arguments(value: Option<&Value>, cwd: Option<&Value>) -> Target {
    let Some(value) = value.and_then(Value::as_object) else {
        return Target::Unknown(UnknownReason::UnsupportedShape);
    };
    let mut names = Vec::new();
    for key in ["file_path", "path", "notebook_path"] {
        if let Some(path) = value.get(key) {
            names.push(path);
        }
    }
    if let Some(paths) = value.get("paths") {
        let Some(paths) = paths.as_array() else {
            return Target::Unknown(UnknownReason::UnsupportedShape);
        };
        if paths.len() > 16 {
            return Target::Unknown(UnknownReason::OverBudget);
        }
        names.extend(paths);
    }
    if let Some(query) = value.get("query") {
        if !names.is_empty() {
            return Target::Unknown(UnknownReason::ConflictingEvidence);
        }
        return match query.as_str() {
            Some(text) if valid(text) => Target::Query(text.into()),
            Some(text) if text.len() > 1024 => Target::Unknown(UnknownReason::OverBudget),
            _ => Target::Unknown(UnknownReason::UnsupportedShape),
        };
    }
    paths(names, cwd)
}
