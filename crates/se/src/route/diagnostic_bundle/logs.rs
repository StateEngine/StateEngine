//! Only the runtime's retained startup-log names are eligible. Never recurse or read configs.
use serde_json::{Value, json};
use std::{io::Read, path::Path, time::SystemTime};

const MAX_ENTRIES: usize = 4096;
const MAX_LOGS: usize = 8;
const MAX_BYTES: usize = 64 * 1024;
pub(super) fn log_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_prefix("runtime-startup-"))
        .and_then(|name| name.strip_suffix(".log"))
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn unreadable(reason: &str) -> Value {
    json!({"state":"unreadable", "inventory_complete":false, "omitted":null,
        "entries":[], "reason":reason})
}
pub(super) fn collect(home: &Path) -> Value {
    // Distinguish a genuinely absent source from failed native custody.
    match std::fs::symlink_metadata(home) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return json!({
            "state":"absent", "inventory_complete":true, "omitted":0, "entries":[],
            "reason":"The selected state home is absent; there are no retained startup logs"});
        }
        Err(_) => return unreadable("Cannot inspect the selected state home"),
        Ok(_) => (),
    }
    let files = match se_proc::NativeStateFiles::open(home) {
        Ok(files) => files,
        Err(_) => {
            return unreadable(
                "Native owner-only state-home custody could not be established; no log contents were read",
            );
        }
    };
    let entries = match std::fs::read_dir(home) {
        Ok(entries) => entries,
        Err(_) => return unreadable("The retained startup-log directory cannot be enumerated"),
    };
    let mut candidates = Vec::new();
    for (scanned, entry) in entries.enumerate() {
        if scanned >= MAX_ENTRIES {
            return unreadable(
                "The directory exceeds the 4096-entry inventory bound; no partial inventory is exported",
            );
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                return unreadable(
                    "A directory entry could not be read; no partial inventory is exported",
                );
            }
        };
        if !log_name(&entry.file_name()) {
            continue;
        }
        // No-follow native readback precedes even mtime inspection.
        let modified = files
            .readback(&entry.path())
            .ok()
            .flatten()
            .and_then(|file| file.metadata().ok())
            .and_then(|meta| meta.modified().ok());
        candidates.push((modified, entry.path()));
    }
    if files.available_bytes().is_err() {
        return unreadable("State-home custody could not be revalidated after log enumeration");
    }
    // Unreadable candidates have unknown age: retain them first rather than hiding
    // them behind eight readable files. Remaining logs are newest first.
    candidates.sort_by(|a, b| match (a.0, b.0) {
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        _ => b.cmp(a),
    });
    let omitted = candidates.len().saturating_sub(MAX_LOGS);
    let entries: Vec<Value> = candidates.into_iter().take(MAX_LOGS).map(|(modified, path)| {
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("unavailable");
        let mut entry = json!({"name":name, "state":"unreadable", "truncated":false});
        if let Some(modified) = modified.and_then(|at| at.duration_since(SystemTime::UNIX_EPOCH).ok()) {
            entry["modified_unix_ms"] = json!(modified.as_millis().to_string());
        }
        let bytes = (|| {
            modified?;
            let file = files.readback(&path).ok().flatten()?;
            let mut bytes = Vec::new();
            file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes).ok()?;
            Some(bytes)
        })();
        match bytes {
            None => entry["reason"] = json!("Protected log readback or modification-time observation failed, or the inventoried file disappeared; no bytes are exported"),
            Some(bytes) if bytes.len() > MAX_BYTES => {
                entry["state"] = json!("oversized");
                entry["truncated"] = json!(true);
                entry["max_bytes"] = json!(MAX_BYTES);
                entry["reason"] = json!("Log exceeds the byte bound; its entire content is omitted to avoid exposing a partial credential");
            }
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(content) => { entry["state"] = json!("observed"); entry["content"] = json!(content); }
                Err(_) => entry["reason"] = json!("Log is not valid UTF-8; no lossy or partial content is exported"),
            },
        }
        entry
    }).collect();
    json!({"state":if entries.is_empty() {"absent"} else {"observed"},
        "inventory_complete":true, "omitted":omitted, "entries":entries,
        "max_logs":MAX_LOGS, "max_bytes_per_log":MAX_BYTES,
        "source":"Retained runtime startup logs only; no conversation, configuration or credential files are collected"})
}
