//! Reading text files in the workspace. Reads are bounded, never wait on a FIFO
//! or device, never follow a link, and a reply never outgrows one protocol
//! message. These calls block, so the client runs them off the async workers.
use super::{Outcome, RESPONSE_BYTES, Refusal};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

/// The largest file read, in bytes. What one reply carries is smaller still, so a
/// larger file is read in parts with `line` and `limit`.
const MAX_FILE: usize = 4 * 1024 * 1024;

/// The folder a conversation opened in, held open from then on. Every read is
/// opened beneath this one handle, and a read refuses once the folder's name no
/// longer leads to it.
pub(super) struct Workspace {
    /// The folder as the agent was told it.
    told: PathBuf,
    /// The same folder with its links resolved.
    physical: PathBuf,
    held: se_proc::NativeSourceRoot,
}

impl Workspace {
    pub(super) fn open(told: PathBuf) -> Result<Self, String> {
        let physical = se_proc::canonicalize_path(&told).map_err(|error| {
            format!(
                "the workspace {} could not be resolved: {error}",
                told.display()
            )
        })?;
        let held = se_proc::NativeSourceRoot::open(&physical).map_err(|error| {
            format!(
                "the workspace {} could not be opened: {error}",
                told.display()
            )
        })?;
        Ok(Self {
            told,
            physical,
            held,
        })
    }
}

/// `fs/read_text_file`: the whole file, or `limit` lines from 1-based `line`. The
/// file is opened beneath the held workspace without following any link, and the
/// bytes come from that same open file.
pub(super) fn read(workspace: &Workspace, params: &Value) -> Outcome {
    let path = text(params, "path")?;
    let relative = beneath(&workspace.told, &workspace.physical, path)?;
    let line = count(params, "line")?;
    let limit = count(params, "limit")?;
    let held = &workspace.held;
    let unreadable = |error: std::io::Error| match error.kind() {
        std::io::ErrorKind::NotFound => Refusal::missing(format!("{path} does not exist")),
        _ => Refusal::failed(format!(
            "{path} could not be read from the held workspace, which follows no links: {error}"
        )),
    };
    let mut file = held
        .open_relative(&relative)
        .map_err(unreadable)?
        .ok_or_else(|| Refusal::missing(format!("{path} does not exist")))?;
    let opened = file.opened_revision();
    if opened.size > MAX_FILE as u64 {
        return Err(Refusal::invalid(format!(
            "{path} is larger than {MAX_FILE} bytes, the most StateEngine reads"
        )));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > MAX_FILE
        || file.revision().map_err(unreadable)? != opened
        || !file.validate_name().map_err(unreadable)?
    {
        return Err(Refusal::failed(format!(
            "{path} changed while it was being read; read it again"
        )));
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| Refusal::invalid(format!("{path} is not UTF-8 text")))?;
    let selected = if line.is_none() && limit.is_none() {
        content
    } else {
        content
            .split_inclusive('\n')
            .skip(line.map_or(0, |line| line.saturating_sub(1)))
            .take(limit.unwrap_or(usize::MAX))
            .collect()
    };
    let encoded = serde_json::to_string(&selected)
        .map_err(|_| Refusal::failed(format!("{path} could not be encoded")))?
        .len();
    if encoded > RESPONSE_BYTES {
        return Err(Refusal::invalid(format!(
            "the requested text of {path} is {encoded} bytes once encoded, more than the \
             {RESPONSE_BYTES} one reply carries; read it in parts with `line` and `limit`"
        )));
    }
    Ok(json!({ "content": selected }))
}

/// The slash-separated path of `path` beneath the workspace, given as the agent
/// was told it or with its links resolved. `..` and other non-name parts are refused.
fn beneath(workspace: &Path, root: &Path, path: &str) -> Result<String, Refusal> {
    let requested = Path::new(path);
    if !requested.is_absolute() {
        return Err(Refusal::invalid(format!("{path} is not an absolute path")));
    }
    let rest = requested
        .strip_prefix(workspace)
        .or_else(|_| requested.strip_prefix(root))
        .map_err(|_| {
            Refusal::invalid(format!(
                "{path} is outside the workspace {}",
                workspace.display()
            ))
        })?;
    let mut parts = Vec::new();
    for component in rest.components() {
        match component {
            std::path::Component::Normal(name) => parts.push(
                name.to_str()
                    .ok_or_else(|| Refusal::invalid(format!("{path} is not valid text")))?,
            ),
            _ => {
                return Err(Refusal::invalid(format!(
                    "{path} must name a file by plain names inside the workspace, without `.` or `..`"
                )));
            }
        }
    }
    if parts.is_empty() {
        return Err(Refusal::invalid(format!("{path} does not name a file")));
    }
    Ok(parts.join("/"))
}

/// An optional positive count parameter.
fn count(params: &Value, name: &str) -> Result<Option<usize>, Refusal> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|value| *value > 0)
            .and_then(|value| usize::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| Refusal::invalid(format!("`{name}` must be a positive whole number"))),
    }
}

/// A required string parameter.
fn text<'a>(params: &'a Value, name: &str) -> Result<&'a str, Refusal> {
    params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::invalid(format!("`{name}` must be a string")))
}
