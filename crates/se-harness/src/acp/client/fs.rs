//! Reading and atomically writing text files in the workspace. Operations are
//! bounded, never wait on a FIFO or device, never follow a link, and refuse
//! paths outside the workspace or inside `.git` metadata. These calls block, so
//! the client runs them off the async workers.
use super::{Outcome, RESPONSE_BYTES, Refusal};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// The largest file read, in bytes. What one reply carries is smaller still, so a
/// larger file is read in parts with `line` and `limit`.
const MAX_FILE: usize = 4 * 1024 * 1024;
/// The largest UTF-8 payload written in one `fs/write_text_file` call.
const MAX_WRITE_BYTES: usize = super::super::wire::MAX_FRAME;

/// The folder a conversation opened in, held open from then on. Every read is
/// opened beneath this one handle, every write verifies the held handle and
/// parent chain without following links, and operations refuse once the
/// folder's name no longer leads to it.
pub(super) struct Workspace {
    /// The folder as the agent was told it.
    told: PathBuf,
    /// The same folder with its links resolved.
    physical: PathBuf,
    held: se_proc::NativeSourceRoot,
    /// Serializes concurrent writes in this workspace so two calls from the
    /// same agent do not race on file creation or replacement locks.
    write_lock: Mutex<()>,
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
            write_lock: Mutex::new(()),
        })
    }

    /// Resolve an optional working directory strictly inside this held workspace,
    /// verifying that neither the workspace root nor any intermediate directory
    /// is a symlink or Windows reparse point.
    pub(super) fn resolve_dir(&self, cwd: Option<&str>) -> Result<PathBuf, Refusal> {
        self.held.check().map_err(|err| {
            Refusal::failed(format!(
                "the workspace {} could not be verified ({err}); start a new conversation there",
                self.told.display()
            ))
        })?;
        let Some(path) = cwd else {
            return Ok(self.physical.clone());
        };
        let requested = Path::new(path);
        if !requested.is_absolute() {
            return Err(Refusal::invalid(format!("{path} is not an absolute path")));
        }
        let rest = requested
            .strip_prefix(&self.told)
            .or_else(|_| requested.strip_prefix(&self.physical))
            .map_err(|_| {
                Refusal::invalid(format!(
                    "{path} is outside the workspace {}",
                    self.told.display()
                ))
            })?;
        let mut current = self.physical.clone();
        for component in rest.components() {
            match component {
                std::path::Component::Normal(name) => {
                    current.push(name);
                    let meta = std::fs::symlink_metadata(&current).map_err(|err| {
                        if err.kind() == std::io::ErrorKind::NotFound {
                            Refusal::missing(format!("{path} does not exist"))
                        } else {
                            Refusal::failed(format!("{path} could not be inspected: {err}"))
                        }
                    })?;
                    if is_link_or_reparse(&meta) {
                        return Err(Refusal::invalid(format!(
                            "{path} traverses a link or reparse point inside the workspace"
                        )));
                    }
                    if !meta.is_dir() {
                        return Err(Refusal::invalid(format!("{path} is not a directory")));
                    }
                }
                _ => {
                    return Err(Refusal::invalid(format!(
                        "{path} must name a directory by plain names inside the workspace, without `.` or `..`"
                    )));
                }
            }
        }
        Ok(current)
    }
}

fn is_link_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Verifies the held workspace directory has not been moved, removed or replaced.
fn check_workspace(workspace: &Workspace) -> Result<(), Refusal> {
    let told = workspace.told.display();
    match workspace.held.check() {
        Ok(()) => Ok(()),
        Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => Err(Refusal::failed(format!(
            "the workspace {told} was moved or removed ({gone}); start a new conversation there"
        ))),
        Err(unverified) => Err(Refusal::failed(format!(
            "the workspace {told} could not be verified ({unverified}); check its \
             permissions, or start a new conversation there if it was moved or replaced"
        ))),
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
    // A moved or replaced workspace is not a missing file, even when the lookup
    // saw "not found", so the held folder is checked before naming the cause.
    let unreadable = |error: std::io::Error| {
        if let Err(refusal) = check_workspace(workspace) {
            return refusal;
        }
        match error.kind() {
            std::io::ErrorKind::NotFound => Refusal::missing(format!("{path} does not exist")),
            _ => Refusal::failed(format!(
                "{path} could not be read from the held workspace, which follows no links: {error}"
            )),
        }
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

/// `fs/write_text_file`: bounded atomic full-file replacement beneath the held
/// workspace. Writes are serialized per session (last-writer-wins with O(1)
/// target metadata inspection, never hashing unbounded existing files), stay
/// strictly relative to `workspace.held`, and distinguish refusals before
/// publication from post-publication durability uncertainty.
pub(super) fn write(workspace: &Workspace, params: &Value, closed: &AtomicBool) -> Outcome {
    let path = text(params, "path")?;
    let content = text(params, "content")?;
    if content.len() > MAX_WRITE_BYTES {
        return Err(Refusal::invalid(format!(
            "the text for {path} is {} bytes, more than the {MAX_WRITE_BYTES} StateEngine writes",
            content.len()
        )));
    }
    let relative = beneath(&workspace.told, &workspace.physical, path)?;
    if closed.load(Ordering::Acquire) {
        return Err(Refusal::invalid(
            "this conversation is closing, so no new workspace write was started",
        ));
    }
    let _serial = workspace.write_lock.lock().map_err(|_| {
        Refusal::failed("the workspace write lock was left unusable by an earlier failure")
    })?;
    if closed.load(Ordering::Acquire) {
        return Err(Refusal::invalid(
            "this conversation is closing, so no new workspace write was started",
        ));
    }
    workspace
        .held
        .write_relative(&relative, content.as_bytes())
        .map_err(|error| map_write_error(workspace, path, error))?;
    Ok(json!({}))
}

fn map_write_error(
    workspace: &Workspace,
    path: &str,
    error: se_proc::WorkspaceWriteError,
) -> Refusal {
    match error {
        se_proc::WorkspaceWriteError::Restored(detail) => Refusal::failed(format!(
            "{path} was not updated because a conflict occurred and the prior state was restored ({detail}); re-read the file before retrying"
        )),
        se_proc::WorkspaceWriteError::PublishedUncertain(detail) => Refusal::failed(format!(
            "{path} had an unresolved write outcome ({detail}); inspect the file on disk before retrying"
        )),
        se_proc::WorkspaceWriteError::BeforePublish(refusal) => {
            if let Err(root_err) = check_workspace(workspace) {
                return root_err;
            }
            match refusal {
                se_proc::WorkspaceWriteRefusal::RootUnverified(err) => Refusal::failed(format!(
                    "the workspace {} could not be verified ({err}); no bytes were written to {path}",
                    workspace.told.display()
                )),
                se_proc::WorkspaceWriteRefusal::InvalidTarget(reason) => Refusal::invalid(format!(
                    "{path} cannot be written safely in the held workspace: {reason}"
                )),
                se_proc::WorkspaceWriteRefusal::Io(err) => Refusal::failed(format!(
                    "{path} could not be written in the held workspace before publication: {err}"
                )),
            }
        }
    }
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
