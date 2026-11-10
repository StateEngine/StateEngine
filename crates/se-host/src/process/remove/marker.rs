//! Retire only the project's recognized Git marker; uncertain paths are kept.
use se_core::ops::project_remove::{KeptItem, RemovedItem};
use se_proc::{DirectoryRemoval, OwnedFile, remove_empty_directory};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

const MARKER_BOUND: usize = 64 * 1024;

#[derive(Default)]
pub(super) struct Cleanup {
    pub removed: Vec<RemovedItem>,
    pub kept: Vec<KeptItem>,
}

impl Cleanup {
    fn keep(&mut self, path: &Path, what: &str, reason: impl Into<String>) {
        self.kept.push(KeptItem {
            what: what.into(),
            path: Some(path.display().to_string()),
            note: reason.into(),
        });
    }
    fn removed(&mut self, path: &Path, what: &str) {
        self.removed.push(RemovedItem {
            what: what.into(),
            path: Some(path.display().to_string()),
        });
    }
}

pub(super) fn remove(root: &Path, project: &str) -> Cleanup {
    let mut result = Cleanup::default();
    let fallback = root
        .join(".git/stateengine")
        .join(format!("project-{project}"));
    let folder = match marker_folder(root) {
        Ok(Some(folder)) => folder,
        Ok(None) => return result,
        Err(reason) => {
            result.keep(&fallback, "git identity marker", reason);
            return result;
        }
    };
    let marker = folder.join(format!("project-{project}"));
    match retire_marker(&marker, project) {
        Ok(true) => result.removed(&marker, "git identity marker"),
        Ok(false) => {
            result.keep(
                &folder,
                "git identity folder",
                "The marker is absent; the state folder was left untouched.",
            );
            return result;
        }
        Err(reason) => {
            // In particular, absence never authorizes removing the parent.
            result.keep(&marker, "git identity marker", reason);
            return result;
        }
    }
    // Recheck the entire path after the file effect. Never recurse into a
    // nonempty folder, and never turn an intentional keep into removal debt.
    match checked_path(&folder, true).and_then(|folder| {
        remove_empty_directory(&folder).map_err(|error| format!("State folder kept: {error}"))
    }) {
        Ok(DirectoryRemoval::Removed) => result.removed(&folder, "git identity folder"),
        Ok(DirectoryRemoval::NotEmpty) => result.keep(
            &folder,
            "git identity folder",
            "The state folder contains other entries and was left untouched.",
        ),
        Ok(DirectoryRemoval::AlreadyAbsent) => result.keep(
            &folder,
            "git identity folder",
            "The state folder was already absent; no directory was removed.",
        ),
        Err(reason) => result.keep(&folder, "git identity folder", reason),
    }
    result
}

fn retire_marker(marker: &Path, project: &str) -> Result<bool, String> {
    let Some(mut file) =
        OwnedFile::open(marker).map_err(|error| format!("Marker kept: {error}"))?
    else {
        return Ok(false);
    };
    let bytes = file
        .read(MARKER_BOUND)
        .map_err(|error| format!("Marker kept: {error}"))?;
    if !recognized(&bytes, project) {
        return Err(
            "The file is not this project's Git identity marker; it was left untouched.".into(),
        );
    }
    checked_path(&marker, false)?;
    file.remove(Sha256::digest(&bytes).into())
        .map_err(|error| format!("Marker removal could not be witnessed: {error}"))?;
    Ok(true)
}

// Match the complete record emitted by init, rather than just its filename or
// project field. The recorded HEAD may predate subsequent user commits.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    v: u8,
    project: String,
    head: String,
    branch: serde_json::Value,
    #[serde(rename = "ts")]
    _ts: u64,
}

fn recognized(bytes: &[u8], project: &str) -> bool {
    let Ok(marker) = serde_json::from_slice::<Marker>(bytes) else {
        return false;
    };
    marker.v == 1
        && marker.project == project
        && matches!(marker.head.len(), 40 | 64)
        && marker.head.bytes().all(|byte| byte.is_ascii_hexdigit())
        && (marker.branch.is_null() || marker.branch.is_string())
}

fn marker_folder(root: &Path) -> Result<Option<PathBuf>, String> {
    let root = checked_path(root, true)?;
    for ancestor in root.ancestors() {
        let state = ancestor.join(".git");
        let metadata = match fs::symlink_metadata(&state) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Git state could not be checked: {error}")),
        };
        // Read Git's original pointers before resolving them: Git itself may
        // canonicalize through a replaced ancestor and hide the link from us.
        let git_dir = if metadata.is_dir() {
            checked_path(&state, true)?
        } else {
            let text = pointer(&state)?;
            let target = text
                .strip_prefix("gitdir: ")
                .filter(|target| !target.is_empty())
                .ok_or_else(|| "The Git directory pointer is not recognized.".to_owned())?;
            checked_path(&ancestor.join(target), true)?
        };
        let common = git_dir.join("commondir");
        let common = match fs::symlink_metadata(&common) {
            Ok(_) => checked_path(&git_dir.join(pointer(&common)?), true)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => git_dir,
            Err(error) => {
                return Err(format!(
                    "Git common-directory pointer is unreadable: {error}"
                ));
            }
        };
        return Ok(Some(common.join("stateengine")));
    }
    Ok(None)
}

fn pointer(path: &Path) -> Result<String, String> {
    checked_path(path, false)?;
    let mut file = OwnedFile::open(path)
        .map_err(|error| format!("Git directory pointer kept: {error}"))?
        .ok_or_else(|| {
            "The Git directory pointer disappeared; no marker was removed.".to_owned()
        })?;
    let bytes = file
        .read(4096)
        .map_err(|error| format!("Git directory pointer is unreadable: {error}"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "Git directory pointer is not readable text.".to_owned())?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty() || text.contains(['\n', '\r']) {
        return Err("Git directory pointer does not contain one path.".into());
    }
    Ok(text.into())
}

fn checked_path(path: &Path, directory: bool) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("Marker path is not absolute; repository state was left untouched.".into());
    }
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(_) => {
                current.push(component.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                current.pop();
            }
            _ => current.push(component.as_os_str()),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "Path kept because {} could not be checked: {error}",
                current.display()
            )
        })?;
        if linked(&metadata) {
            return Err(format!(
                "Path kept because {} is a link; removal does not follow links.",
                current.display()
            ));
        }
        let expect_directory = directory || index + 1 < components.len();
        if (expect_directory && !metadata.is_dir()) || (!expect_directory && !metadata.is_file()) {
            return Err(format!(
                "Path kept because {} is not a regular {}.",
                current.display(),
                if expect_directory {
                    "directory"
                } else {
                    "file"
                }
            ));
        }
    }
    Ok(current)
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
