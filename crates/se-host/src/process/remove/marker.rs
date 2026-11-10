//! The product-owned marker inside the user's repository:
//! `.git/stateengine/project-<id>`, written by `se init` under the common Git
//! directory. Deletion depends on what the marker entry is, not only where it
//! sits: the exact path must resolve without following any link, its final
//! entry must be a regular file, and its content must be exactly the
//! identity record this product wrote for this project. Only then is the file
//! deleted, and the `stateengine` folder is removed only if it is empty and
//! itself a real directory. A linked repository or ancestor, a foreign file
//! at that name, or unreadable content is left untouched, and the removal
//! reports the marker as remaining with the plain reason so the
//! registration stays for a retry.
use se_types::{Result, SeError, details};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const STDOUT_BOUND: usize = 4096;
/// No identity record this product writes comes close to this; anything
/// larger at the marker path is foreign content by definition.
const MARKER_BOUND: usize = 64 * 1024;

/// Achieved marker effects, reported verbatim in the removal receipt.
#[derive(Debug)]
pub(super) enum MarkerRemoval {
    /// The marker file was deleted by this removal and the state folder,
    /// now empty, was deleted with it.
    Removed { marker: PathBuf, folder: PathBuf },
    /// The marker file was deleted; the state folder still holds other
    /// content and stays.
    RemovedMarkerKeptFolder { marker: PathBuf, folder: PathBuf },
    /// No marker existed for this project. `folder` names the state folder
    /// when one still exists with other content.
    Absent {
        marker: PathBuf,
        folder: Option<PathBuf>,
    },
    /// The entry at the exact marker path is not the identity record this
    /// product wrote for this project: a link in the path, a non-file
    /// entry, or foreign or unreadable content. The entry and its folder
    /// were left untouched; `reason` is the plain-word cause.
    Left {
        marker: PathBuf,
        reason: &'static str,
    },
}

/// Delete the project's marker when — and only when — the entry at the exact
/// path is the identity record this product wrote for this project.
///
/// Deletion is decided by identity, not location: every component of the
/// resolved marker path must be a real entry, so the open cannot follow a
/// link anywhere from the marker up to the filesystem root; the final entry
/// must be a regular file; and its bytes must be the v1 record naming this
/// project. A registered root replaced by a directory link, a linked
/// ancestor, a foreign file at the marker name, or an unreadable entry
/// leaves every byte untouched and reports the marker as left. Repository
/// discovery and common-directory resolution still mirror the init write
/// path (`se` route `git_state`/`git_identity`), so a registered subfolder
/// or linked worktree resolves to the same repository location init
/// recorded.
pub(super) fn remove(root: &Path, project_id: &str) -> Result<MarkerRemoval> {
    // Discovery exactly as init's observation performs it. No git state
    // anywhere in the tree is the same observation init used to decide that
    // no marker was recorded, so absence is definite without invoking Git.
    let state = match locate_git_state(root)? {
        Some(state) => state,
        None => {
            let marker = root
                .join(".git")
                .join("stateengine")
                .join(format!("project-{project_id}"));
            return Ok(MarkerRemoval::Absent {
                marker,
                folder: None,
            });
        }
    };
    // Resolution exactly as init's write path performs it.
    let common = common_dir(root, &state)?;
    let folder = common.join("stateengine");
    let marker = folder.join(format!("project-{project_id}"));
    match marker_identity(&marker, project_id) {
        Identity::Recorded => match fs::remove_file(&marker) {
            Ok(()) => match retire_folder(&folder)? {
                Folder::Gone => Ok(MarkerRemoval::Removed { marker, folder }),
                Folder::Kept => Ok(MarkerRemoval::RemovedMarkerKeptFolder { marker, folder }),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A concurrent change removed the entry first; read the
                // folder back before claiming anything about it.
                match retire_folder(&folder)? {
                    Folder::Gone => Ok(MarkerRemoval::Absent {
                        marker,
                        folder: None,
                    }),
                    Folder::Kept => Ok(MarkerRemoval::Absent {
                        marker,
                        folder: Some(folder),
                    }),
                }
            }
            Err(error) => Err(se_core::scope::unreadable(
                "git identity marker",
                &format!("the marker could not be deleted: {error}"),
            )),
        },
        Identity::Absent => match retire_folder(&folder)? {
            Folder::Gone => Ok(MarkerRemoval::Absent {
                marker,
                folder: None,
            }),
            Folder::Kept => Ok(MarkerRemoval::Absent {
                marker,
                folder: Some(folder),
            }),
        },
        Identity::Left(reason) => Ok(MarkerRemoval::Left { marker, reason }),
    }
}

/// The marker's identity: is the entry at the exact path the record this
/// product wrote for this project?
#[derive(Debug)]
enum Identity {
    /// A regular file, with no link anywhere in its path, holding exactly
    /// the v1 identity record for this project.
    Recorded,
    /// No entry at the exact path.
    Absent,
    /// The entry exists but is not this product's record; the carried text
    /// is the plain-word reason, kept verbatim for the receipt.
    Left(&'static str),
}

fn marker_identity(marker: &Path, project_id: &str) -> Identity {
    // The open must not be able to follow a link: check every component of
    // the resolved path, from the marker up to the filesystem root, before
    // opening anything. A linked registered root, a linked ancestor, a
    // linked .git or state folder all land here and stop.
    let mut entry = Some(marker);
    while let Some(path) = entry {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Identity::Left(if path == marker {
                    "the marker entry is a link, and removal never follows a link"
                } else {
                    "a link stands in the directory path above the marker, and removal never follows a link"
                });
            }
            Ok(meta) if path == marker && !meta.file_type().is_file() => {
                return Identity::Left("the marker entry is not a regular file");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Identity::Absent,
            Err(_) => return Identity::Left("the marker entry is unreadable"),
        }
        entry = path.parent();
    }
    // Every component is a real entry, so the open follows no link.
    let bytes = match read_bounded(marker) {
        ReadBound::Bytes(bytes) => bytes,
        ReadBound::Oversized => {
            return Identity::Left(
                "the marker file is larger than any identity record this product writes",
            );
        }
        ReadBound::Unreadable => return Identity::Left("the marker file is unreadable"),
    };
    if is_identity_record(&bytes, project_id) {
        Identity::Recorded
    } else {
        Identity::Left(
            "the marker content is not the identity record this product recorded for this project",
        )
    }
}

enum ReadBound {
    Bytes(Vec<u8>),
    Oversized,
    Unreadable,
}

fn read_bounded(marker: &Path) -> ReadBound {
    let file = match fs::File::open(marker) {
        Ok(file) => file,
        Err(_) => return ReadBound::Unreadable,
    };
    let mut bytes = Vec::new();
    match file.take(MARKER_BOUND as u64 + 1).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() > MARKER_BOUND => ReadBound::Oversized,
        Ok(_) => ReadBound::Bytes(bytes),
        Err(_) => ReadBound::Unreadable,
    }
}

/// True only for the exact record shape `se init` writes: v, project, head,
/// branch and ts — no more, no less. A hand-written or foreign file at the
/// marker name is never this product's record.
fn is_identity_record(bytes: &[u8], project_id: &str) -> bool {
    let record: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(record) => record,
        Err(_) => return false,
    };
    let fields = match record.as_object() {
        Some(fields) if fields.len() == 5 => fields,
        _ => return false,
    };
    fields.get("v").and_then(serde_json::Value::as_u64) == Some(1)
        && fields.get("project").and_then(serde_json::Value::as_str) == Some(project_id)
        && fields
            .get("head")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|head| {
                matches!(head.len(), 40 | 64) && head.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        && fields
            .get("branch")
            .is_some_and(|branch| branch.is_null() || branch.is_string())
        && fields
            .get("ts")
            .and_then(serde_json::Value::as_u64)
            .is_some()
}

enum Folder {
    Gone,
    Kept,
}

/// Remove the state folder only if it is empty and itself a real directory;
/// a link or a folder with other content stays, named in the receipt.
fn retire_folder(folder: &Path) -> Result<Folder> {
    match fs::symlink_metadata(folder) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Folder::Gone),
        Err(error) => Err(se_core::scope::unreadable(
            "git state folder",
            &format!("the state folder is unreadable: {error}"),
        )),
        Ok(meta) if !meta.file_type().is_dir() => Ok(Folder::Kept),
        Ok(_) => match fs::remove_dir(folder) {
            Ok(()) => Ok(Folder::Gone),
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(Folder::Kept),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Folder::Gone),
            Err(error) => Err(se_core::scope::unreadable(
                "git state folder",
                &format!("the empty state folder could not be removed: {error}"),
            )),
        },
    }
}
/// The init-side discovery, mirrored: the first `.git` entry (directory,
/// file or link) at the registered root or an ancestor, up to the filesystem
/// root. `None` means no repository state in the whole tree — the observation
/// init used to decide that no marker was recorded. An unreadable level is an
/// error the caller must surface, never skipped.
fn locate_git_state(root: &Path) -> Result<Option<PathBuf>> {
    let mut candidate = Some(root);
    while let Some(path) = candidate {
        match fs::symlink_metadata(path.join(".git")) {
            Ok(_) => return Ok(Some(path.join(".git"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(se_core::scope::unreadable(
                    "git identity marker",
                    &format!(
                        "the repository tree is unreadable at {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
        candidate = path.parent();
    }
    Ok(None)
}
fn refusal(subject: &str, reason: &str, next_step: &str) -> SeError {
    SeError::new(se_types::Detail::RepoInvalid(details::RepoInvalid {
        subject: subject.into(),
        reason: reason.into(),
        next_step: next_step.into(),
    }))
}
/// The common Git directory, resolved exactly the way the init write path
/// resolves it, so removal finds the file it wrote: bounded output, no shell,
/// no hooks, no network, and the Git environment the caller inherited is
/// stripped so a surrounding repository cannot redirect the lookup. Discovery
/// already proved git state exists in the tree, so a Git that now cannot
/// resolve the repository is a refusal, not a guessed absence.
fn common_dir(root: &Path, state: &Path) -> Result<PathBuf> {
    let output = match run(root, &["rev-parse", "--git-common-dir"]) {
        Spawn::Output(output) => output,
        Spawn::Missing => {
            return Err(SeError::new(se_types::Detail::RepoInvalid(
                details::RepoInvalid {
                    subject: "git identity marker".into(),
                    reason: "Git is not installed on this machine".into(),
                    next_step:
                        "Install Git (https://git-scm.com) and retry the removal so the marker can be checked and deleted.".into(),
                },
            )))
        }
        Spawn::Unreadable(error) => return Err(error),
    };
    if !output.status.success() {
        if output.status.code() == Some(128) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: String = stderr.chars().take(160).collect();
            return Err(refusal(
                "git identity marker",
                &format!(
                    "git state exists at {} but Git cannot resolve the repository from {}: {tail}",
                    state.display(),
                    root.display()
                ),
                "Restore the repository's .git state (or use se project move if the folder moved) and retry the removal.",
            ));
        }
        return Err(unreadable(root, &output));
    }
    let value = text(&output)?;
    let joined = PathBuf::from(&value);
    let joined = if joined.is_absolute() {
        joined
    } else {
        root.join(joined)
    };
    Ok(normalize_lexical(&joined))
}
/// Lexical normalization of `.` and `..` components without touching the
/// filesystem: Git reports the common directory relative to the registered
/// root (for example `../.git` from a registered subfolder), and the
/// registered root is already canonical from init, so no intermediate
/// component is a link and the cleaned path names the same location.
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                cleaned.push(component.as_os_str())
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                // Clamp at the filesystem root, where pop is a no-op.
                let _ = cleaned.pop();
            }
            std::path::Component::Normal(name) => cleaned.push(name),
        }
    }
    cleaned
}
/// One bounded Git invocation. `Missing` keeps a spawn that found no Git
/// binary distinct from a command that ran and failed: absent is a different
/// fact from unreadable, and each caller reports it as such.
enum Spawn {
    Output(Output),
    Missing,
    Unreadable(SeError),
}
fn run(root: &Path, args: &[&str]) -> Spawn {
    match Command::new("git")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
    {
        Ok(output) => Spawn::Output(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Spawn::Missing,
        Err(error) => Spawn::Unreadable(se_core::scope::unreadable(
            "git identity marker",
            &format!("Git could not be started: {error}"),
        )),
    }
}
fn text(output: &Output) -> Result<String> {
    if output.stdout.len() > STDOUT_BOUND {
        return Err(SeError::too_large(
            "Git metadata",
            STDOUT_BOUND,
            output.stdout.len(),
        ));
    }
    std::str::from_utf8(&output.stdout)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| se_core::scope::unreadable("Git metadata", "Git returned non-UTF-8 metadata"))
}
fn unreadable(root: &Path, output: &Output) -> SeError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: String = stderr.chars().take(160).collect();
    se_core::scope::unreadable(
        "git identity marker",
        &format!(
            "git failed for {} with exit {:?}: {tail}",
            root.display(),
            output.status.code()
        ),
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures: a failed setup is a test bug, not a product path"
    )]
    use super::*;

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(["-c", "user.email=t@e.st", "-c", "user.name=t"])
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .expect("git spawn");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn fixture(tag: &str, repo: bool) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("se-marker-remove-{stamp}-{tag}"));
        fs::create_dir_all(&dir).expect("fixture dir");
        if repo {
            git(&dir, &["init", "-b", "main"]);
            fs::write(dir.join("note.txt"), "user bytes").expect("user file");
            git(&dir, &["add", "note.txt"]);
            git(&dir, &["commit", "-m", "note"]);
        }
        dir
    }
    fn marker_path(dir: &Path, project_id: &str) -> PathBuf {
        let common = dir.join(".git");
        common
            .join("stateengine")
            .join(format!("project-{project_id}"))
    }
    /// Seed the exact record shape `se init` writes, so the identity check
    /// accepts it.
    fn seed(dir: &Path, project_id: &str, extra: Option<&str>) -> PathBuf {
        let marker = marker_path(dir, project_id);
        fs::create_dir_all(marker.parent().expect("marker parent")).expect("state folder");
        let record = serde_json::json!({
            "v": 1,
            "project": project_id,
            "head": "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0",
            "branch": "main",
            "ts": 1,
        });
        fs::write(&marker, serde_json::to_vec(&record).expect("record")).expect("marker");
        if let Some(name) = extra {
            fs::write(marker.parent().expect("state folder").join(name), b"other")
                .expect("extra state");
        }
        marker
    }
    fn outside_of(dir: &Path) -> PathBuf {
        let outside = dir.with_file_name(format!(
            "{}-outside",
            dir.file_name().expect("name").to_string_lossy()
        ));
        fs::create_dir_all(&outside).expect("outside dir");
        outside
    }
    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target).expect("copy dir");
        for entry in fs::read_dir(source).expect("read dir").flatten() {
            let from = entry.path();
            let to = target.join(entry.file_name());
            if from.is_dir() && !from.is_symlink() {
                copy_tree(&from, &to);
            } else {
                fs::copy(&from, &to).expect("copy file");
            }
        }
    }
    fn read_tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        fn walk(dir: &Path, root: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).expect("read dir").flatten() {
                let path = entry.path();
                let relative = path.strip_prefix(root).expect("relative");
                if path.is_symlink() {
                    out.insert(relative.to_path_buf(), Vec::new());
                } else if path.is_dir() {
                    walk(&path, root, out);
                } else {
                    out.insert(relative.to_path_buf(), fs::read(&path).expect("bytes"));
                }
            }
        }
        walk(root, root, &mut out);
        out
    }
    /// The registered root replaced by a directory link to a copied tree;
    /// `foreign` replaces the copy's marker bytes when `Some`. Returns the
    /// registered root (now the link) and its outside parent.
    #[cfg(unix)]
    fn linked_ancestor_fixture(project_id: &str, foreign: Option<&[u8]>) -> (PathBuf, PathBuf) {
        let dir = fixture(&format!("ancestor-{project_id}"), true);
        seed(&dir, project_id, None);
        let outside = outside_of(&dir);
        let original = outside.join("original-repository");
        let target = outside.join("foreign-repository");
        fs::rename(&dir, &original).expect("retain the original repository");
        copy_tree(&original, &target);
        if let Some(bytes) = foreign {
            let marker = target
                .join(".git")
                .join("stateengine")
                .join(format!("project-{project_id}"));
            fs::write(&marker, bytes).expect("foreign marker");
        }
        std::os::unix::fs::symlink(&target, &dir).expect("registered root link");
        (dir, outside)
    }
    #[test]
    fn marker_and_empty_folder_are_removed() {
        let dir = fixture("removed", true);
        let marker = seed(&dir, "pid-a", None);
        let outcome = remove(&dir, "pid-a").expect("marker removal");
        let MarkerRemoval::Removed {
            marker: gone,
            folder,
        } = outcome
        else {
            panic!("expected marker and folder removed, got {outcome:?}");
        };
        assert_eq!(gone, marker);
        assert!(!gone.exists());
        assert!(!folder.exists());
        assert_eq!(
            fs::read(dir.join("note.txt")).expect("user file"),
            b"user bytes"
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn marker_removed_keeps_folder_with_other_content() {
        let dir = fixture("kept-folder", true);
        let marker = seed(&dir, "pid-b", Some("other-state.bin"));
        let outcome = remove(&dir, "pid-b").expect("marker removal");
        let MarkerRemoval::RemovedMarkerKeptFolder {
            marker: gone,
            folder,
        } = outcome
        else {
            panic!("expected folder kept, got {outcome:?}");
        };
        assert!(!gone.exists());
        assert!(folder.exists());
        let extra = marker
            .parent()
            .expect("state folder")
            .join("other-state.bin");
        assert_eq!(fs::read(extra).expect("other state"), b"other");
        assert_eq!(
            fs::read(dir.join("note.txt")).expect("user file"),
            b"user bytes"
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn absent_marker_is_reported_without_deleting_anything() {
        let dir = fixture("absent", true);
        let outcome = remove(&dir, "pid-c").expect("marker removal");
        let MarkerRemoval::Absent { marker, folder } = outcome else {
            panic!("expected absence, got {outcome:?}");
        };
        assert!(!marker.exists());
        assert!(folder.is_none());
        assert!(!dir.join(".git/stateengine").exists());
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn empty_leftover_state_folder_is_cleared() {
        let dir = fixture("leftover", true);
        fs::create_dir_all(dir.join(".git/stateengine")).expect("empty state folder");
        let outcome = remove(&dir, "pid-d").expect("marker removal");
        let MarkerRemoval::Absent {
            marker: gone,
            folder,
        } = outcome
        else {
            panic!("expected absence, got {outcome:?}");
        };
        assert!(!gone.exists());
        assert!(folder.is_none());
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn plain_folder_is_definitely_absent_without_git() {
        let dir = fixture("plain", false);
        let outcome = remove(&dir, "pid-e").expect("marker removal");
        let MarkerRemoval::Absent { marker, folder } = outcome else {
            panic!("expected absence, got {outcome:?}");
        };
        assert_eq!(marker, dir.join(".git/stateengine/project-pid-e"));
        assert!(folder.is_none());
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn unresolvable_git_state_refuses_instead_of_guessing() {
        let dir = fixture("broken", false);
        fs::create_dir_all(dir.join(".git")).expect("empty .git");
        let outcome = remove(&dir, "pid-f");
        assert!(outcome.is_err(), "broken .git must refuse, got {outcome:?}");
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn registered_subfolder_finds_the_real_marker() {
        let dir = fixture("subfolder", true);
        let marker = seed(&dir, "pid-g", None);
        fs::create_dir_all(dir.join("sub")).expect("subfolder");
        let outcome = remove(&dir.join("sub"), "pid-g").expect("marker removal");
        let MarkerRemoval::Removed {
            marker: gone,
            folder,
        } = outcome
        else {
            panic!("expected the real marker removed, got {outcome:?}");
        };
        assert_eq!(gone, marker);
        assert!(!gone.exists());
        assert!(!folder.exists());
        assert_eq!(
            fs::read(dir.join("note.txt")).expect("user file"),
            b"user bytes"
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn linked_worktree_finds_the_real_marker() {
        let dir = fixture("worktree", true);
        let marker = seed(&dir, "pid-h", None);
        let wt = dir.join("wt");
        git(
            &dir,
            &[
                "worktree",
                "add",
                "-q",
                wt.to_str().expect("utf8 wt"),
                "-b",
                "side",
            ],
        );
        let outcome = remove(&wt, "pid-h").expect("marker removal");
        let MarkerRemoval::Removed {
            marker: gone,
            folder,
        } = outcome
        else {
            panic!("expected the real marker removed, got {outcome:?}");
        };
        assert_eq!(gone, marker);
        assert!(!gone.exists());
        assert!(!folder.exists());
        git(
            &dir,
            &[
                "worktree",
                "remove",
                "--force",
                wt.to_str().expect("utf8 wt"),
            ],
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn directory_at_marker_path_is_left_untouched() {
        let dir = fixture("dir-marker", true);
        let marker = seed(&dir, "pid-m", None);
        fs::remove_file(&marker).expect("clear marker slot");
        fs::create_dir_all(&marker).expect("directory at marker path");
        fs::write(marker.join("user.bin"), b"do not recurse").expect("user file");
        let outcome = remove(&dir, "pid-m").expect("marker removal");
        let MarkerRemoval::Left { reason, .. } = outcome else {
            panic!("expected the directory left untouched, got {outcome:?}");
        };
        assert_eq!(reason, "the marker entry is not a regular file");
        assert_eq!(
            fs::read(marker.join("user.bin")).expect("user file"),
            b"do not recurse"
        );
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn foreign_content_at_marker_path_is_left_untouched() {
        let dir = fixture("foreign", true);
        let marker = seed(&dir, "pid-n", None);
        let foreign = b"never the recorded identity";
        fs::write(&marker, foreign).expect("replace content");
        let outcome = remove(&dir, "pid-n").expect("marker removal");
        let MarkerRemoval::Left { reason, .. } = outcome else {
            panic!("expected the foreign file left untouched, got {outcome:?}");
        };
        assert_eq!(
            reason,
            "the marker content is not the identity record this product recorded for this project"
        );
        assert_eq!(fs::read(&marker).expect("marker bytes"), foreign);
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
    fn oversized_file_at_marker_path_is_left_untouched() {
        let dir = fixture("oversized", true);
        let marker = seed(&dir, "pid-o", None);
        let big = vec![0u8; MARKER_BOUND + 1];
        fs::write(&marker, &big).expect("oversized file");
        let outcome = remove(&dir, "pid-o").expect("marker removal");
        let MarkerRemoval::Left { reason, .. } = outcome else {
            panic!("expected the oversized file left untouched, got {outcome:?}");
        };
        assert_eq!(
            reason,
            "the marker file is larger than any identity record this product writes"
        );
        assert_eq!(fs::read(&marker).expect("oversized file"), big);
        let _ = fs::remove_dir_all(&dir);
    }
    #[cfg(unix)]
    #[test]
    fn marker_link_is_left_untouched() {
        let dir = fixture("marker-link", true);
        let marker = seed(&dir, "pid-k", None);
        let outside = outside_of(&dir);
        let target = outside.join("victim.json");
        fs::write(&target, b"{\"keep\":1}").expect("victim");
        fs::remove_file(&marker).expect("clear marker slot");
        std::os::unix::fs::symlink(&target, &marker).expect("marker link");
        let outcome = remove(&dir, "pid-k").expect("marker removal");
        let MarkerRemoval::Left {
            marker: left,
            reason,
        } = outcome
        else {
            panic!("expected the link left untouched, got {outcome:?}");
        };
        assert_eq!(left, marker);
        assert_eq!(
            reason,
            "the marker entry is a link, and removal never follows a link"
        );
        assert!(left.is_symlink(), "the link itself must stay");
        assert!(
            dir.join(".git/stateengine").is_dir(),
            "the state folder must stay"
        );
        assert_eq!(fs::read(&target).expect("victim"), b"{\"keep\":1}");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_state_folder_is_left_untouched() {
        let dir = fixture("state-link", true);
        let marker = seed(&dir, "pid-i", None);
        let outside = outside_of(&dir);
        let moved = outside.join("stateengine");
        fs::rename(marker.parent().expect("state folder"), &moved).expect("move state out");
        std::os::unix::fs::symlink(&moved, dir.join(".git/stateengine")).expect("state link");
        let before = fs::read(&marker).expect("external marker");
        let outcome = remove(&dir, "pid-i").expect("marker removal");
        let MarkerRemoval::Left {
            marker: left,
            reason,
        } = outcome
        else {
            panic!("expected the linked folder left untouched, got {outcome:?}");
        };
        assert_eq!(left, marker);
        assert_eq!(
            reason,
            "a link stands in the directory path above the marker, and removal never follows a link"
        );
        assert!(dir.join(".git/stateengine").is_symlink());
        assert_eq!(
            fs::read(&marker).expect("external marker"),
            before,
            "the external target must be preserved byte for byte"
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_git_dir_is_left_untouched() {
        let dir = fixture("git-link", true);
        let marker = seed(&dir, "pid-j", None);
        let outside = outside_of(&dir);
        fs::rename(dir.join(".git"), outside.join("gitdir")).expect("move .git out");
        std::os::unix::fs::symlink(outside.join("gitdir"), dir.join(".git")).expect(".git link");
        let before = fs::read(&marker).expect("external marker");
        let outcome = remove(&dir, "pid-j").expect("marker removal");
        let MarkerRemoval::Left { reason, .. } = outcome else {
            panic!("expected the linked .git left untouched, got {outcome:?}");
        };
        assert_eq!(
            reason,
            "a link stands in the directory path above the marker, and removal never follows a link"
        );
        assert_eq!(
            fs::read(&marker).expect("external marker"),
            before,
            "the external marker must be preserved byte for byte"
        );
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }
    #[cfg(unix)]
    #[test]
    fn linked_ancestor_with_foreign_marker_is_left_untouched() {
        let (dir, outside) = linked_ancestor_fixture(
            "pid-l",
            Some(b"foreign user bytes; never the recorded identity"),
        );
        let target = outside.join("foreign-repository");
        let marker = dir.join(".git").join("stateengine").join("project-pid-l");
        let target_before = read_tree(&target);
        let original_before = read_tree(&outside.join("original-repository"));
        let outcome = remove(&dir, "pid-l").expect("marker removal");
        let MarkerRemoval::Left {
            marker: left,
            reason,
        } = outcome
        else {
            panic!("expected the linked ancestor left untouched, got {outcome:?}");
        };
        assert_eq!(left, marker);
        assert_eq!(
            reason,
            "a link stands in the directory path above the marker, and removal never follows a link"
        );
        assert!(dir.is_symlink(), "the registered root link must stay");
        assert_eq!(
            read_tree(&target),
            target_before,
            "the external tree must stay byte for byte"
        );
        assert_eq!(
            read_tree(&outside.join("original-repository")),
            original_before,
            "the retained original must stay byte for byte"
        );
        let _ = fs::remove_file(&dir);
        let _ = fs::remove_dir_all(&outside);
    }
    #[cfg(unix)]
    #[test]
    fn linked_ancestor_with_recorded_identity_is_left_untouched() {
        let (dir, outside) = linked_ancestor_fixture("pid-p", None);
        let target = outside.join("foreign-repository");
        let foreign_marker = target
            .join(".git")
            .join("stateengine")
            .join("project-pid-p");
        assert!(
            foreign_marker.exists(),
            "the copy carries the recorded identity"
        );
        let target_before = read_tree(&target);
        let outcome = remove(&dir, "pid-p").expect("marker removal");
        let MarkerRemoval::Left { reason, .. } = outcome else {
            panic!("a link in the path must win over matching content, got {outcome:?}");
        };
        assert_eq!(
            reason,
            "a link stands in the directory path above the marker, and removal never follows a link"
        );
        assert_eq!(
            read_tree(&target),
            target_before,
            "the external tree must stay byte for byte"
        );
        let _ = fs::remove_file(&dir);
        let _ = fs::remove_dir_all(&outside);
    }
}
