//! The product-owned marker inside the user's repository:
//! `.git/stateengine/project-<id>`, written by `se init` under the common Git
//! directory. Removal deletes that exact file, then the `stateengine` folder
//! only if it is empty; every other byte of the repository is untouched.
use se_types::{Result, SeError, details};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const STDOUT_BOUND: usize = 4096;

/// Achieved marker effects, reported verbatim in the removal receipt.
#[derive(Debug)]
pub(super) enum MarkerRemoval {
    /// The marker file was deleted and the state folder, now empty, was
    /// deleted with it, or a concurrent change removed it first and the
    /// readback proved the folder gone either way.
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
}

/// Delete the project's marker with exact-path deletes only. Absent,
/// unreadable and failed are kept distinct: a marker that provably does not
/// exist is reported as absent, while any state that cannot be resolved is an
/// error the caller must surface, never a silent skip.
pub(super) fn remove(root: &Path, project_id: &str) -> Result<MarkerRemoval> {
    let git_state = root.join(".git");
    let common = match fs::symlink_metadata(&git_state) {
        Ok(_) => common_dir(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // No `.git` file or directory at this root: the init write path
            // could never have placed a marker here, so absence is definite
            // without invoking Git.
            let marker = git_state
                .join("stateengine")
                .join(format!("project-{project_id}"));
            return Ok(MarkerRemoval::Absent {
                marker,
                folder: None,
            });
        }
        Err(error) => {
            return Err(se_core::scope::unreadable(
                "git identity marker",
                &format!("the repository's .git state is unreadable: {error}"),
            ));
        }
    };
    let folder = common.join("stateengine");
    let marker = folder.join(format!("project-{project_id}"));
    match fs::remove_file(&marker) {
        Ok(()) => match fs::remove_dir(&folder) {
            Ok(()) => Ok(MarkerRemoval::Removed { marker, folder }),
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                Ok(MarkerRemoval::RemovedMarkerKeptFolder { marker, folder })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::symlink_metadata(&folder) {
                    // The folder vanished between the two deletes; read it back
                    // before claiming it removed.
                    Err(absent) if absent.kind() == std::io::ErrorKind::NotFound => {
                        Ok(MarkerRemoval::Removed { marker, folder })
                    }
                    _ => Err(se_core::scope::unreadable(
                        "git state folder",
                        "the folder could not be read back after the marker delete; re-run the removal",
                    )),
                }
            }
            Err(error) => Err(se_core::scope::unreadable(
                "git state folder",
                &error.to_string(),
            )),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // No marker to delete. An empty state folder left by an earlier
            // failed marker write is cleared by the same rule; a folder with
            // other content stays and is named.
            match fs::remove_dir(&folder) {
                Ok(()) => Ok(MarkerRemoval::Absent {
                    marker,
                    folder: None,
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(MarkerRemoval::Absent {
                        marker,
                        folder: None,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                    Ok(MarkerRemoval::Absent {
                        marker,
                        folder: Some(folder),
                    })
                }
                Err(error) => Err(se_core::scope::unreadable(
                    "git state folder",
                    &error.to_string(),
                )),
            }
        }
        Err(error) => Err(se_core::scope::unreadable(
            "git identity marker",
            &error.to_string(),
        )),
    }
}
/// The common Git directory, resolved exactly the way the init write path
/// resolves it, so removal finds the file it wrote: bounded output, no shell,
/// no hooks, no network, and the Git environment the caller inherited is
/// stripped so a surrounding repository cannot redirect the lookup.
fn common_dir(root: &Path) -> Result<PathBuf> {
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
        return Err(unreadable(root, &output));
    }
    let value = text(&output)?;
    let path = PathBuf::from(&value);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
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
        let dir = std::env::temp_dir().join(format!("5e-marker-remove-{stamp}-{tag}"));
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
    fn seed(dir: &Path, project_id: &str, extra: Option<&str>) -> PathBuf {
        let marker = marker_path(dir, project_id);
        fs::create_dir_all(marker.parent().expect("marker parent")).expect("state folder");
        fs::write(&marker, b"{\"v\":1}").expect("marker");
        if let Some(name) = extra {
            fs::write(marker.parent().expect("state folder").join(name), b"other")
                .expect("extra state");
        }
        marker
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
}
