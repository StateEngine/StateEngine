//! Safe linked Git worktree removal with a non-following link/junction guard.
//!
//! Before deleting anything, this module proves the target is a real linked Git
//! worktree (never a primary repository root or unrelated directory), walks the
//! entire tree with `symlink_metadata` to refuse any symbolic link, Windows
//! directory junction / reparse point, or unreadable entry (even under
//! `--force`), optionally enforces working-tree cleanliness, deletes files and
//! directories bottom-up without following links, and prunes the worktree's
//! administrative metadata from the common Git directory.
use git2::{
    Repository, RepositoryOpenFlags, StatusOptions, WorktreeLockStatus, WorktreePruneOptions,
};
use std::{
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Maximum offending paths retained per category in a refusal report.
const MAX_REPORTED_PATHS: usize = 64;
/// Maximum dirty/untracked sample paths included in a dirty-worktree refusal.
const MAX_DIRTY_SAMPLE: usize = 10;

/// Witnessed result of a completed safe worktree removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeRemoveReport {
    pub path: PathBuf,
    pub worktree_name: String,
    pub common_dir: PathBuf,
    pub forced: bool,
    pub pruned: bool,
}

/// Typed refusal or failure from [`remove_worktree`].
/// Absent, unreadable, link-guarded, and dirty states are never collapsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorktreeRemoveError {
    Absent {
        path: PathBuf,
    },
    Unreadable {
        entries: Vec<(PathBuf, String)>,
        total: usize,
    },
    LinksDetected {
        links: Vec<(PathBuf, String)>,
        total_links: usize,
        unreadable: Vec<(PathBuf, String)>,
        total_unreadable: usize,
    },
    NotLinkedWorktree {
        path: PathBuf,
        reason: String,
    },
    Locked {
        path: PathBuf,
        reason: Option<String>,
    },
    Dirty {
        path: PathBuf,
        count: usize,
        sample: Vec<String>,
    },
    DeleteFailed {
        path: PathBuf,
        reason: String,
    },
    PruneFailed {
        worktree_name: String,
        reason: String,
    },
}

struct WalkFindings {
    links: Vec<(PathBuf, String)>,
    total_links: usize,
    unreadable: Vec<(PathBuf, String)>,
    total_unreadable: usize,
}

impl WalkFindings {
    fn new() -> Self {
        Self {
            links: Vec::new(),
            total_links: 0,
            unreadable: Vec::new(),
            total_unreadable: 0,
        }
    }

    fn record_link(&mut self, path: PathBuf, kind: String) {
        self.total_links += 1;
        if self.links.len() < MAX_REPORTED_PATHS {
            self.links.push((path, kind));
        }
    }

    fn record_unreadable(&mut self, path: PathBuf, reason: String) {
        self.total_unreadable += 1;
        if self.unreadable.len() < MAX_REPORTED_PATHS {
            self.unreadable.push((path, reason));
        }
    }

    fn into_result(mut self) -> Result<(), WorktreeRemoveError> {
        self.links.sort_by(|a, b| a.0.cmp(&b.0));
        self.unreadable.sort_by(|a, b| a.0.cmp(&b.0));
        if self.total_links > 0 {
            return Err(WorktreeRemoveError::LinksDetected {
                links: self.links,
                total_links: self.total_links,
                unreadable: self.unreadable,
                total_unreadable: self.total_unreadable,
            });
        }
        if self.total_unreadable > 0 {
            return Err(WorktreeRemoveError::Unreadable {
                entries: self.unreadable,
                total: self.total_unreadable,
            });
        }
        Ok(())
    }
}

struct VerifiedWorktree {
    canonical_root: PathBuf,
    common_dir: PathBuf,
    worktree_name: String,
}

/// Safely remove a linked Git worktree at `path`.
///
/// When `force` is `false`, dirty or untracked working-tree files refuse
/// removal. `force` **never** bypasses the non-following link/junction guard,
/// unreadable-entry refusal, locked-worktree check, or linked-worktree check.
pub fn remove_worktree(
    path: &Path,
    force: bool,
) -> Result<WorktreeRemoveReport, WorktreeRemoveError> {
    let canonical_root = inspect_target_root(path)?;
    let verified = verify_linked_worktree(&canonical_root, force)?;
    scan_tree_for_links(&verified.canonical_root)?;
    remove_tree_no_follow(&verified.canonical_root)?;
    verify_gone(&verified.canonical_root)?;
    prune_worktree_metadata(&verified)?;
    Ok(WorktreeRemoveReport {
        path: verified.canonical_root,
        worktree_name: verified.worktree_name,
        common_dir: verified.common_dir,
        forced: force,
        pruned: true,
    })
}

/// Inspect `path` without following a final symlink or Windows reparse point.
fn inspect_target_root(path: &Path) -> Result<PathBuf, WorktreeRemoveError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(WorktreeRemoveError::Absent {
                path: path.to_path_buf(),
            });
        }
        Err(err) => {
            return Err(WorktreeRemoveError::Unreadable {
                entries: vec![(path.to_path_buf(), err.to_string())],
                total: 1,
            });
        }
    };
    if let Some(kind) = link_or_reparse_kind(&meta) {
        return Err(WorktreeRemoveError::LinksDetected {
            links: vec![(path.to_path_buf(), kind.to_owned())],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        });
    }
    if !meta.is_dir() {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: path.to_path_buf(),
            reason: "target path is not a directory".to_owned(),
        });
    }
    se_proc::canonicalize_path(path).map_err(|err| WorktreeRemoveError::Unreadable {
        entries: vec![(path.to_path_buf(), err.to_string())],
        total: 1,
    })
}

/// Prove `canonical_root` is a linked Git worktree (never the primary repo root,
/// never a subdirectory, never locked, and clean unless `force` is set).
fn verify_linked_worktree(
    canonical_root: &Path,
    force: bool,
) -> Result<VerifiedWorktree, WorktreeRemoveError> {
    let dot_git = canonical_root.join(".git");
    let dot_git_meta = match fs::symlink_metadata(&dot_git) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(WorktreeRemoveError::NotLinkedWorktree {
                path: canonical_root.to_path_buf(),
                reason: "directory has no .git file; not a linked Git worktree".to_owned(),
            });
        }
        Err(err) => {
            return Err(WorktreeRemoveError::Unreadable {
                entries: vec![(dot_git, err.to_string())],
                total: 1,
            });
        }
    };
    if let Some(kind) = link_or_reparse_kind(&dot_git_meta) {
        return Err(WorktreeRemoveError::LinksDetected {
            links: vec![(dot_git, kind.to_owned())],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        });
    }
    if dot_git_meta.is_dir() {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: "target has a physical .git directory (primary repository root, not a linked worktree)".to_owned(),
        });
    }
    if !dot_git_meta.is_file() {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: ".git entry is not a regular file".to_owned(),
        });
    }

    let repo = Repository::open_ext(
        canonical_root,
        RepositoryOpenFlags::NO_SEARCH,
        &[] as &[&OsStr],
    )
    .map_err(|err| WorktreeRemoveError::NotLinkedWorktree {
        path: canonical_root.to_path_buf(),
        reason: format!("cannot open linked Git worktree: {}", err.message()),
    })?;

    if !repo.is_worktree() {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: "Git repository is not a linked worktree".to_owned(),
        });
    }
    let Some(workdir) = repo.workdir() else {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: "Git repository has no working tree".to_owned(),
        });
    };
    let canonical_workdir =
        se_proc::canonicalize_path(workdir).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(workdir.to_path_buf(), err.to_string())],
            total: 1,
        })?;
    if canonical_workdir != canonical_root {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: format!(
                "path is not the worktree root (resolved worktree root is {})",
                canonical_workdir.display()
            ),
        });
    }

    let worktree_name = repo
        .path()
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: "cannot determine linked worktree administrative name".to_owned(),
        })?
        .to_owned();

    let common_dir = se_proc::canonicalize_path(repo.commondir()).map_err(|err| {
        WorktreeRemoveError::Unreadable {
            entries: vec![(repo.commondir().to_path_buf(), err.to_string())],
            total: 1,
        }
    })?;

    verify_registered_and_unlocked(canonical_root, &common_dir, &worktree_name)?;

    if !force {
        check_clean_working_tree(canonical_root, &repo)?;
    }

    drop(repo);
    Ok(VerifiedWorktree {
        canonical_root: canonical_root.to_path_buf(),
        common_dir,
        worktree_name,
    })
}

fn verify_registered_and_unlocked(
    canonical_root: &Path,
    common_dir: &Path,
    worktree_name: &str,
) -> Result<(), WorktreeRemoveError> {
    let common_repo =
        Repository::open_ext(common_dir, RepositoryOpenFlags::NO_SEARCH, &[] as &[&OsStr])
            .map_err(|err| WorktreeRemoveError::NotLinkedWorktree {
                path: canonical_root.to_path_buf(),
                reason: format!("cannot open common Git directory: {}", err.message()),
            })?;

    if let Some(primary_workdir) = common_repo.workdir()
        && let Ok(canonical_primary) = se_proc::canonicalize_path(primary_workdir)
        && canonical_primary == canonical_root
    {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: "target matches the primary repository working tree".to_owned(),
        });
    }

    let worktree = common_repo.find_worktree(worktree_name).map_err(|err| {
        WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: format!(
                "worktree '{worktree_name}' is not registered in common Git directory: {}",
                err.message()
            ),
        }
    })?;

    let registered_path = se_proc::canonicalize_path(worktree.path()).map_err(|err| {
        WorktreeRemoveError::Unreadable {
            entries: vec![(worktree.path().to_path_buf(), err.to_string())],
            total: 1,
        }
    })?;
    if registered_path != canonical_root {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: format!(
                "registered worktree '{worktree_name}' points to {}, not {}",
                registered_path.display(),
                canonical_root.display()
            ),
        });
    }

    match worktree.is_locked() {
        Ok(WorktreeLockStatus::Unlocked) => Ok(()),
        Ok(WorktreeLockStatus::Locked(reason)) => Err(WorktreeRemoveError::Locked {
            path: canonical_root.to_path_buf(),
            reason,
        }),
        Err(err) => Err(WorktreeRemoveError::Unreadable {
            entries: vec![(canonical_root.to_path_buf(), err.message().to_owned())],
            total: 1,
        }),
    }
}

fn check_clean_working_tree(
    canonical_root: &Path,
    repo: &Repository,
) -> Result<(), WorktreeRemoveError> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false)
        .include_unmodified(false)
        .exclude_submodules(false);
    let statuses =
        repo.statuses(Some(&mut opts))
            .map_err(|err| WorktreeRemoveError::Unreadable {
                entries: vec![(
                    canonical_root.to_path_buf(),
                    format!("cannot inspect Git working tree status: {}", err.message()),
                )],
                total: 1,
            })?;
    if statuses.is_empty() {
        return Ok(());
    }
    let count = statuses.len();
    let sample = statuses
        .iter()
        .take(MAX_DIRTY_SAMPLE)
        .map(|entry| {
            entry
                .path()
                .map(str::to_owned)
                .unwrap_or_else(|_| "<non-utf8 path>".to_owned())
        })
        .collect();
    Err(WorktreeRemoveError::Dirty {
        path: canonical_root.to_path_buf(),
        count,
        sample,
    })
}

/// Non-following pre-removal walk over `root`. Never descends into symlinks,
/// Windows junctions, mount points, or any other reparse point.
fn scan_tree_for_links(root: &Path) -> Result<(), WorktreeRemoveError> {
    let mut findings = WalkFindings::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                findings.record_unreadable(dir, err.to_string());
                continue;
            }
        };
        for entry_res in entries {
            let entry = match entry_res {
                Ok(entry) => entry,
                Err(err) => {
                    findings.record_unreadable(dir.clone(), err.to_string());
                    continue;
                }
            };
            let entry_path = entry.path();
            let meta = match fs::symlink_metadata(&entry_path) {
                Ok(meta) => meta,
                Err(err) => {
                    findings.record_unreadable(entry_path, err.to_string());
                    continue;
                }
            };
            if let Some(kind) = link_or_reparse_kind(&meta) {
                findings.record_link(entry_path, kind.to_owned());
                continue;
            }
            if meta.is_dir() {
                stack.push(entry_path);
            }
        }
    }
    findings.into_result()
}

/// Bottom-up non-following directory deletion. Re-verifies `symlink_metadata`
/// before every removal so a concurrent link swap can never be followed.
fn remove_tree_no_follow(root: &Path) -> Result<(), WorktreeRemoveError> {
    enum Step {
        Enter(PathBuf),
        RemoveDir(PathBuf),
    }
    let mut stack = vec![Step::Enter(root.to_path_buf())];
    while let Some(step) = stack.pop() {
        match step {
            Step::Enter(dir) => {
                let dir_meta = fs::symlink_metadata(&dir).map_err(|err| {
                    WorktreeRemoveError::DeleteFailed {
                        path: dir.clone(),
                        reason: err.to_string(),
                    }
                })?;
                if let Some(kind) = link_or_reparse_kind(&dir_meta) {
                    return Err(WorktreeRemoveError::LinksDetected {
                        links: vec![(dir, kind.to_owned())],
                        total_links: 1,
                        unreadable: Vec::new(),
                        total_unreadable: 0,
                    });
                }
                stack.push(Step::RemoveDir(dir.clone()));
                let entries =
                    fs::read_dir(&dir).map_err(|err| WorktreeRemoveError::DeleteFailed {
                        path: dir.clone(),
                        reason: err.to_string(),
                    })?;
                for entry_res in entries {
                    let entry = entry_res.map_err(|err| WorktreeRemoveError::DeleteFailed {
                        path: dir.clone(),
                        reason: err.to_string(),
                    })?;
                    let entry_path = entry.path();
                    let meta = fs::symlink_metadata(&entry_path).map_err(|err| {
                        WorktreeRemoveError::DeleteFailed {
                            path: entry_path.clone(),
                            reason: err.to_string(),
                        }
                    })?;
                    if let Some(kind) = link_or_reparse_kind(&meta) {
                        return Err(WorktreeRemoveError::LinksDetected {
                            links: vec![(entry_path, kind.to_owned())],
                            total_links: 1,
                            unreadable: Vec::new(),
                            total_unreadable: 0,
                        });
                    }
                    if meta.is_dir() {
                        stack.push(Step::Enter(entry_path));
                    } else {
                        remove_regular_file(&entry_path, &meta)?;
                    }
                }
            }
            Step::RemoveDir(dir) => {
                remove_empty_dir(&dir)?;
            }
        }
    }
    Ok(())
}

fn remove_regular_file(path: &Path, meta: &fs::Metadata) -> Result<(), WorktreeRemoveError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            clear_readonly(path, meta);
            fs::remove_file(path).map_err(|retry_err| WorktreeRemoveError::DeleteFailed {
                path: path.to_path_buf(),
                reason: retry_err.to_string(),
            })
        }
        Err(err) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }),
    }
}

fn remove_empty_dir(path: &Path) -> Result<(), WorktreeRemoveError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            if let Ok(meta) = fs::symlink_metadata(path)
                && link_or_reparse_kind(&meta).is_none()
            {
                clear_readonly(path, &meta);
            }
            fs::remove_dir(path).map_err(|retry_err| WorktreeRemoveError::DeleteFailed {
                path: path.to_path_buf(),
                reason: retry_err.to_string(),
            })
        }
        Err(err) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }),
    }
}

#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly(path: &Path, meta: &fs::Metadata) {
    let mut perms = meta.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
}

fn verify_gone(path: &Path) -> Result<(), WorktreeRemoveError> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: "worktree directory still exists after removal".to_owned(),
        }),
        Err(err) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: format!("cannot verify worktree removal: {err}"),
        }),
    }
}

fn prune_worktree_metadata(verified: &VerifiedWorktree) -> Result<(), WorktreeRemoveError> {
    let common_repo = Repository::open_ext(
        &verified.common_dir,
        RepositoryOpenFlags::NO_SEARCH,
        &[] as &[&OsStr],
    )
    .map_err(|err| WorktreeRemoveError::PruneFailed {
        worktree_name: verified.worktree_name.clone(),
        reason: err.message().to_owned(),
    })?;
    let worktree = common_repo
        .find_worktree(&verified.worktree_name)
        .map_err(|err| WorktreeRemoveError::PruneFailed {
            worktree_name: verified.worktree_name.clone(),
            reason: err.message().to_owned(),
        })?;
    let mut opts = WorktreePruneOptions::new();
    opts.valid(true).working_tree(false).locked(false);
    worktree
        .prune(Some(&mut opts))
        .map_err(|err| WorktreeRemoveError::PruneFailed {
            worktree_name: verified.worktree_name.clone(),
            reason: err.message().to_owned(),
        })
}

/// Returns a human-readable kind when `meta` is a symbolic link or (on Windows)
/// any reparse point (directory junction, volume mount point, symlink, etc.).
fn link_or_reparse_kind(meta: &fs::Metadata) -> Option<&'static str> {
    if meta.file_type().is_symlink() {
        return Some("symlink");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Some("reparse point / junction");
        }
    }
    None
}
