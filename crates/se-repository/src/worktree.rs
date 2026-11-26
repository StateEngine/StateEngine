//! Safe linked Git worktree removal with a non-following link/junction/mount guard.
pub use crate::worktree_guard::parse_linux_mountinfo;
use crate::worktree_guard::{
    NodeIdentity, collect_mount_points, link_or_reparse_kind, remove_tree_no_follow,
    scan_tree_for_links,
};
use git2::{
    Repository, RepositoryOpenFlags, StatusOptions, WorktreeLockStatus, WorktreePruneOptions,
};
use std::{
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

/// Maximum dirty/untracked/ignored sample paths included in a dirty refusal.
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
/// Absent, unreadable, link/mount-guarded, custody-changed, and dirty states
/// are never collapsed.
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
    CustodyChanged {
        path: PathBuf,
        reason: String,
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
        partial: bool,
        dot_git_preserved: bool,
    },
    PruneFailed {
        worktree_name: String,
        reason: String,
    },
}

pub(crate) struct VerifiedWorktree {
    pub(crate) canonical_root: PathBuf,
    pub(crate) root_identity: NodeIdentity,
    pub(crate) dot_git_identity: NodeIdentity,
    pub(crate) common_dir: PathBuf,
    pub(crate) common_dir_identity: NodeIdentity,
    pub(crate) admin_dir: PathBuf,
    pub(crate) admin_dir_identity: NodeIdentity,
    pub(crate) worktree_name: String,
    #[cfg(unix)]
    pub(crate) root_dev: u64,
}

/// Safely remove a linked Git worktree at `path`.
///
/// When `force` is `false`, modified, staged, untracked, or ignored files
/// refuse removal. `force` **never** bypasses the non-following
/// link/junction/mount guard, unreadable-entry refusal, custody verification,
/// locked-worktree check, or linked-worktree check.
pub fn remove_worktree(
    path: &Path,
    force: bool,
) -> Result<WorktreeRemoveReport, WorktreeRemoveError> {
    let (canonical_root, root_identity, root_dev) = inspect_target_root(path)?;
    #[cfg(not(unix))]
    let _ = root_dev;
    let verified = verify_linked_worktree(
        &canonical_root,
        root_identity,
        #[cfg(unix)]
        root_dev,
        force,
    )?;
    let mount_points = collect_mount_points(&verified.canonical_root)?;
    let dir_identities = scan_tree_for_links(&verified, &mount_points)?;
    remove_tree_no_follow(&verified, &dir_identities, &mount_points)?;
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
fn inspect_target_root(path: &Path) -> Result<(PathBuf, NodeIdentity, u64), WorktreeRemoveError> {
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
    let root_identity = NodeIdentity::from_meta(&meta);
    #[cfg(unix)]
    let root_dev = {
        use std::os::unix::fs::MetadataExt;
        meta.dev()
    };
    #[cfg(not(unix))]
    let root_dev = 0;
    let canonical =
        se_proc::canonicalize_path(path).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(path.to_path_buf(), err.to_string())],
            total: 1,
        })?;
    let canon_meta =
        fs::symlink_metadata(&canonical).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(canonical.clone(), err.to_string())],
            total: 1,
        })?;
    if NodeIdentity::from_meta(&canon_meta) != root_identity {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: canonical,
            reason: "worktree root changed identity during canonicalization".to_owned(),
        });
    }
    Ok((canonical, root_identity, root_dev))
}

fn inspect_dot_git_file(canonical_root: &Path) -> Result<NodeIdentity, WorktreeRemoveError> {
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
    Ok(NodeIdentity::from_meta(&dot_git_meta))
}

fn verify_linked_worktree(
    canonical_root: &Path,
    root_identity: NodeIdentity,
    #[cfg(unix)] root_dev: u64,
    force: bool,
) -> Result<VerifiedWorktree, WorktreeRemoveError> {
    let dot_git_identity = inspect_dot_git_file(canonical_root)?;

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
    let common_dir_meta =
        fs::symlink_metadata(&common_dir).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(common_dir.clone(), err.to_string())],
            total: 1,
        })?;
    let common_dir_identity = NodeIdentity::from_meta(&common_dir_meta);

    let admin_dir = common_dir.join("worktrees").join(&worktree_name);
    let admin_dir_meta =
        fs::symlink_metadata(&admin_dir).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(admin_dir.clone(), err.to_string())],
            total: 1,
        })?;
    if link_or_reparse_kind(&admin_dir_meta).is_some() || !admin_dir_meta.is_dir() {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: format!(
                "worktree administrative entry {} is not a real directory",
                admin_dir.display()
            ),
        });
    }
    let admin_dir_identity = NodeIdentity::from_meta(&admin_dir_meta);

    verify_registered_and_unlocked(canonical_root, &common_dir, &worktree_name)?;

    if !force {
        check_clean_working_tree(canonical_root, &repo)?;
    }

    drop(repo);
    Ok(VerifiedWorktree {
        canonical_root: canonical_root.to_path_buf(),
        root_identity,
        dot_git_identity,
        common_dir,
        common_dir_identity,
        admin_dir,
        admin_dir_identity,
        worktree_name,
        #[cfg(unix)]
        root_dev,
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
        .include_ignored(true)
        .recurse_ignored_dirs(true)
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

fn verify_gone(path: &Path) -> Result<(), WorktreeRemoveError> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: "worktree directory still exists after removal".to_owned(),
            partial: true,
            dot_git_preserved: false,
        }),
        Err(err) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: format!("cannot verify worktree removal: {err}"),
            partial: true,
            dot_git_preserved: false,
        }),
    }
}

/// Prune ONLY the exact verified, now-missing worktree registration.
fn prune_worktree_metadata(verified: &VerifiedWorktree) -> Result<(), WorktreeRemoveError> {
    let common_meta = fs::symlink_metadata(&verified.common_dir).map_err(|err| {
        WorktreeRemoveError::PruneFailed {
            worktree_name: verified.worktree_name.clone(),
            reason: format!("cannot re-verify common Git directory: {err}"),
        }
    })?;
    if link_or_reparse_kind(&common_meta).is_some()
        || NodeIdentity::from_meta(&common_meta) != verified.common_dir_identity
    {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: verified.common_dir.clone(),
            reason: "common Git directory changed identity before metadata prune".to_owned(),
        });
    }
    let admin_meta = fs::symlink_metadata(&verified.admin_dir).map_err(|err| {
        WorktreeRemoveError::PruneFailed {
            worktree_name: verified.worktree_name.clone(),
            reason: format!("cannot re-verify worktree metadata directory: {err}"),
        }
    })?;
    if link_or_reparse_kind(&admin_meta).is_some()
        || NodeIdentity::from_meta(&admin_meta) != verified.admin_dir_identity
    {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: verified.admin_dir.clone(),
            reason: "worktree metadata directory changed identity before prune".to_owned(),
        });
    }

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
    // `valid(false)` refuses pruning if a valid worktree reappeared at the path.
    let mut opts = WorktreePruneOptions::new();
    opts.valid(false).working_tree(false).locked(false);
    worktree
        .prune(Some(&mut opts))
        .map_err(|err| WorktreeRemoveError::PruneFailed {
            worktree_name: verified.worktree_name.clone(),
            reason: err.message().to_owned(),
        })
}
