//! Safe linked Git worktree removal with a non-following link/junction/mount guard.
pub use crate::worktree_guard::parse_linux_mountinfo;
use crate::worktree_guard::{prune_verified_admin_dir, remove_tree_no_follow, scan_tree_for_links};
use crate::worktree_types::{VerifiedWorktree, format_dir_op_err};
pub use crate::worktree_types::{WorktreeRemoveError, WorktreeRemoveReport};
use git2::{Repository, RepositoryOpenFlags, StatusOptions, WorktreeLockStatus};
use se_native_path::dir_ops::{ChildKind, DirHandle, DirOpError, NodeId};
use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

/// Maximum dirty/untracked/ignored sample paths included in a dirty refusal.
const MAX_DIRTY_SAMPLE: usize = 10;

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
    let (canonical_root, root_parent, root_name, root_id) = inspect_target_root(path)?;
    let verified = verify_linked_worktree(canonical_root, root_parent, root_name, root_id, force)?;
    let dir_identities = scan_tree_for_links(&verified)?;
    remove_tree_no_follow(&verified, &dir_identities)?;
    verify_gone(&verified)?;
    prune_verified_admin_dir(&verified)?;
    Ok(WorktreeRemoveReport {
        path: verified.canonical_root,
        worktree_name: verified.worktree_name,
        common_dir: verified.common_dir,
        forced: force,
        pruned: true,
    })
}

/// Open `path` without following a final symlink or Windows reparse point,
/// canonicalize it, and anchor both the root and its parent directory via
/// retained OS handles.
fn inspect_target_root(
    path: &Path,
) -> Result<(PathBuf, DirHandle, OsString, NodeId), WorktreeRemoveError> {
    let initial = DirHandle::open_root(path).map_err(|err| match err {
        DirOpError::NotFound => WorktreeRemoveError::Absent {
            path: path.to_path_buf(),
        },
        DirOpError::Link(kind) => WorktreeRemoveError::single_link(path.to_path_buf(), kind),
        DirOpError::NotDir => WorktreeRemoveError::NotLinkedWorktree {
            path: path.to_path_buf(),
            reason: "target path is not a directory".to_owned(),
        },
        DirOpError::Io(io_err) => WorktreeRemoveError::Unreadable {
            entries: vec![(path.to_path_buf(), io_err.to_string())],
            total: 1,
        },
    })?;
    let (root_id, is_mount_root) =
        initial
            .stat_self()
            .map_err(|err| WorktreeRemoveError::Unreadable {
                entries: vec![(path.to_path_buf(), err.to_string())],
                total: 1,
            })?;
    if is_mount_root {
        return Err(WorktreeRemoveError::single_link(
            path.to_path_buf(),
            "mount point / bind mount",
        ));
    }
    let canonical =
        se_proc::canonicalize_path(path).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(path.to_path_buf(), err.to_string())],
            total: 1,
        })?;
    let parent_path = canonical
        .parent()
        .ok_or_else(|| WorktreeRemoveError::NotLinkedWorktree {
            path: canonical.clone(),
            reason: "worktree path has no parent directory".to_owned(),
        })?;
    let root_name = canonical
        .file_name()
        .ok_or_else(|| WorktreeRemoveError::NotLinkedWorktree {
            path: canonical.clone(),
            reason: "worktree path has no final directory name".to_owned(),
        })?
        .to_os_string();
    let root_parent =
        DirHandle::open_root(parent_path).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(parent_path.to_path_buf(), format_dir_op_err(&err))],
            total: 1,
        })?;
    let child_info = root_parent.inspect_child(&root_name).map_err(|err| {
        WorktreeRemoveError::CustodyChanged {
            path: canonical.clone(),
            reason: format!(
                "cannot verify canonical worktree root: {}",
                format_dir_op_err(&err)
            ),
        }
    })?;
    if child_info.id != root_id {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: canonical,
            reason: "worktree root changed identity during canonicalization".to_owned(),
        });
    }
    drop(initial);
    Ok((canonical, root_parent, root_name, root_id))
}

fn inspect_dot_git_file(
    canonical_root: &Path,
    root_parent: &DirHandle,
    root_name: &OsStr,
    root_id: NodeId,
) -> Result<NodeId, WorktreeRemoveError> {
    let root_handle = root_parent.open_child_dir(root_name).map_err(|err| {
        WorktreeRemoveError::CustodyChanged {
            path: canonical_root.to_path_buf(),
            reason: format!("cannot open worktree root: {}", format_dir_op_err(&err)),
        }
    })?;
    let (actual_id, _) =
        root_handle
            .stat_self()
            .map_err(|err| WorktreeRemoveError::Unreadable {
                entries: vec![(canonical_root.to_path_buf(), err.to_string())],
                total: 1,
            })?;
    if actual_id != root_id {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: canonical_root.to_path_buf(),
            reason: "worktree root changed identity before .git inspection".to_owned(),
        });
    }
    let dot_git = canonical_root.join(".git");
    let info = match root_handle.inspect_child(OsStr::new(".git")) {
        Ok(info) => info,
        Err(DirOpError::NotFound) => {
            return Err(WorktreeRemoveError::NotLinkedWorktree {
                path: canonical_root.to_path_buf(),
                reason: "directory has no .git file; not a linked Git worktree".to_owned(),
            });
        }
        Err(DirOpError::Link(kind)) => {
            return Err(WorktreeRemoveError::single_link(dot_git, kind));
        }
        Err(err) => {
            return Err(WorktreeRemoveError::Unreadable {
                entries: vec![(dot_git, format_dir_op_err(&err))],
                total: 1,
            });
        }
    };
    match info.kind {
        ChildKind::Link(kind) => Err(WorktreeRemoveError::single_link(dot_git, kind)),
        ChildKind::Dir => Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: "target has a physical .git directory (primary repository root, not a linked worktree)".to_owned(),
        }),
        ChildKind::File => Ok(info.id),
        ChildKind::Other => Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root.to_path_buf(),
            reason: ".git entry is not a regular file".to_owned(),
        }),
    }
}

fn verify_linked_worktree(
    canonical_root: PathBuf,
    root_parent: DirHandle,
    root_name: OsString,
    root_id: NodeId,
    force: bool,
) -> Result<VerifiedWorktree, WorktreeRemoveError> {
    let dot_git_id = inspect_dot_git_file(&canonical_root, &root_parent, &root_name, root_id)?;

    let repo = Repository::open_ext(
        &canonical_root,
        RepositoryOpenFlags::NO_SEARCH,
        &[] as &[&OsStr],
    )
    .map_err(|err| WorktreeRemoveError::NotLinkedWorktree {
        path: canonical_root.clone(),
        reason: format!("cannot open linked Git worktree: {}", err.message()),
    })?;

    if !repo.is_worktree() {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root,
            reason: "Git repository is not a linked worktree".to_owned(),
        });
    }
    let Some(workdir) = repo.workdir() else {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root,
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
            path: canonical_root,
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
            path: canonical_root.clone(),
            reason: "cannot determine linked worktree administrative name".to_owned(),
        })?
        .to_owned();

    let common_dir = se_proc::canonicalize_path(repo.commondir()).map_err(|err| {
        WorktreeRemoveError::Unreadable {
            entries: vec![(repo.commondir().to_path_buf(), err.to_string())],
            total: 1,
        }
    })?;

    let worktrees_dir = common_dir.join("worktrees");
    let worktrees_parent =
        DirHandle::open_root(&worktrees_dir).map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(worktrees_dir.clone(), format_dir_op_err(&err))],
            total: 1,
        })?;
    let admin_dir = worktrees_dir.join(&worktree_name);
    let admin_info = worktrees_parent
        .inspect_child(OsStr::new(&worktree_name))
        .map_err(|err| WorktreeRemoveError::Unreadable {
            entries: vec![(admin_dir.clone(), format_dir_op_err(&err))],
            total: 1,
        })?;
    if admin_info.kind != ChildKind::Dir || admin_info.is_mount_root {
        return Err(WorktreeRemoveError::NotLinkedWorktree {
            path: canonical_root,
            reason: format!(
                "worktree administrative entry {} is not a real directory",
                admin_dir.display()
            ),
        });
    }
    let admin_dir_id = admin_info.id;

    verify_registered_and_unlocked(&canonical_root, &common_dir, &worktree_name)?;

    if !force {
        check_clean_working_tree(&canonical_root, &repo)?;
    }

    drop(repo);
    Ok(VerifiedWorktree {
        canonical_root,
        root_parent,
        root_name,
        root_id,
        dot_git_id,
        common_dir,
        worktrees_parent,
        admin_dir,
        admin_dir_id,
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

fn verify_gone(verified: &VerifiedWorktree) -> Result<(), WorktreeRemoveError> {
    match verified.root_parent.inspect_child(&verified.root_name) {
        Err(DirOpError::NotFound) => Ok(()),
        Ok(_) | Err(DirOpError::Link(_)) => Err(WorktreeRemoveError::DeleteFailed {
            path: verified.canonical_root.clone(),
            reason: "worktree directory still exists after removal".to_owned(),
            partial: true,
            dot_git_preserved: false,
        }),
        Err(err) => Err(WorktreeRemoveError::DeleteFailed {
            path: verified.canonical_root.clone(),
            reason: format!(
                "cannot verify worktree removal: {}",
                format_dir_op_err(&err)
            ),
            partial: true,
            dot_git_preserved: false,
        }),
    }
}
