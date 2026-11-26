//! Shared types for safe linked Git worktree removal.
//! Kept in a leaf module so `worktree` and `worktree_guard` remain acyclic.
use se_native_path::dir_ops::{DeleteChildError, DirHandle, DirOpError, NodeId};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Witnessed result of a completed safe worktree removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorktreeRemoveReport {
    pub path: PathBuf,
    pub worktree_name: String,
    pub common_dir: PathBuf,
    pub forced: bool,
    pub pruned: bool,
}

/// Typed refusal or failure from [`crate::worktree::remove_worktree`].
/// Absent, unreadable, link/mount-guarded, nested-repo, custody-changed, and
/// dirty states are never collapsed.
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
    NestedGitRepositories {
        paths: Vec<(PathBuf, String)>,
        total: usize,
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

impl WorktreeRemoveError {
    /// Construct a single-entry `LinksDetected` refusal.
    pub(crate) fn single_link(path: PathBuf, kind: impl Into<String>) -> Self {
        Self::LinksDetected {
            links: vec![(path, kind.into())],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        }
    }
}

pub(crate) struct VerifiedWorktree {
    pub(crate) canonical_root: PathBuf,
    pub(crate) root_parent: DirHandle,
    pub(crate) root_name: OsString,
    pub(crate) root_id: NodeId,
    pub(crate) dot_git_id: NodeId,
    pub(crate) common_dir: PathBuf,
    pub(crate) worktrees_parent: DirHandle,
    pub(crate) admin_dir: PathBuf,
    pub(crate) admin_dir_id: NodeId,
    pub(crate) worktree_name: String,
}

/// Maximum offending paths retained per category in a refusal report.
const MAX_REPORTED_PATHS: usize = 64;

pub(crate) struct WalkFindings {
    links: Vec<(PathBuf, String)>,
    total_links: usize,
    nested_repos: Vec<(PathBuf, String)>,
    total_nested_repos: usize,
    unreadable: Vec<(PathBuf, String)>,
    total_unreadable: usize,
}

impl WalkFindings {
    pub(crate) fn new() -> Self {
        Self {
            links: Vec::new(),
            total_links: 0,
            nested_repos: Vec::new(),
            total_nested_repos: 0,
            unreadable: Vec::new(),
            total_unreadable: 0,
        }
    }

    pub(crate) fn record_link(&mut self, path: PathBuf, kind: String) {
        self.total_links += 1;
        if self.links.len() < MAX_REPORTED_PATHS {
            self.links.push((path, kind));
        }
    }

    pub(crate) fn record_nested_repo(&mut self, path: PathBuf, kind: String) {
        self.total_nested_repos += 1;
        if self.nested_repos.len() < MAX_REPORTED_PATHS {
            self.nested_repos.push((path, kind));
        }
    }

    pub(crate) fn record_unreadable(&mut self, path: PathBuf, reason: String) {
        self.total_unreadable += 1;
        if self.unreadable.len() < MAX_REPORTED_PATHS {
            self.unreadable.push((path, reason));
        }
    }

    pub(crate) fn into_result(mut self) -> Result<(), WorktreeRemoveError> {
        self.links.sort_by(|a, b| a.0.cmp(&b.0));
        self.nested_repos.sort_by(|a, b| a.0.cmp(&b.0));
        self.unreadable.sort_by(|a, b| a.0.cmp(&b.0));
        if self.total_links > 0 {
            return Err(WorktreeRemoveError::LinksDetected {
                links: self.links,
                total_links: self.total_links,
                unreadable: self.unreadable,
                total_unreadable: self.total_unreadable,
            });
        }
        if self.total_nested_repos > 0 {
            return Err(WorktreeRemoveError::NestedGitRepositories {
                paths: self.nested_repos,
                total: self.total_nested_repos,
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

pub(crate) fn format_dir_op_err(err: &DirOpError) -> String {
    match err {
        DirOpError::NotFound => "entry not found".to_owned(),
        DirOpError::Link(kind) => (*kind).to_owned(),
        DirOpError::NotDir => "not a directory".to_owned(),
        DirOpError::Io(io_err) => io_err.to_string(),
    }
}

pub(crate) fn format_delete_child_err(err: &DeleteChildError) -> String {
    match err {
        DeleteChildError::Link(kind) => format!("target became a {kind} before removal"),
        DeleteChildError::IdentityMismatch => "entry identity changed before deletion".to_owned(),
        DeleteChildError::ClearReadonlyFailed(io_err) => {
            format!("failed to clear read-only attribute on verified handle: {io_err}")
        }
        DeleteChildError::Io(io_err) => io_err.to_string(),
    }
}

pub(crate) fn map_delete_err(
    err: DeleteChildError,
    path: &Path,
    partial: bool,
    dot_git_preserved: bool,
) -> WorktreeRemoveError {
    match err {
        DeleteChildError::Link(kind) => WorktreeRemoveError::single_link(path.to_path_buf(), kind),
        DeleteChildError::IdentityMismatch => WorktreeRemoveError::CustodyChanged {
            path: path.to_path_buf(),
            reason: "entry identity changed before deletion".to_owned(),
        },
        DeleteChildError::ClearReadonlyFailed(io_err) => WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: format!("failed to clear read-only attribute on verified handle: {io_err}"),
            partial,
            dot_git_preserved,
        },
        DeleteChildError::Io(io_err) => WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: io_err.to_string(),
            partial,
            dot_git_preserved,
        },
    }
}

/// Once any file or directory has been removed (`removed_any == true`), convert
/// any non-`DeleteFailed`/`PruneFailed` refusal or unreadable error into
/// `DeleteFailed` carrying `partial: true` and `dot_git_preserved: true` so
/// callers never mistake a post-mutation failure for a clean preflight refusal.
pub(crate) fn late_guard_err(err: WorktreeRemoveError, removed_any: bool) -> WorktreeRemoveError {
    if !removed_any {
        return err;
    }
    match err {
        err @ (WorktreeRemoveError::DeleteFailed { .. }
        | WorktreeRemoveError::PruneFailed { .. }) => err,
        WorktreeRemoveError::LinksDetected { links, .. } => {
            let (path, kind) = links
                .into_iter()
                .next()
                .unwrap_or_else(|| (PathBuf::new(), "link/mount".to_owned()));
            WorktreeRemoveError::DeleteFailed {
                path,
                reason: format!("detected {kind} during deletion"),
                partial: true,
                dot_git_preserved: true,
            }
        }
        WorktreeRemoveError::NestedGitRepositories { paths, .. } => {
            let (path, kind) = paths
                .into_iter()
                .next()
                .unwrap_or_else(|| (PathBuf::new(), "nested Git repository".to_owned()));
            WorktreeRemoveError::DeleteFailed {
                path,
                reason: format!("detected {kind} during deletion"),
                partial: true,
                dot_git_preserved: true,
            }
        }
        WorktreeRemoveError::Unreadable { entries, .. } => {
            let (path, reason) = entries.into_iter().next().unwrap_or_else(|| {
                (
                    PathBuf::new(),
                    "unreadable entry during deletion".to_owned(),
                )
            });
            WorktreeRemoveError::DeleteFailed {
                path,
                reason,
                partial: true,
                dot_git_preserved: true,
            }
        }
        WorktreeRemoveError::CustodyChanged { path, reason }
        | WorktreeRemoveError::NotLinkedWorktree { path, reason } => {
            WorktreeRemoveError::DeleteFailed {
                path,
                reason,
                partial: true,
                dot_git_preserved: true,
            }
        }
        WorktreeRemoveError::Absent { path } => WorktreeRemoveError::DeleteFailed {
            path,
            reason: "target vanished during deletion".to_owned(),
            partial: true,
            dot_git_preserved: true,
        },
        WorktreeRemoveError::Locked { path, reason } => WorktreeRemoveError::DeleteFailed {
            path,
            reason: reason.unwrap_or_else(|| "worktree became locked during deletion".to_owned()),
            partial: true,
            dot_git_preserved: true,
        },
        WorktreeRemoveError::Dirty { path, count, .. } => WorktreeRemoveError::DeleteFailed {
            path,
            reason: format!("worktree became dirty ({count} change(s)) during deletion"),
            partial: true,
            dot_git_preserved: true,
        },
    }
}

/// Once the worktree directory itself has been removed, every error during the
/// post-delete metadata prune phase must surface as `PruneFailed` so callers
/// know the directory is already gone and only Git metadata prune failed.
pub(crate) fn late_prune_err(worktree_name: &str, err: WorktreeRemoveError) -> WorktreeRemoveError {
    match err {
        err @ WorktreeRemoveError::PruneFailed { .. } => err,
        WorktreeRemoveError::CustodyChanged { reason, .. }
        | WorktreeRemoveError::NotLinkedWorktree { reason, .. }
        | WorktreeRemoveError::DeleteFailed { reason, .. } => WorktreeRemoveError::PruneFailed {
            worktree_name: worktree_name.to_owned(),
            reason,
        },
        WorktreeRemoveError::Locked { reason, .. } => WorktreeRemoveError::PruneFailed {
            worktree_name: worktree_name.to_owned(),
            reason: reason
                .unwrap_or_else(|| "worktree was locked before metadata prune".to_owned()),
        },
        WorktreeRemoveError::Unreadable { entries, .. } => {
            let reason = entries
                .into_iter()
                .next()
                .map(|(p, r)| format!("{}: {r}", p.display()))
                .unwrap_or_else(|| "unreadable metadata entry".to_owned());
            WorktreeRemoveError::PruneFailed {
                worktree_name: worktree_name.to_owned(),
                reason,
            }
        }
        WorktreeRemoveError::LinksDetected { links, .. } => {
            let reason = links
                .into_iter()
                .next()
                .map(|(p, k)| format!("detected {k} at {}", p.display()))
                .unwrap_or_else(|| "detected link/mount in metadata directory".to_owned());
            WorktreeRemoveError::PruneFailed {
                worktree_name: worktree_name.to_owned(),
                reason,
            }
        }
        other => WorktreeRemoveError::PruneFailed {
            worktree_name: worktree_name.to_owned(),
            reason: format!("{other:?}"),
        },
    }
}
