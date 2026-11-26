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
