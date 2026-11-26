//! Handle-anchored non-following link/junction/mount guard and bottom-up
//! deletion for [`crate::worktree::remove_worktree`].
use crate::worktree::{VerifiedWorktree, WorktreeRemoveError};
use se_native_path::dir_ops::{
    ChildInfo, ChildKind, DeleteChildError, DirHandle, DirOpError, NodeId,
};
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

/// Maximum offending paths retained per category in a refusal report.
const MAX_REPORTED_PATHS: usize = 64;
/// Maximum `.git` pointer file size backed up in memory for final-rmdir recovery.
const MAX_DOT_GIT_BYTES: usize = 64 * 1024;

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

/// Parse `/proc/self/mountinfo` lines and return mount points at or below `root`.
/// Used as a fallback on Linux kernels that lack `statx` `STATX_MNT_ID`.
pub fn parse_linux_mountinfo(content: &str, root: &Path) -> HashSet<PathBuf> {
    let mut mounts = HashSet::new();
    for line in content.lines() {
        let Some(raw_mount) = line.split(' ').nth(4) else {
            continue;
        };
        let path = PathBuf::from(unescape_mountinfo_path(raw_mount));
        if path.starts_with(root) {
            mounts.insert(path);
        }
    }
    mounts
}

fn unescape_mountinfo_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let d0 = bytes[i + 1] - b'0';
            let d1 = bytes[i + 2] - b'0';
            let d2 = bytes[i + 3] - b'0';
            out.push((d0 << 6) | (d1 << 3) | d2);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn live_mountinfo_contains(path: &Path, root_id: NodeId) -> Result<bool, WorktreeRemoveError> {
    #[cfg(target_os = "linux")]
    {
        // Live `statx` `STATX_MNT_ID` + `STATX_ATTR_MOUNT_ROOT` already covers
        // same-filesystem bind mounts on every modern Linux kernel. Only read
        // `/proc/self/mountinfo` if the kernel did not report `mount_id`.
        if root_id.mount_id.is_some() {
            return Ok(false);
        }
        let content = std::fs::read_to_string("/proc/self/mountinfo").map_err(|err| {
            WorktreeRemoveError::Unreadable {
                entries: vec![(PathBuf::from("/proc/self/mountinfo"), err.to_string())],
                total: 1,
            }
        })?;
        Ok(parse_linux_mountinfo(&content, path).contains(path))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, root_id);
        Ok(false)
    }
}

fn check_child_guard(
    path: &Path,
    info: ChildInfo,
    root_id: NodeId,
) -> Result<Option<&'static str>, WorktreeRemoveError> {
    if let ChildKind::Link(kind) = info.kind {
        return Ok(Some(kind));
    }
    if info.is_mount_root || info.id.crosses_mount_from(root_id) {
        return Ok(Some("mount point / bind mount"));
    }
    if live_mountinfo_contains(path, root_id)? {
        return Ok(Some("mount point / bind mount"));
    }
    Ok(None)
}

/// Handle-anchored non-following pre-removal scan starting from the verified
/// worktree root handle. Never descends into symlinks, Windows reparse points,
/// or mounts (verified live per opened handle via `statx` / `FileIdInfo`).
pub(crate) fn scan_tree_for_links(
    verified: &VerifiedWorktree,
) -> Result<HashMap<PathBuf, NodeId>, WorktreeRemoveError> {
    let root_handle = open_verified_root(verified)?;
    let mut findings = WalkFindings::new();
    let mut identities = HashMap::new();
    identities.insert(verified.canonical_root.clone(), verified.root_id);

    let mut stack = vec![(verified.canonical_root.clone(), root_handle)];
    while let Some((dir_path, dir_handle)) = stack.pop() {
        let names = match dir_handle.read_entries() {
            Ok(names) => names,
            Err(err) => {
                findings.record_unreadable(dir_path, err.to_string());
                continue;
            }
        };
        for name in names {
            let entry_path = dir_path.join(&name);
            let info = match dir_handle.inspect_child(&name) {
                Ok(info) => info,
                Err(DirOpError::Link(kind)) => {
                    findings.record_link(entry_path, kind.to_owned());
                    continue;
                }
                Err(err) => {
                    findings.record_unreadable(entry_path, format_dir_op_err(&err));
                    continue;
                }
            };
            if let Some(kind) = check_child_guard(&entry_path, info, verified.root_id)? {
                findings.record_link(entry_path, kind.to_owned());
                continue;
            }
            if info.kind == ChildKind::Dir {
                match dir_handle.open_child_dir(&name) {
                    Ok(child_handle) => {
                        let (actual_id, is_mount_root) = match child_handle.stat_self() {
                            Ok(v) => v,
                            Err(err) => {
                                findings.record_unreadable(entry_path, err.to_string());
                                continue;
                            }
                        };
                        if is_mount_root || actual_id.crosses_mount_from(verified.root_id) {
                            findings.record_link(entry_path, "mount point / bind mount".to_owned());
                            continue;
                        }
                        if actual_id != info.id {
                            return Err(WorktreeRemoveError::CustodyChanged {
                                path: entry_path,
                                reason: "directory changed identity during link scan".to_owned(),
                            });
                        }
                        identities.insert(entry_path.clone(), actual_id);
                        stack.push((entry_path, child_handle));
                    }
                    Err(DirOpError::Link(kind)) => {
                        findings.record_link(entry_path, kind.to_owned());
                    }
                    Err(err) => {
                        findings.record_unreadable(entry_path, format_dir_op_err(&err));
                    }
                }
            }
        }
    }
    findings.into_result()?;
    Ok(identities)
}

/// Handle-anchored bottom-up deletion of the verified linked worktree.
///
/// Pre-checks parent writability, deletes every non-`.git` entry relative to
/// retained directory handles, backs up `.git` bytes before unlinking `.git`,
/// drops the root handle, and removes the root via its retained parent handle.
/// If the final root removal fails, `.git` is restored into the verified root
/// so retrying `se worktree remove` remains safe.
pub(crate) fn remove_tree_no_follow(
    verified: &VerifiedWorktree,
    dir_identities: &HashMap<PathBuf, NodeId>,
) -> Result<(), WorktreeRemoveError> {
    let parent_writable = verified.root_parent.can_modify_entries().map_err(|err| {
        WorktreeRemoveError::DeleteFailed {
            path: verified.canonical_root.clone(),
            reason: format!("cannot verify parent directory permissions: {err}"),
            partial: false,
            dot_git_preserved: true,
        }
    })?;
    if !parent_writable {
        return Err(WorktreeRemoveError::DeleteFailed {
            path: verified.canonical_root.clone(),
            reason: "parent directory is not writable; cannot remove worktree root".to_owned(),
            partial: false,
            dot_git_preserved: true,
        });
    }

    let root_handle = open_verified_root(verified)?;
    let dot_git_bytes = root_handle
        .read_child_file(OsStr::new(".git"), MAX_DOT_GIT_BYTES)
        .map_err(|err| WorktreeRemoveError::CustodyChanged {
            path: verified.canonical_root.join(".git"),
            reason: format!(
                "cannot read verified .git file before removal: {}",
                format_dir_op_err(&err)
            ),
        })?;

    let mut removed_any = false;
    delete_dir_contents(
        &root_handle,
        &verified.canonical_root,
        verified.root_id,
        Some(dir_identities),
        true,
        &mut removed_any,
    )?;

    let dot_git_path = verified.canonical_root.join(".git");
    root_handle
        .unlink_child_file(OsStr::new(".git"), Some(verified.dot_git_id))
        .map_err(|err| map_delete_err(err, &dot_git_path, removed_any, true))?;
    drop(root_handle);

    if let Err(err) = verified
        .root_parent
        .remove_child_dir(&verified.root_name, Some(verified.root_id))
    {
        let mut restored = false;
        let mut restore_note = String::new();
        match verified.root_parent.open_child_dir(&verified.root_name) {
            Ok(reopened) => match reopened.stat_self() {
                Ok((id, _)) if id == verified.root_id => {
                    match reopened.create_child_file_exclusive(OsStr::new(".git"), &dot_git_bytes) {
                        Ok(()) => restored = true,
                        Err(restore_err) => {
                            restore_note = format!("; failed to restore .git: {restore_err}");
                        }
                    }
                }
                Ok(_) => {
                    restore_note = "; root changed identity before .git restore".to_owned();
                }
                Err(stat_err) => {
                    restore_note = format!("; cannot stat root for .git restore: {stat_err}");
                }
            },
            Err(open_err) => {
                restore_note = format!(
                    "; cannot reopen root for .git restore: {}",
                    format_dir_op_err(&open_err)
                );
            }
        }
        return Err(map_delete_err_with_note(
            err,
            &verified.canonical_root,
            true,
            restored,
            &restore_note,
        ));
    }
    Ok(())
}

/// Handle-anchored deletion of a verified Git worktree admin directory
/// (`<commondir>/worktrees/<name>`) through its retained parent handle.
pub(crate) fn prune_verified_admin_dir(
    verified: &VerifiedWorktree,
) -> Result<(), WorktreeRemoveError> {
    let admin_handle = verified
        .worktrees_parent
        .open_child_dir(OsStr::new(&verified.worktree_name))
        .map_err(|err| match err {
            DirOpError::Link(kind) => WorktreeRemoveError::CustodyChanged {
                path: verified.admin_dir.clone(),
                reason: format!("worktree metadata directory became a {kind} before prune"),
            },
            other => WorktreeRemoveError::PruneFailed {
                worktree_name: verified.worktree_name.clone(),
                reason: format!(
                    "cannot open worktree metadata directory: {}",
                    format_dir_op_err(&other)
                ),
            },
        })?;
    let (actual_id, is_mount_root) =
        admin_handle
            .stat_self()
            .map_err(|err| WorktreeRemoveError::PruneFailed {
                worktree_name: verified.worktree_name.clone(),
                reason: format!("cannot stat worktree metadata directory: {err}"),
            })?;
    if is_mount_root || actual_id != verified.admin_dir_id {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: verified.admin_dir.clone(),
            reason: "worktree metadata directory changed identity before prune".to_owned(),
        });
    }
    match admin_handle.inspect_child(OsStr::new("locked")) {
        Err(DirOpError::NotFound) => {}
        Ok(_) | Err(DirOpError::Link(_)) => {
            return Err(WorktreeRemoveError::Locked {
                path: verified.canonical_root.clone(),
                reason: Some("worktree was locked before metadata prune".to_owned()),
            });
        }
        Err(err) => {
            return Err(WorktreeRemoveError::PruneFailed {
                worktree_name: verified.worktree_name.clone(),
                reason: format!(
                    "cannot verify lock status before prune: {}",
                    format_dir_op_err(&err)
                ),
            });
        }
    }

    let mut removed_any = false;
    delete_dir_contents(
        &admin_handle,
        &verified.admin_dir,
        actual_id,
        None,
        false,
        &mut removed_any,
    )
    .map_err(|err| WorktreeRemoveError::PruneFailed {
        worktree_name: verified.worktree_name.clone(),
        reason: format!("failed clearing metadata directory: {err:?}"),
    })?;
    drop(admin_handle);

    verified
        .worktrees_parent
        .remove_child_dir(
            OsStr::new(&verified.worktree_name),
            Some(verified.admin_dir_id),
        )
        .map_err(|err| match err {
            DeleteChildError::IdentityMismatch | DeleteChildError::Link(_) => {
                WorktreeRemoveError::CustodyChanged {
                    path: verified.admin_dir.clone(),
                    reason: "worktree metadata directory changed identity during prune".to_owned(),
                }
            }
            DeleteChildError::ClearReadonlyFailed(e) => WorktreeRemoveError::PruneFailed {
                worktree_name: verified.worktree_name.clone(),
                reason: format!("failed clearing readonly attribute on metadata directory: {e}"),
            },
            DeleteChildError::Io(e) => WorktreeRemoveError::PruneFailed {
                worktree_name: verified.worktree_name.clone(),
                reason: e.to_string(),
            },
        })
}

fn open_verified_root(verified: &VerifiedWorktree) -> Result<DirHandle, WorktreeRemoveError> {
    let handle = verified
        .root_parent
        .open_child_dir(&verified.root_name)
        .map_err(|err| match err {
            DirOpError::Link(kind) => WorktreeRemoveError::LinksDetected {
                links: vec![(verified.canonical_root.clone(), kind.to_owned())],
                total_links: 1,
                unreadable: Vec::new(),
                total_unreadable: 0,
            },
            other => WorktreeRemoveError::CustodyChanged {
                path: verified.canonical_root.clone(),
                reason: format!(
                    "cannot open verified worktree root: {}",
                    format_dir_op_err(&other)
                ),
            },
        })?;
    let (actual_id, is_mount_root) =
        handle
            .stat_self()
            .map_err(|err| WorktreeRemoveError::CustodyChanged {
                path: verified.canonical_root.clone(),
                reason: format!("cannot stat verified worktree root: {err}"),
            })?;
    if is_mount_root || live_mountinfo_contains(&verified.canonical_root, verified.root_id)? {
        return Err(WorktreeRemoveError::LinksDetected {
            links: vec![(
                verified.canonical_root.clone(),
                "mount point / bind mount".to_owned(),
            )],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        });
    }
    if actual_id != verified.root_id {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: verified.canonical_root.clone(),
            reason: "worktree root changed identity between verification and removal".to_owned(),
        });
    }
    Ok(handle)
}

fn delete_dir_contents(
    dir_handle: &DirHandle,
    dir_path: &Path,
    root_id: NodeId,
    expected_dirs: Option<&HashMap<PathBuf, NodeId>>,
    skip_root_dot_git: bool,
    removed_any: &mut bool,
) -> Result<(), WorktreeRemoveError> {
    let names = dir_handle
        .read_entries()
        .map_err(|err| WorktreeRemoveError::DeleteFailed {
            path: dir_path.to_path_buf(),
            reason: err.to_string(),
            partial: *removed_any,
            dot_git_preserved: true,
        })?;
    for name in names {
        if skip_root_dot_git && name == OsStr::new(".git") {
            continue;
        }
        let entry_path = dir_path.join(&name);
        let info = dir_handle.inspect_child(&name).map_err(|err| match err {
            DirOpError::Link(kind) => WorktreeRemoveError::LinksDetected {
                links: vec![(entry_path.clone(), kind.to_owned())],
                total_links: 1,
                unreadable: Vec::new(),
                total_unreadable: 0,
            },
            other => WorktreeRemoveError::DeleteFailed {
                path: entry_path.clone(),
                reason: format_dir_op_err(&other),
                partial: *removed_any,
                dot_git_preserved: true,
            },
        })?;
        if let Some(kind) = check_child_guard(&entry_path, info, root_id)? {
            return Err(WorktreeRemoveError::LinksDetected {
                links: vec![(entry_path, kind.to_owned())],
                total_links: 1,
                unreadable: Vec::new(),
                total_unreadable: 0,
            });
        }
        if info.kind == ChildKind::Dir {
            delete_child_dir_recursive(
                dir_handle,
                &name,
                &entry_path,
                info.id,
                root_id,
                expected_dirs,
                removed_any,
            )?;
        } else {
            dir_handle
                .unlink_child_file(&name, Some(info.id))
                .map_err(|err| map_delete_err(err, &entry_path, *removed_any, true))?;
            *removed_any = true;
        }
    }
    Ok(())
}

fn delete_child_dir_recursive(
    parent_handle: &DirHandle,
    name: &OsString,
    entry_path: &Path,
    inspected_id: NodeId,
    root_id: NodeId,
    expected_dirs: Option<&HashMap<PathBuf, NodeId>>,
    removed_any: &mut bool,
) -> Result<(), WorktreeRemoveError> {
    let expected_id = if let Some(map) = expected_dirs {
        let Some(&scanned) = map.get(entry_path) else {
            return Err(WorktreeRemoveError::CustodyChanged {
                path: entry_path.to_path_buf(),
                reason: "directory appeared after pre-removal scan".to_owned(),
            });
        };
        if scanned != inspected_id {
            return Err(WorktreeRemoveError::CustodyChanged {
                path: entry_path.to_path_buf(),
                reason: "directory changed identity between scan and removal".to_owned(),
            });
        }
        scanned
    } else {
        inspected_id
    };

    let child_handle = parent_handle
        .open_child_dir(name)
        .map_err(|err| match err {
            DirOpError::Link(kind) => WorktreeRemoveError::LinksDetected {
                links: vec![(entry_path.to_path_buf(), kind.to_owned())],
                total_links: 1,
                unreadable: Vec::new(),
                total_unreadable: 0,
            },
            other => WorktreeRemoveError::DeleteFailed {
                path: entry_path.to_path_buf(),
                reason: format_dir_op_err(&other),
                partial: *removed_any,
                dot_git_preserved: true,
            },
        })?;
    let (actual_id, is_mount_root) =
        child_handle
            .stat_self()
            .map_err(|err| WorktreeRemoveError::CustodyChanged {
                path: entry_path.to_path_buf(),
                reason: format!("cannot stat opened directory handle: {err}"),
            })?;
    if is_mount_root
        || actual_id.crosses_mount_from(root_id)
        || live_mountinfo_contains(entry_path, root_id)?
    {
        return Err(WorktreeRemoveError::LinksDetected {
            links: vec![(
                entry_path.to_path_buf(),
                "mount point / bind mount".to_owned(),
            )],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        });
    }
    if actual_id != expected_id {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: entry_path.to_path_buf(),
            reason: "directory changed identity on open".to_owned(),
        });
    }

    delete_dir_contents(
        &child_handle,
        entry_path,
        root_id,
        expected_dirs,
        false,
        removed_any,
    )?;
    // Close the child handle before unlinking it via its retained parent handle
    // (required on Windows so the directory is not held open during delete).
    drop(child_handle);

    parent_handle
        .remove_child_dir(name, Some(expected_id))
        .map_err(|err| map_delete_err(err, entry_path, *removed_any, true))?;
    *removed_any = true;
    Ok(())
}

fn map_delete_err(
    err: DeleteChildError,
    path: &Path,
    partial: bool,
    dot_git_preserved: bool,
) -> WorktreeRemoveError {
    map_delete_err_with_note(err, path, partial, dot_git_preserved, "")
}

fn map_delete_err_with_note(
    err: DeleteChildError,
    path: &Path,
    partial: bool,
    dot_git_preserved: bool,
    note: &str,
) -> WorktreeRemoveError {
    match err {
        DeleteChildError::Link(kind) => WorktreeRemoveError::LinksDetected {
            links: vec![(path.to_path_buf(), kind.to_owned())],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        },
        DeleteChildError::IdentityMismatch => WorktreeRemoveError::CustodyChanged {
            path: path.to_path_buf(),
            reason: format!("entry identity changed before deletion{note}"),
        },
        DeleteChildError::ClearReadonlyFailed(io_err) => WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: format!(
                "failed to clear read-only attribute on verified handle: {io_err}{note}"
            ),
            partial,
            dot_git_preserved,
        },
        DeleteChildError::Io(io_err) => WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: format!("{io_err}{note}"),
            partial,
            dot_git_preserved,
        },
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
