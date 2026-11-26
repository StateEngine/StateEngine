//! Handle-anchored non-following link/junction/mount/nested-repo guard and
//! bottom-up deletion for [`crate::worktree::remove_worktree`].
use crate::worktree_types::{
    VerifiedWorktree, WalkFindings, WorktreeRemoveError, format_delete_child_err,
    format_dir_op_err, late_guard_err, map_delete_err,
};
use se_native_path::dir_ops::{
    ChildInfo, ChildKind, DeleteChildError, DirHandle, DirOpError, NodeId,
};
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

/// Maximum `.git` pointer file size read for submodule check or final-rmdir recovery.
const MAX_DOT_GIT_BYTES: usize = 64 * 1024;

/// Anchored parent-to-child binding verified along the full active ancestor
/// chain across mutation boundaries so a concurrent move/rename of the root or
/// any descendant stops deletion immediately.
#[derive(Clone, Copy)]
struct AncestorLink<'a> {
    parent: &'a DirHandle,
    name: &'a OsStr,
    id: NodeId,
    path: &'a Path,
}

impl AncestorLink<'_> {
    fn verify(&self, removed_any: bool) -> Result<(), WorktreeRemoveError> {
        let info = self.parent.inspect_child(self.name).map_err(|err| {
            late_guard_err(
                WorktreeRemoveError::CustodyChanged {
                    path: self.path.to_path_buf(),
                    reason: format!(
                        "anchored directory moved or vanished during removal: {}",
                        format_dir_op_err(&err)
                    ),
                },
                removed_any,
            )
        })?;
        if let ChildKind::Link(kind) = info.kind {
            return Err(late_guard_err(
                WorktreeRemoveError::single_link(self.path.to_path_buf(), kind),
                removed_any,
            ));
        }
        if info.is_mount_root || info.id != self.id {
            return Err(late_guard_err(
                WorktreeRemoveError::CustodyChanged {
                    path: self.path.to_path_buf(),
                    reason: "anchored directory was replaced or moved during removal".to_owned(),
                },
                removed_any,
            ));
        }
        Ok(())
    }
}

fn verify_ancestors(
    ancestors: &[AncestorLink<'_>],
    removed_any: bool,
) -> Result<(), WorktreeRemoveError> {
    for link in ancestors {
        link.verify(removed_any)?;
    }
    Ok(())
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

/// Classify a `.git` entry found below the worktree root.
/// Exempts only submodule gitfiles whose `gitdir:` target resolves inside this
/// repository's own `<common_dir>/modules`. Any nested `.git` directory or
/// non-submodule `.git` file (such as a nested linked worktree) is refused.
fn nested_git_kind(
    dir_handle: &DirHandle,
    dir_path: &Path,
    info: ChildInfo,
    own_modules_dir: Option<&Path>,
) -> Option<&'static str> {
    match info.kind {
        ChildKind::Dir => Some("nested Git repository"),
        ChildKind::File => {
            if let Some(modules_dir) = own_modules_dir
                && let Ok(bytes) = dir_handle.read_child_file(OsStr::new(".git"), MAX_DOT_GIT_BYTES)
                && let Ok(text) = std::str::from_utf8(&bytes)
                && let Some(raw_target) = text.trim().strip_prefix("gitdir:")
            {
                let target = Path::new(raw_target.trim());
                let resolved = if target.is_absolute() {
                    target.to_path_buf()
                } else {
                    dir_path.join(target)
                };
                if let Ok(canon) = se_proc::canonicalize_path(&resolved)
                    && canon.starts_with(modules_dir)
                {
                    return None;
                }
            }
            Some("nested linked worktree or Git repository")
        }
        _ => Some("nested Git entry"),
    }
}

/// Handle-anchored non-following pre-removal scan holding only `O(depth)` open
/// directory handles (the active ancestor chain), never opening sibling
/// directories simultaneously.
pub(crate) fn scan_tree_for_links(
    verified: &VerifiedWorktree,
) -> Result<HashMap<PathBuf, NodeId>, WorktreeRemoveError> {
    let root_handle = open_verified_root(verified)?;
    let own_modules = se_proc::canonicalize_path(verified.common_dir.join("modules")).ok();
    let mut findings = WalkFindings::new();
    let mut identities = HashMap::new();
    identities.insert(verified.canonical_root.clone(), verified.root_id);

    scan_dir_recursive(
        &root_handle,
        &verified.canonical_root,
        0,
        verified.root_id,
        own_modules.as_deref(),
        &mut identities,
        &mut findings,
    )?;
    findings.into_result()?;
    Ok(identities)
}

fn scan_dir_recursive(
    dir_handle: &DirHandle,
    dir_path: &Path,
    depth: usize,
    root_id: NodeId,
    own_modules_dir: Option<&Path>,
    identities: &mut HashMap<PathBuf, NodeId>,
    findings: &mut WalkFindings,
) -> Result<(), WorktreeRemoveError> {
    let names = match dir_handle.read_entries() {
        Ok(names) => names,
        Err(err) => {
            findings.record_unreadable(dir_path.to_path_buf(), err.to_string());
            return Ok(());
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
        if let Some(kind) = check_child_guard(&entry_path, info, root_id)? {
            findings.record_link(entry_path, kind.to_owned());
            continue;
        }
        if depth > 0
            && name == OsStr::new(".git")
            && let Some(kind) = nested_git_kind(dir_handle, dir_path, info, own_modules_dir)
        {
            findings.record_nested_repo(dir_path.to_path_buf(), kind.to_owned());
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
                    if is_mount_root || actual_id.crosses_mount_from(root_id) {
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
                    scan_dir_recursive(
                        &child_handle,
                        &entry_path,
                        depth + 1,
                        root_id,
                        own_modules_dir,
                        identities,
                        findings,
                    )?;
                    // `child_handle` drops here before opening the next sibling (`O(depth)` FDs).
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
    Ok(())
}

/// Handle-anchored bottom-up deletion of the verified linked worktree.
///
/// Pre-checks parent writability, verifies the root's parent binding across
/// every mutation boundary, backs up `.git` bytes before unlinking `.git`,
/// drops the root handle, and removes the root via its retained parent handle.
/// Any failure on the final root removal attempts to restore `.git` and always
/// reports `DeleteFailed` carrying `partial`, `dot_git_preserved`, and full
/// recovery detail.
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

    let own_modules = se_proc::canonicalize_path(verified.common_dir.join("modules")).ok();
    let root_anchor = [AncestorLink {
        parent: &verified.root_parent,
        name: &verified.root_name,
        id: verified.root_id,
        path: &verified.canonical_root,
    }];
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
    let ctx = DeleteCtx {
        root_id: verified.root_id,
        expected_dirs: Some(dir_identities),
        own_modules_dir: own_modules.as_deref(),
        guard_nested_git: true,
    };
    delete_dir_contents(
        &root_handle,
        &verified.canonical_root,
        0,
        &root_anchor,
        &ctx,
        true,
        &mut removed_any,
    )?;

    verify_ancestors(&root_anchor, removed_any)?;
    let dot_git_path = verified.canonical_root.join(".git");
    root_handle
        .unlink_child_file(OsStr::new(".git"), Some(verified.dot_git_id))
        .map_err(|err| {
            late_guard_err(
                map_delete_err(err, &dot_git_path, removed_any, true),
                removed_any,
            )
        })?;
    drop(root_handle);

    if let Err(err) = verified
        .root_parent
        .remove_child_dir(&verified.root_name, Some(verified.root_id))
    {
        let (restored, restore_note) = restore_dot_git(verified, &dot_git_bytes);
        return Err(WorktreeRemoveError::DeleteFailed {
            path: verified.canonical_root.clone(),
            reason: format!("{}{restore_note}", format_delete_child_err(&err)),
            partial: true,
            dot_git_preserved: restored,
        });
    }
    Ok(())
}

fn restore_dot_git(verified: &VerifiedWorktree, dot_git_bytes: &[u8]) -> (bool, String) {
    match verified.root_parent.open_child_dir(&verified.root_name) {
        Ok(reopened) => match reopened.stat_self() {
            Ok((id, _)) if id == verified.root_id => {
                match reopened.create_child_file_exclusive(OsStr::new(".git"), dot_git_bytes) {
                    Ok(()) => (true, String::new()),
                    Err(restore_err) => (false, format!("; failed to restore .git: {restore_err}")),
                }
            }
            Ok(_) => (
                false,
                "; root changed identity before .git restore".to_owned(),
            ),
            Err(stat_err) => (
                false,
                format!("; cannot stat root for .git restore: {stat_err}"),
            ),
        },
        Err(open_err) => (
            false,
            format!(
                "; cannot reopen root for .git restore: {}",
                format_dir_op_err(&open_err)
            ),
        ),
    }
}

/// Handle-anchored deletion of a verified Git worktree admin directory
/// (`<commondir>/worktrees/<name>`) through its retained parent handle.
pub(crate) fn prune_verified_admin_dir(
    verified: &VerifiedWorktree,
) -> Result<(), WorktreeRemoveError> {
    let admin_anchor = [AncestorLink {
        parent: &verified.worktrees_parent,
        name: OsStr::new(&verified.worktree_name),
        id: verified.admin_dir_id,
        path: &verified.admin_dir,
    }];
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
    let ctx = DeleteCtx {
        root_id: actual_id,
        expected_dirs: None,
        own_modules_dir: None,
        guard_nested_git: false,
    };
    delete_dir_contents(
        &admin_handle,
        &verified.admin_dir,
        0,
        &admin_anchor,
        &ctx,
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
            DirOpError::Link(kind) => {
                WorktreeRemoveError::single_link(verified.canonical_root.clone(), kind)
            }
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
        return Err(WorktreeRemoveError::single_link(
            verified.canonical_root.clone(),
            "mount point / bind mount",
        ));
    }
    if actual_id != verified.root_id {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: verified.canonical_root.clone(),
            reason: "worktree root changed identity between verification and removal".to_owned(),
        });
    }
    Ok(handle)
}

struct DeleteCtx<'a> {
    root_id: NodeId,
    expected_dirs: Option<&'a HashMap<PathBuf, NodeId>>,
    own_modules_dir: Option<&'a Path>,
    guard_nested_git: bool,
}

fn delete_dir_contents(
    dir_handle: &DirHandle,
    dir_path: &Path,
    depth: usize,
    ancestors: &[AncestorLink<'_>],
    ctx: &DeleteCtx<'_>,
    skip_root_dot_git: bool,
    removed_any: &mut bool,
) -> Result<(), WorktreeRemoveError> {
    verify_ancestors(ancestors, *removed_any)?;
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
        verify_ancestors(ancestors, *removed_any)?;
        let entry_path = dir_path.join(&name);
        let info = dir_handle.inspect_child(&name).map_err(|err| match err {
            DirOpError::Link(kind) => late_guard_err(
                WorktreeRemoveError::single_link(entry_path.clone(), kind),
                *removed_any,
            ),
            other => WorktreeRemoveError::DeleteFailed {
                path: entry_path.clone(),
                reason: format_dir_op_err(&other),
                partial: *removed_any,
                dot_git_preserved: true,
            },
        })?;
        if let Some(kind) = check_child_guard(&entry_path, info, ctx.root_id)? {
            return Err(late_guard_err(
                WorktreeRemoveError::single_link(entry_path, kind),
                *removed_any,
            ));
        }
        if ctx.guard_nested_git
            && depth > 0
            && name == OsStr::new(".git")
            && let Some(kind) = nested_git_kind(dir_handle, dir_path, info, ctx.own_modules_dir)
        {
            return Err(late_guard_err(
                WorktreeRemoveError::NestedGitRepositories {
                    paths: vec![(dir_path.to_path_buf(), kind.to_owned())],
                    total: 1,
                },
                *removed_any,
            ));
        }
        if info.kind == ChildKind::Dir {
            delete_child_dir_recursive(
                dir_handle,
                &name,
                &entry_path,
                depth + 1,
                info.id,
                ancestors,
                ctx,
                removed_any,
            )?;
        } else {
            dir_handle
                .unlink_child_file(&name, Some(info.id))
                .map_err(|err| {
                    late_guard_err(
                        map_delete_err(err, &entry_path, *removed_any, true),
                        *removed_any,
                    )
                })?;
            *removed_any = true;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn delete_child_dir_recursive(
    parent_handle: &DirHandle,
    name: &OsString,
    entry_path: &Path,
    child_depth: usize,
    inspected_id: NodeId,
    ancestors: &[AncestorLink<'_>],
    ctx: &DeleteCtx<'_>,
    removed_any: &mut bool,
) -> Result<(), WorktreeRemoveError> {
    let expected_id = if let Some(map) = ctx.expected_dirs {
        let Some(&scanned) = map.get(entry_path) else {
            return Err(late_guard_err(
                WorktreeRemoveError::CustodyChanged {
                    path: entry_path.to_path_buf(),
                    reason: "directory appeared after pre-removal scan".to_owned(),
                },
                *removed_any,
            ));
        };
        if scanned != inspected_id {
            return Err(late_guard_err(
                WorktreeRemoveError::CustodyChanged {
                    path: entry_path.to_path_buf(),
                    reason: "directory changed identity between scan and removal".to_owned(),
                },
                *removed_any,
            ));
        }
        scanned
    } else {
        inspected_id
    };

    let child_handle = parent_handle
        .open_child_dir(name)
        .map_err(|err| match err {
            DirOpError::Link(kind) => late_guard_err(
                WorktreeRemoveError::single_link(entry_path.to_path_buf(), kind),
                *removed_any,
            ),
            other => WorktreeRemoveError::DeleteFailed {
                path: entry_path.to_path_buf(),
                reason: format_dir_op_err(&other),
                partial: *removed_any,
                dot_git_preserved: true,
            },
        })?;
    let (actual_id, is_mount_root) = child_handle.stat_self().map_err(|err| {
        late_guard_err(
            WorktreeRemoveError::CustodyChanged {
                path: entry_path.to_path_buf(),
                reason: format!("cannot stat opened directory handle: {err}"),
            },
            *removed_any,
        )
    })?;
    if is_mount_root
        || actual_id.crosses_mount_from(ctx.root_id)
        || live_mountinfo_contains(entry_path, ctx.root_id)?
    {
        return Err(late_guard_err(
            WorktreeRemoveError::single_link(entry_path.to_path_buf(), "mount point / bind mount"),
            *removed_any,
        ));
    }
    if actual_id != expected_id {
        return Err(late_guard_err(
            WorktreeRemoveError::CustodyChanged {
                path: entry_path.to_path_buf(),
                reason: "directory changed identity on open".to_owned(),
            },
            *removed_any,
        ));
    }

    let mut child_ancestors = Vec::with_capacity(ancestors.len() + 1);
    child_ancestors.extend_from_slice(ancestors);
    child_ancestors.push(AncestorLink {
        parent: parent_handle,
        name: name.as_os_str(),
        id: expected_id,
        path: entry_path,
    });
    delete_dir_contents(
        &child_handle,
        entry_path,
        child_depth,
        &child_ancestors,
        ctx,
        false,
        removed_any,
    )?;
    // Close the child handle before unlinking it via its retained parent handle
    // (required on Windows so the directory is not held open during delete).
    drop(child_handle);

    verify_ancestors(&child_ancestors, *removed_any)?;
    parent_handle
        .remove_child_dir(name, Some(expected_id))
        .map_err(|err| {
            late_guard_err(
                map_delete_err(err, entry_path, *removed_any, true),
                *removed_any,
            )
        })?;
    *removed_any = true;
    Ok(())
}
