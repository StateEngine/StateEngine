//! Non-following link/junction/mount guard, retained filesystem custody, and
//! bottom-up deletion for [`crate::worktree::remove_worktree`].
use crate::worktree::{VerifiedWorktree, WorktreeRemoveError};
#[cfg(windows)]
use std::io::ErrorKind;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Maximum offending paths retained per category in a refusal report.
const MAX_REPORTED_PATHS: usize = 64;

/// Retained filesystem identity used to detect concurrent swaps between
/// validation, scan, deletion, and metadata pruning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NodeIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    file_attributes: u32,
    #[cfg(windows)]
    file_size: u64,
}

impl NodeIdentity {
    pub(crate) fn from_meta(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                dev: meta.dev(),
                ino: meta.ino(),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            Self {
                creation_time: meta.creation_time(),
                file_attributes: meta.file_attributes(),
                file_size: meta.file_size(),
            }
        }
    }
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

/// On Linux, collect any mount points (including same-filesystem bind mounts)
/// at or inside `canonical_root` from `/proc/self/mountinfo`.
pub(crate) fn collect_mount_points(
    canonical_root: &Path,
) -> Result<HashSet<PathBuf>, WorktreeRemoveError> {
    #[cfg(target_os = "linux")]
    {
        let content = fs::read_to_string("/proc/self/mountinfo").map_err(|err| {
            WorktreeRemoveError::Unreadable {
                entries: vec![(PathBuf::from("/proc/self/mountinfo"), err.to_string())],
                total: 1,
            }
        })?;
        Ok(parse_linux_mountinfo(&content, canonical_root))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = canonical_root;
        Ok(HashSet::new())
    }
}

/// Parse `/proc/self/mountinfo` lines and return mount points at or below `root`.
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

/// Non-following pre-removal walk over `verified.canonical_root`. Never
/// descends into symlinks, Windows junctions/reparse points, or Unix mounts.
pub(crate) fn scan_tree_for_links(
    verified: &VerifiedWorktree,
    mount_points: &HashSet<PathBuf>,
) -> Result<HashMap<PathBuf, NodeIdentity>, WorktreeRemoveError> {
    if mount_points.contains(&verified.canonical_root) {
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
    let mut findings = WalkFindings::new();
    let mut identities = HashMap::new();
    identities.insert(verified.canonical_root.clone(), verified.root_identity);
    let mut stack = vec![verified.canonical_root.clone()];
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
            if let Some(kind) = entry_guard_violation(&entry_path, &meta, verified, mount_points) {
                findings.record_link(entry_path, kind.to_owned());
                continue;
            }
            if meta.is_dir() {
                identities.insert(entry_path.clone(), NodeIdentity::from_meta(&meta));
                stack.push(entry_path);
            }
        }
    }
    findings.into_result()?;
    Ok(identities)
}

fn entry_guard_violation(
    path: &Path,
    meta: &fs::Metadata,
    verified: &VerifiedWorktree,
    mount_points: &HashSet<PathBuf>,
) -> Option<&'static str> {
    if let Some(kind) = link_or_reparse_kind(meta) {
        return Some(kind);
    }
    if mount_points.contains(path) {
        return Some("mount point / bind mount");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != verified.root_dev {
            return Some("mount point (cross-device boundary)");
        }
    }
    #[cfg(not(unix))]
    let _ = verified;
    None
}

fn verify_custody(
    path: &Path,
    expected: NodeIdentity,
    verified: &VerifiedWorktree,
    mount_points: &HashSet<PathBuf>,
) -> Result<(), WorktreeRemoveError> {
    let meta = fs::symlink_metadata(path).map_err(|err| WorktreeRemoveError::CustodyChanged {
        path: path.to_path_buf(),
        reason: format!("cannot re-verify entry identity: {err}"),
    })?;
    if let Some(kind) = entry_guard_violation(path, &meta, verified, mount_points) {
        return Err(WorktreeRemoveError::LinksDetected {
            links: vec![(path.to_path_buf(), kind.to_owned())],
            total_links: 1,
            unreadable: Vec::new(),
            total_unreadable: 0,
        });
    }
    if NodeIdentity::from_meta(&meta) != expected {
        return Err(WorktreeRemoveError::CustodyChanged {
            path: path.to_path_buf(),
            reason: "entry identity changed between verification and removal".to_owned(),
        });
    }
    Ok(())
}

/// Bottom-up non-following directory deletion. Re-verifies retained directory
/// custody before every mutation and deletes the root `.git` file LAST so any
/// partial failure leaves the worktree verifiable and retryable.
pub(crate) fn remove_tree_no_follow(
    verified: &VerifiedWorktree,
    dir_identities: &HashMap<PathBuf, NodeIdentity>,
    mount_points: &HashSet<PathBuf>,
) -> Result<(), WorktreeRemoveError> {
    enum Step {
        Enter(PathBuf),
        RemoveDir(PathBuf),
    }
    let root = &verified.canonical_root;
    let dot_git = root.join(".git");
    let mut removed_any = false;
    let mut stack = vec![Step::Enter(root.clone())];

    while let Some(step) = stack.pop() {
        match step {
            Step::Enter(dir) => {
                let expected = dir_identities.get(&dir).copied().ok_or_else(|| {
                    WorktreeRemoveError::CustodyChanged {
                        path: dir.clone(),
                        reason: "directory appeared after pre-removal scan".to_owned(),
                    }
                })?;
                verify_custody(&dir, expected, verified, mount_points)?;
                if dir != *root {
                    stack.push(Step::RemoveDir(dir.clone()));
                }
                let entries =
                    fs::read_dir(&dir).map_err(|err| WorktreeRemoveError::DeleteFailed {
                        path: dir.clone(),
                        reason: err.to_string(),
                        partial: removed_any,
                        dot_git_preserved: true,
                    })?;
                for entry_res in entries {
                    let entry = entry_res.map_err(|err| WorktreeRemoveError::DeleteFailed {
                        path: dir.clone(),
                        reason: err.to_string(),
                        partial: removed_any,
                        dot_git_preserved: true,
                    })?;
                    let entry_path = entry.path();
                    if entry_path == dot_git {
                        continue;
                    }
                    let meta = fs::symlink_metadata(&entry_path).map_err(|err| {
                        WorktreeRemoveError::DeleteFailed {
                            path: entry_path.clone(),
                            reason: err.to_string(),
                            partial: removed_any,
                            dot_git_preserved: true,
                        }
                    })?;
                    if let Some(kind) =
                        entry_guard_violation(&entry_path, &meta, verified, mount_points)
                    {
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
                        remove_regular_file(&entry_path, &meta, removed_any, true)?;
                        removed_any = true;
                    }
                }
            }
            Step::RemoveDir(dir) => {
                let expected = dir_identities.get(&dir).copied().ok_or_else(|| {
                    WorktreeRemoveError::CustodyChanged {
                        path: dir.clone(),
                        reason: "directory lacks verified scan custody".to_owned(),
                    }
                })?;
                verify_custody(&dir, expected, verified, mount_points)?;
                remove_empty_dir(&dir, removed_any, true)?;
                removed_any = true;
            }
        }
    }

    verify_custody(root, verified.root_identity, verified, mount_points)?;
    verify_custody(&dot_git, verified.dot_git_identity, verified, mount_points)?;
    let dot_git_meta =
        fs::symlink_metadata(&dot_git).map_err(|err| WorktreeRemoveError::DeleteFailed {
            path: dot_git.clone(),
            reason: err.to_string(),
            partial: removed_any,
            dot_git_preserved: true,
        })?;
    remove_regular_file(&dot_git, &dot_git_meta, removed_any, true)?;
    remove_empty_dir(root, true, false)?;
    Ok(())
}

fn remove_regular_file(
    path: &Path,
    meta: &fs::Metadata,
    partial: bool,
    dot_git_preserved: bool,
) -> Result<(), WorktreeRemoveError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            clear_windows_readonly(path, meta);
            fs::remove_file(path).map_err(|retry_err| WorktreeRemoveError::DeleteFailed {
                path: path.to_path_buf(),
                reason: retry_err.to_string(),
                partial,
                dot_git_preserved,
            })
        }
        Err(err) => {
            let _ = meta;
            Err(WorktreeRemoveError::DeleteFailed {
                path: path.to_path_buf(),
                reason: err.to_string(),
                partial,
                dot_git_preserved,
            })
        }
    }
}

fn remove_empty_dir(
    path: &Path,
    partial: bool,
    dot_git_preserved: bool,
) -> Result<(), WorktreeRemoveError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            if let Ok(meta) = fs::symlink_metadata(path)
                && link_or_reparse_kind(&meta).is_none()
            {
                clear_windows_readonly(path, &meta);
            }
            fs::remove_dir(path).map_err(|retry_err| WorktreeRemoveError::DeleteFailed {
                path: path.to_path_buf(),
                reason: retry_err.to_string(),
                partial,
                dot_git_preserved,
            })
        }
        Err(err) => Err(WorktreeRemoveError::DeleteFailed {
            path: path.to_path_buf(),
            reason: err.to_string(),
            partial,
            dot_git_preserved,
        }),
    }
}

/// Strictly Windows-only read-only attribute clear on already-verified non-link
/// custody. Unix never modifies permissions during deletion.
#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn clear_windows_readonly(path: &Path, meta: &fs::Metadata) {
    let mut perms = meta.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
}

/// Returns a human-readable kind when `meta` is a symbolic link or (on Windows)
/// any reparse point (directory junction, volume mount point, symlink, etc.).
pub(crate) fn link_or_reparse_kind(meta: &fs::Metadata) -> Option<&'static str> {
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
