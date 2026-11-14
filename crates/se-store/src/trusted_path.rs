//! Resolve trusted symlinked ancestors before handing a database path to SQLite.
//!
//! SQLite's `SQLITE_OPEN_NOFOLLOW` refuses every path with a symbolic link
//! component, which breaks the ordinary macOS temp directory where `/var`
//! aliases `/private/var` (SQLite extended code 1550,
//! `SQLITE_CANTOPEN_SYMLINK`). The state-files walk admits exactly one
//! exception: a symlinked ancestor owned by root or by the current user. This
//! module applies that same rule at the open seam: it walks the absolute path
//! component by component, refuses a foreign-owned link with the walk's own
//! verdict, and returns the path with every such link resolved. The final
//! component is never followed: NOFOLLOW still refuses a symlinked database
//! name at open time, and a missing one is still created by the open itself.
//!
//! Windows is exempt: the verbatim form already drops NOFOLLOW under the
//! caller's pin, and the walk rule is a Unix one.
//!
//! Mirror module: the identical rule lives in crates/se-atlas/src/
//! trusted_path.rs. Both files cover the SQLite open seam for trusted link
//! ancestors; a divergence between them is a safety defect, not style.
#[cfg(unix)]
use std::{collections::VecDeque, ffi::OsString, os::unix::fs::MetadataExt, path::Component};
use std::{
    io,
    path::{Path, PathBuf},
};
/// Kernel `SYMLOOP_MAX`: more follows than the kernel itself would take.
#[cfg(unix)]
const MAX_LINK_DEPTH: usize = 40;
/// The path to hand SQLite after admitting its symlinked ancestors.
///
/// A relative path is returned unchanged: the caller owns its working
/// directory, and resolving it here would change which file is opened. An
/// absolute path is walked from the root; a symlinked component is admitted
/// only when root- or current-user-owned, and the returned path resolves
/// every such link. A foreign-owned link refuses with the state-files walk's
/// own verdict.
pub(crate) fn resolve(path: &Path) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        unix_resolve(path)
    }
    #[cfg(not(unix))]
    {
        Ok(path.to_path_buf())
    }
}
#[cfg(unix)]
fn unix_resolve(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        // The caller owns its working directory; resolving it here would
        // change which file SQLite opens.
        return Ok(path.to_path_buf());
    }
    let dot = OsString::from(".");
    let dotdot = OsString::from("..");
    let mut pending: VecDeque<OsString> = VecDeque::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::RootDir => rooted = true,
            Component::Normal(name) => pending.push_back(name.to_os_string()),
            Component::CurDir => pending.push_back(dot.clone()),
            Component::ParentDir => pending.push_back(dotdot.clone()),
            _ => {}
        }
    }
    if !rooted {
        return Ok(path.to_path_buf());
    }
    // SAFETY: geteuid has no pointers and no process-wide mutation.
    let euid = unsafe { libc::geteuid() };
    // Real directory components walked so far, relative to the root.
    let mut resolved: Vec<OsString> = Vec::new();
    let mut links_followed = 0;
    while let Some(component) = pending.pop_front() {
        if component == dot {
            continue;
        }
        if component == dotdot {
            // The root's parent is the root, as in the kernel.
            if !resolved.is_empty() {
                resolved.pop();
            }
            continue;
        }
        if pending.is_empty() {
            // The database name: NOFOLLOW owns it at open time, so it is
            // appended without being probed or followed.
            resolved.push(component);
            continue;
        }
        let probe = join_resolved(&resolved, &component);
        let meta = std::fs::symlink_metadata(&probe)?;
        if meta.file_type().is_symlink() {
            links_followed += 1;
            if links_followed > MAX_LINK_DEPTH {
                return Err(io::Error::other(
                    "too many levels of symbolic links in the database path",
                ));
            }
            if meta.uid() != 0 && meta.uid() != euid {
                return Err(io::Error::other("untrusted or private-directory symlink"));
            }
            let target = std::fs::read_link(&probe)?;
            if target.is_absolute() {
                resolved.clear();
            }
            let mut splice = VecDeque::new();
            for link_component in target.components() {
                match link_component {
                    Component::Normal(name) => splice.push_back(name.to_os_string()),
                    Component::CurDir => splice.push_back(dot.clone()),
                    Component::ParentDir => splice.push_back(dotdot.clone()),
                    Component::RootDir => {}
                    _ => {}
                }
            }
            splice.extend(pending);
            pending = splice;
            continue;
        }
        if !meta.is_dir() {
            return Err(io::Error::other(format!(
                "not a directory: {}",
                probe.display()
            )));
        }
        resolved.push(component);
    }
    let mut out = PathBuf::from("/");
    for part in &resolved {
        out.push(part);
    }
    Ok(out)
}
#[cfg(unix)]
fn join_resolved(resolved: &[OsString], component: &OsString) -> PathBuf {
    let mut probe = PathBuf::from("/");
    for part in resolved.iter().chain(std::iter::once(component)) {
        probe.push(part);
    }
    probe
}

#[cfg(all(test, unix))]
mod tests;
