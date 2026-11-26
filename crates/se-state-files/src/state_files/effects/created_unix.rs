use super::*;
use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

pub(in crate::state_files) struct CreatedDirectory {
    path: PathBuf,
    parent: File,
    name: CString,
    file: File,
    identity: (u64, u64),
}
fn random_name(path: &Path, prefix: &str) -> Result<CString> {
    let nonce = super::super::random(path)?;
    let suffix: String = se_types::hex_lower(&nonce);
    name(std::ffi::OsStr::new(&format!("{prefix}{suffix}")), path)
}
impl CreatedDirectory {
    pub(in crate::state_files) fn path(&self) -> &Path {
        &self.path
    }
    pub(in crate::state_files) fn cleanup(&self) -> Result<DirectoryRemoval> {
        let (parent, _) = creation_parent(&self.path)?;
        if id(&parent, &self.path, true, false)? != id(&self.parent, &self.path, true, false)? {
            return Err(changed(
                "created directory parent was replaced; preserved",
                &self.path,
            ));
        }
        let named = match leaf(&self.parent, &self.name, &self.path, true) {
            Ok(file) => file,
            Err(error) if absent(&error) => return Ok(DirectoryRemoval::AlreadyAbsent),
            Err(error) => return Err(error),
        };
        if id(&named, &self.path, true, true)? != self.identity
            || id(&self.file, &self.path, true, true)? != self.identity
        {
            return Err(changed(
                "created directory identity differs; preserved",
                &self.path,
            ));
        }
        let quarantine = random_name(&self.path, ".se-dir-cleanup-")?;
        move_no_replace(&self.parent, &self.name, &quarantine, &self.path)?;
        let moved = leaf(&self.parent, &quarantine, &self.path, true)?;
        if id(&moved, &self.path, true, true)? != self.identity {
            move_no_replace(&self.parent, &quarantine, &self.name, &self.path)?;
            return Err(changed(
                "created directory changed at cleanup; restored",
                &self.path,
            ));
        }
        // SAFETY: retained trusted parent and exclusive random quarantine name,
        // verified against the exact created directory; no recursive deletion.
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                quarantine.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } < 0
        {
            let cause = io::Error::last_os_error();
            move_no_replace(&self.parent, &quarantine, &self.name, &self.path)?;
            return if matches!(
                cause.raw_os_error(),
                Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
            ) {
                Ok(DirectoryRemoval::NotEmpty)
            } else {
                Err(io_error(
                    "remove retained created directory",
                    &self.path,
                    cause,
                ))
            };
        }
        self.parent
            .sync_all()
            .map_err(|error| io_error("sync created-directory cleanup", &self.path, error))?;
        match leaf(&self.parent, &self.name, &self.path, true) {
            Err(error) if absent(&error) => Ok(DirectoryRemoval::Removed),
            Err(error) => Err(error),
            Ok(_) => Err(changed(
                "directory pathname reappeared after cleanup; preserved",
                &self.path,
            )),
        }
    }
}
pub(in crate::state_files) fn prepare_created_directory(
    path: &Path,
    created: &mut Vec<CreatedDirectory>,
) -> Result<()> {
    let (parent, target) = creation_parent(path)?;
    // Inspect the actual named entry first: a trusted system-ancestor symlink
    // is the owning walk's to resolve under the same ownership rule, and it
    // must not be mistaken for an owned child. A foreign link refuses here with
    // the walk's own verdict instead of the leaf's.
    // SAFETY: initialized no-follow stat output, retained parent, literal name.
    let mut entry: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the same no-follow entry query into the initialized stat above.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            target.as_ptr(),
            &mut entry,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
        && entry.st_mode & libc::S_IFMT == libc::S_IFLNK
    {
        // SAFETY: geteuid has no pointers or process-wide mutation.
        if entry.st_uid != 0 && entry.st_uid != unsafe { libc::geteuid() } {
            return Err(unsafe_path("untrusted or private-directory symlink", path));
        }
        return Ok(());
    }
    // Each preparation component is only an anchor. Its caller separately
    // requires a readable final root; new staging objects still use leaf().
    match super::super::open_component(parent.as_raw_fd(), &target, false, path, false) {
        Ok(file) => return trusted_directory(&file, path, false),
        Err(error) if absent(&error) => (),
        Err(error) => return Err(error),
    }
    let staging = random_name(path, ".se-dir-stage-")?;
    // SAFETY: exclusive random private directory beneath the retained trusted
    // parent. The final name is published only after opening this staging object.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), staging.as_ptr(), 0o700) } < 0 {
        return Err(io_error(
            "create unpublished directory staging",
            path,
            io::Error::last_os_error(),
        ));
    }
    let stage_path = path.with_file_name(std::ffi::OsStr::from_bytes(staging.to_bytes()));
    let file = leaf(&parent, &staging, &stage_path, true)?;
    let identity = id(&file, &stage_path, true, true)?;
    // Creation mode is masked by the caller's umask. Publish only after an
    // explicit handle-based 0700 update and a native metadata readback.
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|error| io_error("protect created staging directory", &stage_path, error))?;
    #[cfg(target_os = "macos")]
    super::super::clear_created_acl(&file, &stage_path, true)?;
    let stat = file
        .metadata()
        .map_err(|error| io_error("inspect created staging directory", path, error))?;
    if stat.mode() & 0o777 != 0o700 {
        return Err(unsafe_path(
            "created directory staging is not private",
            path,
        ));
    }
    file.sync_all()
        .map_err(|error| io_error("flush private directory staging", path, error))?;
    if let Err(error) = move_no_replace(&parent, &staging, &target, path) {
        let stage_path = path.with_file_name(std::ffi::OsStr::from_bytes(staging.to_bytes()));
        let custody = CreatedDirectory {
            path: stage_path,
            parent,
            name: staging,
            file,
            identity,
        };
        match custody.cleanup() {
            Ok(DirectoryRemoval::Removed | DirectoryRemoval::AlreadyAbsent) => (),
            Ok(DirectoryRemoval::NotEmpty) => {
                created.push(custody);
                return Err(error);
            }
            Err(cleanup) => {
                created.push(custody);
                return Err(cleanup);
            }
        }
        if error
            .source
            .as_ref()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::AlreadyExists)
        {
            return Ok(());
        }
        return Err(error);
    }
    let custody = CreatedDirectory {
        path: path.into(),
        parent,
        name: target,
        file,
        identity,
    };
    created.push(custody);
    let held = created
        .last()
        .ok_or_else(|| changed("created directory custody unavailable", path))?;
    let outside = leaf(&held.parent, &held.name, path, true)?;
    if id(&outside, path, true, true)? != held.identity {
        return Err(changed(
            "created directory publication identity differs",
            path,
        ));
    }
    held.parent
        .sync_all()
        .map_err(|error| io_error("flush created directory publication", path, error))
}

fn creation_parent(path: &Path) -> Result<(File, CString)> {
    components(path)?;
    let directory = path
        .parent()
        .ok_or_else(|| unsafe_path("directory parent missing", path))?;
    let leaf_name = path
        .file_name()
        .ok_or_else(|| unsafe_path("directory leaf missing", path))?;
    Ok((
        super::super::walk_effect_parent_for_creation(directory)?,
        name(leaf_name, path)?,
    ))
}

pub(in crate::state_files) fn validate_creation_target(path: &Path) -> Result<()> {
    let (parent, name) = creation_parent(path)?;
    let file = leaf(&parent, &name, path, true)?;
    id(&file, path, true, true)?;
    trusted_directory(&file, path, true)
}

/// Ensure a user-owned external directory hierarchy exists without forcing
/// `0700` on shared user directories (such as provider config homes).
/// Walks from `/` by directory fd and verifies ownership/trust on intermediate
/// and final directories.
pub(in crate::state_files) fn ensure_user_directory(path: &Path) -> Result<()> {
    let parts = components(path)?;
    let mut current = owned(
        // SAFETY: literal root pathname with O_RDONLY | O_DIRECTORY | O_CLOEXEC.
        unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        },
        "open filesystem root",
        Path::new("/"),
    )?;
    let mut traversed = PathBuf::from("/");
    for (index, part) in parts.iter().enumerate() {
        traversed.push(part);
        let leaf = name(part, &traversed)?;
        let final_component = index + 1 == parts.len();
        let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        if final_component {
            flags |= libc::O_NOFOLLOW;
        }
        // SAFETY: held parent directory fd and literal NUL-terminated component.
        let raw = unsafe { libc::openat(current.as_raw_fd(), leaf.as_ptr(), flags) };
        let next = if raw < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::NotFound {
                return Err(io_error("open user directory component", &traversed, err));
            }
            // SAFETY: held parent directory fd and literal NUL-terminated component.
            if unsafe { libc::mkdirat(current.as_raw_fd(), leaf.as_ptr(), 0o755) } < 0 {
                let mk_err = io::Error::last_os_error();
                if mk_err.kind() != io::ErrorKind::AlreadyExists {
                    return Err(io_error("create user directory", &traversed, mk_err));
                }
            }
            owned(
                // SAFETY: reopen newly created component without following symlinks.
                unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        leaf.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                },
                "open created user directory",
                &traversed,
            )?
        } else {
            // SAFETY: successful openat transferred unique ownership of `raw`.
            owned(raw, "open user directory component", &traversed)?
        };
        trusted_directory(&next, &traversed, final_component)?;
        current = next;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn try_create_tmpfile_and_publish(
    parent_dir: &File,
    leaf: &std::ffi::CStr,
    path: &Path,
    dir: &Path,
    bytes: &[u8],
) -> Result<bool> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let dot = c".";
    // SAFETY: held parent directory fd and literal "." with O_TMPFILE creates
    // an unlinked anonymous regular file that no other writer can swap by name.
    let raw = unsafe {
        libc::openat(
            parent_dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        let err = io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::EISDIR | libc::EINVAL | libc::ENOSYS | libc::EACCES)
        ) {
            return Ok(false);
        }
        return Err(io_error("create anonymous staged user file", path, err));
    }
    let mut file = owned(raw, "create anonymous staged user file", path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| io_error("write new user file", path, e))?;
    // Best-effort fchmod before linkat so mode is 0600 before publication even
    // under a restrictive umask; older Linux kernels (< 6.6) may return
    // EINVAL/EOPNOTSUPP on unlinked O_TMPFILE fds, so enforce after linkat too.
    let pre_chmod_ok = match file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => true,
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOENT)
            ) =>
        {
            false
        }
        Err(err) => return Err(io_error("protect staged user file", path, err)),
    };
    let proc_fd = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| unsafe_path("invalid proc fd path", path))?;
    // SAFETY: links the exact held open inode into (parent_dir, leaf) without
    // replacement (fails with EEXIST if leaf exists).
    let linked = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            proc_fd.as_ptr(),
            parent_dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if linked < 0 {
        let err = io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::EXDEV)) {
            return Ok(false);
        }
        return Err(io_error("publish new user file", path, err));
    }
    if !pre_chmod_ok {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io_error("protect published user file", path, e))?;
    }
    drop(file);
    parent_dir
        .sync_all()
        .map_err(|e| io_error("sync user file parent", dir, e))?;
    Ok(true)
}

fn create_direct_exclusive(
    parent_dir: &File,
    leaf: &std::ffi::CStr,
    path: &Path,
    dir: &Path,
    bytes: &[u8],
) -> Result<()> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    // Exclusively create the target directly without staging directories or
    // name-based AT_REMOVEDIR cleanup in a potentially shared parent folder.
    // O_CREAT|O_EXCL|O_NOFOLLOW atomically refuses existing files and symlinks,
    // and returns a writable fd even under a restrictive umask (e.g. 0777).
    let mut file = owned(
        // SAFETY: held verified parent_dir fd and literal NUL-terminated leaf.
        unsafe {
            libc::openat(
                parent_dir.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        },
        "create new user file",
        path,
    )?;
    let _ = id(&file, path, false, true)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| {
            io_error(
                "protect new user file (newly created file was left in place)",
                path,
                e,
            )
        })?;
    #[cfg(target_os = "macos")]
    super::super::clear_created_acl(&file, path, false)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            io_error(
                "write new user file (newly created file may be incomplete and was left in place)",
                path,
                e,
            )
        })?;
    drop(file);
    parent_dir
        .sync_all()
        .map_err(|e| io_error("sync user file parent after create", dir, e))
}

/// Exclusively create a new regular file in a user-owned external directory
/// without requiring `0700` on the parent directory. Validates the destination
/// before creating, uses `O_TMPFILE` + `linkat` on Linux when supported and
/// direct `O_CREAT|O_EXCL|O_NOFOLLOW` otherwise (avoiding staging directories
/// or name-based `AT_REMOVEDIR` in a shared parent), and always syncs the parent.
pub(in crate::state_files) fn create_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| unsafe_path("cannot create file at filesystem root", path))?;
    ensure_user_directory(dir)?;
    let (parent_dir, leaf) = parent(path)?;
    #[cfg(target_os = "linux")]
    if try_create_tmpfile_and_publish(&parent_dir, &leaf, path, dir, bytes)? {
        return Ok(());
    }
    create_direct_exclusive(&parent_dir, &leaf, path, dir, bytes)
}
