use super::{WorkspaceWriteError, WorkspaceWriteRefusal, stage_name};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
};

fn invalid(reason: impl Into<String>) -> WorkspaceWriteError {
    WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(reason.into()))
}

fn io_before(error: io::Error) -> WorkspaceWriteError {
    WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(error))
}

fn cstr(part: &str) -> Result<CString, WorkspaceWriteError> {
    CString::new(part).map_err(|_| invalid("path component contains a NUL byte"))
}

fn owned(fd: libc::c_int) -> Result<File, io::Error> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native openat returned a uniquely owned file descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn lstat_at(parent: &File, name: &CStr) -> Result<Option<libc::stat>, io::Error> {
    // SAFETY: POD stat output zero-initialized before fstatat populates it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: retained directory fd, NUL-terminated leaf, AT_SYMLINK_NOFOLLOW.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err);
    }
    Ok(Some(st))
}

fn stat_dev(st: &libc::stat) -> u64 {
    #[cfg(target_os = "macos")]
    {
        st.st_dev as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        st.st_dev
    }
}

fn dot_git_id(parent: &File) -> Result<Option<(u64, u64)>, WorkspaceWriteError> {
    let st = lstat_at(parent, c".git").map_err(io_before)?;
    Ok(st.map(|s| (stat_dev(&s), s.st_ino)))
}

fn open_dir_nofollow(parent: &File, name: &CString) -> Result<File, io::Error> {
    // SAFETY: retained directory fd and NUL-terminated component; O_NOFOLLOW
    // rejects symlinks and O_DIRECTORY rejects non-directories.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned(fd)
}

fn open_or_create_dir(
    parent: &File,
    part: &str,
    root_dev: u64,
) -> Result<File, WorkspaceWriteError> {
    if part.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path enters .git metadata, which StateEngine does not write",
        ));
    }
    let dot_git = dot_git_id(parent)?;
    let name = cstr(part)?;
    let child = match open_dir_nofollow(parent, &name) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // SAFETY: retained directory fd and NUL-terminated literal name.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } < 0 {
                let mk_err = io::Error::last_os_error();
                if mk_err.kind() != io::ErrorKind::AlreadyExists {
                    return Err(io_before(mk_err));
                }
            } else {
                // Sync the containing directory so the newly created ancestor
                // entry is durable before descending into it.
                parent.sync_all().map_err(io_before)?;
            }
            open_dir_nofollow(parent, &name).map_err(map_open_error)?
        }
        Err(err) => return Err(map_open_error(err)),
    };
    let meta = child.metadata().map_err(io_before)?;
    if !meta.is_dir() {
        return Err(invalid("parent component is not a directory"));
    }
    if meta.dev() != root_dev {
        return Err(invalid(
            "path crosses a filesystem mount boundary inside the workspace",
        ));
    }
    if dot_git == Some((meta.dev(), meta.ino())) {
        return Err(invalid(
            "path aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok(child)
}

fn map_open_error(err: io::Error) -> WorkspaceWriteError {
    match err.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => invalid(format!(
            "component is a symbolic link or not a directory: {err}"
        )),
        _ => io_before(err),
    }
}

fn inspect_target_leaf(
    parent: &File,
    leaf: &CString,
    root_dev: u64,
    dot_git: Option<(u64, u64)>,
) -> Result<Option<libc::mode_t>, WorkspaceWriteError> {
    let Some(st) = lstat_at(parent, leaf).map_err(io_before)? else {
        return Ok(None);
    };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(invalid(
            "target exists and is not a regular file (links, directories and devices are refused)",
        ));
    }
    let dev = stat_dev(&st);
    if dev != root_dev {
        return Err(invalid(
            "target crosses a filesystem mount boundary inside the workspace",
        ));
    }
    if dot_git == Some((dev, st.st_ino)) {
        return Err(invalid(
            "target aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok(Some(st.st_mode & 0o777))
}

fn cleanup_stage(parent: &File, stage: &CString) {
    // SAFETY: retained parent directory fd and our unique O_EXCL staging name.
    let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), stage.as_ptr(), 0) };
}

pub(super) fn write_relative(
    root: &File,
    path: &str,
    bytes: &[u8],
) -> Result<(), WorkspaceWriteError> {
    let root_dev = root.metadata().map_err(io_before)?.dev();
    let (parent_prefix, leaf_str) = match path.rsplit_once('/') {
        Some((prefix, leaf)) => (Some(prefix), leaf),
        None => (None, path),
    };
    if leaf_str.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path targets .git metadata, which StateEngine does not write",
        ));
    }
    let mut held: Option<File> = None;
    if let Some(prefix) = parent_prefix {
        for part in prefix.split('/') {
            let parent = held.as_ref().unwrap_or(root);
            held = Some(open_or_create_dir(parent, part, root_dev)?);
        }
    }
    let parent = held.as_ref().unwrap_or(root);
    let dot_git = dot_git_id(parent)?;
    let leaf = cstr(leaf_str)?;
    let existing_mode = inspect_target_leaf(parent, &leaf, root_dev, dot_git)?;

    let stage_str = stage_name()?;
    let stage_cstr = cstr(&stage_str)?;
    let mode: libc::c_uint = existing_mode.map_or(0o600, u32::from);
    // SAFETY: retained parent directory fd, exclusive random staging name,
    // O_NOFOLLOW | O_EXCL | O_CLOEXEC.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            stage_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    let mut stage = owned(raw).map_err(io_before)?;
    let prepare = (|| -> Result<(), WorkspaceWriteError> {
        if let Some(existing_mode) = existing_mode {
            // Preserve the replaced file's exact mode without umask masking.
            // SAFETY: uniquely owned staging file descriptor and masked mode bits.
            if unsafe { libc::fchmod(stage.as_raw_fd(), existing_mode) } < 0 {
                return Err(io_before(io::Error::last_os_error()));
            }
        }
        stage.write_all(bytes).map_err(io_before)?;
        stage.sync_all().map_err(io_before)?;
        Ok(())
    })();
    drop(stage);
    if let Err(error) = prepare {
        cleanup_stage(parent, &stage_cstr);
        return Err(error);
    }

    // Re-inspect leaf right before renameat so a concurrent symlink/dir/mount
    // replacement is refused before publication.
    if let Err(error) = inspect_target_leaf(parent, &leaf, root_dev, dot_git) {
        cleanup_stage(parent, &stage_cstr);
        return Err(error);
    }

    // SAFETY: retained parent directory fd and two NUL-terminated literal names
    // in that same directory; atomic replacement without following symlinks.
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            stage_cstr.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        cleanup_stage(parent, &stage_cstr);
        return Err(io_before(err));
    }

    // File is now published; any failure from here on is PublishedUncertain.
    parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after publication: {error}"
        ))
    })?;
    Ok(())
}
