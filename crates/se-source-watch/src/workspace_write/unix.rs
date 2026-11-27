use super::{WorkspaceWriteError, WorkspaceWriteRefusal, stage_name};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
};

#[path = "unix_replace.rs"]
mod replace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MountIdentity {
    dev: u64,
    #[cfg(target_os = "linux")]
    mnt_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryMeta {
    dev: u64,
    ino: u64,
    mode: libc::mode_t,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    #[cfg(target_os = "linux")]
    mnt_id: Option<u64>,
    #[cfg(target_os = "linux")]
    is_mount_root: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetBaseline {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    mode: libc::mode_t,
}

impl TargetBaseline {
    fn from_meta(meta: EntryMeta) -> Self {
        Self {
            dev: meta.dev,
            ino: meta.ino,
            size: meta.size,
            mtime_sec: meta.mtime_sec,
            mtime_nsec: meta.mtime_nsec,
            mode: meta.mode & 0o777,
        }
    }
}

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
    // SAFETY: successful native open returned a uniquely owned file descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn stat_entry_at(
    parent: &File,
    name: &CStr,
    flags: libc::c_int,
) -> Result<Option<EntryMeta>, io::Error> {
    // SAFETY: POD statx output zero-initialized before statx populates it.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let mask = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
    // SAFETY: retained fd, NUL-terminated leaf or empty path, valid flags and buffer.
    if unsafe { libc::statx(parent.as_raw_fd(), name.as_ptr(), flags, mask, &mut stx) } < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err);
    }
    let dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor);
    let mnt_id = (stx.stx_mask & libc::STATX_MNT_ID != 0).then_some(stx.stx_mnt_id);
    let is_mount_root = (stx.stx_attributes_mask & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0)
        && (stx.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0);
    Ok(Some(EntryMeta {
        dev,
        ino: stx.stx_ino,
        mode: libc::mode_t::from(stx.stx_mode),
        size: stx.stx_size,
        mtime_sec: stx.stx_mtime.tv_sec,
        mtime_nsec: i64::from(stx.stx_mtime.tv_nsec),
        mnt_id,
        is_mount_root,
    }))
}

#[cfg(not(target_os = "linux"))]
fn stat_entry_at(
    parent: &File,
    name: &CStr,
    flags: libc::c_int,
) -> Result<Option<EntryMeta>, io::Error> {
    // SAFETY: POD stat output zero-initialized before fstatat populates it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: retained directory fd, NUL-terminated leaf, valid flags.
    if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), &mut st, flags) } < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err);
    }
    #[cfg(target_os = "macos")]
    let dev = st.st_dev as u64;
    #[cfg(not(target_os = "macos"))]
    let dev = st.st_dev;
    Ok(Some(EntryMeta {
        dev,
        ino: st.st_ino,
        mode: st.st_mode,
        size: st.st_size as u64,
        mtime_sec: st.st_mtime,
        mtime_nsec: st.st_mtime_nsec,
    }))
}

fn stat_fd(file: &File) -> Result<EntryMeta, io::Error> {
    #[cfg(target_os = "linux")]
    {
        stat_entry_at(file, c"", libc::AT_EMPTY_PATH)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "open handle disappeared"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: POD stat output zero-initialized before fstat populates it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: valid open file descriptor.
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "macos")]
        let dev = st.st_dev as u64;
        #[cfg(not(target_os = "macos"))]
        let dev = st.st_dev;
        Ok(EntryMeta {
            dev,
            ino: st.st_ino,
            mode: st.st_mode,
            size: st.st_size as u64,
            mtime_sec: st.st_mtime,
            mtime_nsec: st.st_mtime_nsec,
        })
    }
}

fn root_mount_identity(root: &File) -> Result<MountIdentity, WorkspaceWriteError> {
    let meta = stat_fd(root).map_err(io_before)?;
    Ok(MountIdentity {
        dev: meta.dev,
        #[cfg(target_os = "linux")]
        mnt_id: meta.mnt_id,
    })
}

fn verify_same_mount(
    meta: EntryMeta,
    root_mount: MountIdentity,
    subject: &str,
) -> Result<(), WorkspaceWriteError> {
    if meta.dev != root_mount.dev {
        return Err(invalid(format!(
            "{subject} crosses a filesystem mount boundary inside the workspace"
        )));
    }
    #[cfg(target_os = "linux")]
    {
        if meta.is_mount_root {
            return Err(invalid(format!(
                "{subject} crosses a mount point inside the workspace"
            )));
        }
        if let Some(root_mnt_id) = root_mount.mnt_id
            && meta.mnt_id != Some(root_mnt_id)
        {
            return Err(invalid(format!(
                "{subject} crosses a same-device mount boundary inside the workspace"
            )));
        }
    }
    Ok(())
}

fn dot_git_id(parent: &File) -> Result<Option<(u64, u64)>, WorkspaceWriteError> {
    let st = stat_entry_at(parent, c".git", libc::AT_SYMLINK_NOFOLLOW).map_err(io_before)?;
    Ok(st.map(|s| (s.dev, s.ino)))
}

fn open_dir_nofollow(parent: &File, name: &CString) -> Result<File, io::Error> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: POD open_how zero-initialized before setting known fields.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags =
            (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
        how.mode = 0;
        how.resolve = libc::RESOLVE_NO_XDEV | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_BENEATH;
        // SAFETY: retained directory fd, NUL-terminated component, exact open_how layout.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd >= 0 {
            return owned(fd as libc::c_int);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOSYS) {
            return Err(err);
        }
    }
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
    root_mount: MountIdentity,
) -> Result<(File, (u64, u64)), WorkspaceWriteError> {
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
    let meta = stat_fd(&child).map_err(io_before)?;
    if (meta.mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(invalid("parent component is not a directory"));
    }
    verify_same_mount(meta, root_mount, "path")?;
    if dot_git == Some((meta.dev, meta.ino)) {
        return Err(invalid(
            "path aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok((child, (meta.dev, meta.ino)))
}

fn map_open_error(err: io::Error) -> WorkspaceWriteError {
    match err.raw_os_error() {
        Some(libc::EXDEV) => invalid("path crosses a mount boundary inside the workspace"),
        Some(libc::ELOOP | libc::ENOTDIR) => invalid(format!(
            "component is a symbolic link or not a directory: {err}"
        )),
        _ => io_before(err),
    }
}

/// Re-walk the admitted ancestor chain from `root` to prove the held parent
/// directory has not been moved out of the workspace or replaced.
fn verify_parent_chain(
    root: &File,
    chain: &[(&str, File, (u64, u64))],
    root_mount: MountIdentity,
) -> Result<(), WorkspaceWriteError> {
    let mut cursor: Option<File> = None;
    for (part, _, expected_id) in chain {
        let parent = cursor.as_ref().unwrap_or(root);
        let name = cstr(part)?;
        let fresh = open_dir_nofollow(parent, &name).map_err(|err| {
            invalid(format!(
                "workspace parent directory changed during write: {err}"
            ))
        })?;
        let meta = stat_fd(&fresh).map_err(io_before)?;
        verify_same_mount(meta, root_mount, "parent directory")?;
        if (meta.dev, meta.ino) != *expected_id {
            return Err(invalid(
                "workspace parent directory was moved or replaced during write",
            ));
        }
        cursor = Some(fresh);
    }
    Ok(())
}

fn inspect_target_leaf(
    parent: &File,
    leaf: &CString,
    root_mount: MountIdentity,
    dot_git: Option<(u64, u64)>,
) -> Result<Option<TargetBaseline>, WorkspaceWriteError> {
    let Some(meta) = stat_entry_at(parent, leaf, libc::AT_SYMLINK_NOFOLLOW).map_err(io_before)?
    else {
        return Ok(None);
    };
    if (meta.mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(invalid(
            "target exists and is not a regular file (links, directories and devices are refused)",
        ));
    }
    verify_same_mount(meta, root_mount, "target")?;
    if dot_git == Some((meta.dev, meta.ino)) {
        return Err(invalid(
            "target aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok(Some(TargetBaseline::from_meta(meta)))
}

fn verify_target_unchanged(
    parent: &File,
    leaf: &CString,
    root_mount: MountIdentity,
    dot_git: Option<(u64, u64)>,
    baseline: Option<TargetBaseline>,
) -> Result<(), WorkspaceWriteError> {
    let current = inspect_target_leaf(parent, leaf, root_mount, dot_git)?;
    match (baseline, current) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(io_before(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "target file was created concurrently during staging",
        ))),
        (Some(_), None) => Err(invalid(
            "target file was removed concurrently during staging",
        )),
        (Some(expected), Some(actual)) => {
            if expected != actual {
                return Err(invalid(
                    "target file changed concurrently during staging; retry write",
                ));
            }
            Ok(())
        }
    }
}

fn publish_exclusive(
    parent: &File,
    stage: &CString,
    leaf: &CString,
) -> Result<(), WorkspaceWriteError> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: retained parent directory fd and two NUL-terminated literal
        // names in that directory; RENAME_NOREPLACE refuses overwriting a
        // concurrently created target.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                stage.as_ptr(),
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if !replace::is_rename_flag_unsupported(&err) {
            return Err(io_before(err));
        }
    }
    // SAFETY: retained parent directory fd and literal names; linkat fails
    // atomically with EEXIST if another writer created `leaf`.
    if unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            leaf.as_ptr(),
            0,
        )
    } < 0
    {
        return Err(io_before(io::Error::last_os_error()));
    }
    // `leaf` is now published; unlink the staging alias.
    // SAFETY: retained parent directory fd and our unique O_EXCL staging name.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), stage.as_ptr(), 0) } < 0 {
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "target published but staging cleanup failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn cleanup_stage(parent: &File, stage: &CString) {
    // SAFETY: retained parent directory fd and our unique O_EXCL staging name.
    let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), stage.as_ptr(), 0) };
}

fn stage_file(
    parent: &File,
    stage_cstr: &CString,
    bytes: &[u8],
    baseline: Option<TargetBaseline>,
) -> Result<TargetBaseline, WorkspaceWriteError> {
    let mode: libc::c_uint = baseline.map_or(0o666, |b| {
        #[cfg(target_os = "macos")]
        {
            u32::from(b.mode)
        }
        #[cfg(not(target_os = "macos"))]
        {
            b.mode
        }
    });
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
    let prepare = (|| -> Result<TargetBaseline, WorkspaceWriteError> {
        if let Some(baseline) = baseline {
            // Preserve the replaced file's exact mode without umask masking.
            // SAFETY: uniquely owned staging file descriptor and masked mode bits.
            if unsafe { libc::fchmod(stage.as_raw_fd(), baseline.mode) } < 0 {
                return Err(io_before(io::Error::last_os_error()));
            }
        }
        stage.write_all(bytes).map_err(io_before)?;
        stage.sync_all().map_err(io_before)?;
        let meta = stat_fd(&stage).map_err(io_before)?;
        Ok(TargetBaseline::from_meta(meta))
    })();
    drop(stage);
    match prepare {
        Ok(staged) => Ok(staged),
        Err(error) => {
            cleanup_stage(parent, stage_cstr);
            Err(error)
        }
    }
}

pub(super) fn write_relative(
    root: &File,
    _root_path: &std::path::Path,
    path: &str,
    bytes: &[u8],
    root_check: &dyn Fn() -> io::Result<()>,
) -> Result<(), WorkspaceWriteError> {
    let root_mount = root_mount_identity(root)?;
    let (parent_prefix, leaf_str) = match path.rsplit_once('/') {
        Some((prefix, leaf)) => (Some(prefix), leaf),
        None => (None, path),
    };
    if leaf_str.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path targets .git metadata, which StateEngine does not write",
        ));
    }
    let mut chain: Vec<(&str, File, (u64, u64))> = Vec::new();
    if let Some(prefix) = parent_prefix {
        for part in prefix.split('/') {
            let parent = chain.last().map_or(root, |(_, dir, _)| dir);
            let (dir, id) = open_or_create_dir(parent, part, root_mount)?;
            chain.push((part, dir, id));
        }
    }
    let parent = chain.last().map_or(root, |(_, dir, _)| dir);
    let dot_git = dot_git_id(parent)?;
    let leaf = cstr(leaf_str)?;
    let baseline = inspect_target_leaf(parent, &leaf, root_mount, dot_git)?;

    let stage_str = stage_name()?;
    let stage_cstr = cstr(&stage_str)?;
    let stage_baseline = stage_file(parent, &stage_cstr, bytes, baseline)?;

    let pre_publish = (|| -> Result<(), WorkspaceWriteError> {
        root_check().map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
        })?;
        verify_parent_chain(root, &chain, root_mount)?;
        verify_target_unchanged(parent, &leaf, root_mount, dot_git, baseline)
    })();
    if let Err(error) = pre_publish {
        cleanup_stage(parent, &stage_cstr);
        return Err(error);
    }

    if let Some(expected) = baseline {
        return replace::publish_replace(&replace::ReplaceCtx {
            root,
            chain: &chain,
            parent,
            stage: &stage_cstr,
            leaf: &leaf,
            stage_baseline,
            expected,
            root_mount,
            dot_git,
            root_check,
        });
    }

    if let Err(error) = publish_exclusive(parent, &stage_cstr, &leaf) {
        if matches!(error, WorkspaceWriteError::BeforePublish(_)) {
            cleanup_stage(parent, &stage_cstr);
        }
        return Err(error);
    }
    let post_custody = root_check()
        .map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
        })
        .and_then(|()| verify_parent_chain(root, &chain, root_mount));
    if let Err(reason) = post_custody {
        return Err(
            match stat_entry_at(parent, &leaf, libc::AT_SYMLINK_NOFOLLOW) {
                Ok(Some(m)) if TargetBaseline::from_meta(m) == stage_baseline => {
                    // SAFETY: verified our exact newly-created revision in the displaced parent.
                    if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) } == 0 {
                        match parent.sync_all() {
                            Ok(()) => WorkspaceWriteError::Restored(format!(
                                "parent displaced during create ({reason}); newly created file removed"
                            )),
                            Err(sync_err) => WorkspaceWriteError::PublishedUncertain(format!(
                                "parent displaced during create ({reason}) and newly created file removed, but rollback sync failed: {sync_err}"
                            )),
                        }
                    } else {
                        let unlink_err = io::Error::last_os_error();
                        WorkspaceWriteError::PublishedUncertain(format!(
                            "parent displaced during create ({reason}); rollback unlink failed: {unlink_err}"
                        ))
                    }
                }
                Ok(Some(_)) => WorkspaceWriteError::PublishedUncertain(format!(
                    "parent displaced during create ({reason}); created target was modified before rollback and was left on disk"
                )),
                Ok(None) => WorkspaceWriteError::PublishedUncertain(format!(
                    "parent displaced during create ({reason}); created target was already absent before rollback"
                )),
                Err(stat_err) => WorkspaceWriteError::PublishedUncertain(format!(
                    "parent displaced during create ({reason}); rollback inspection failed: {stat_err}"
                )),
            },
        );
    }
    parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after publication: {error}"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod tests;
