//! Existing-file replacement for Unix workspace writes: prefers atomic
//! `renameat2(RENAME_EXCHANGE)` / `renameatx_np(RENAME_SWAP)` and falls back to
//! a parent-fd-anchored backup-hardlink + `renameat` sequence on mounts where
//! exchange flags are unsupported (WSL2 `/mnt/c`, VirtioFS, FUSE, NFS/SMB,
//! non-APFS macOS volumes).
use super::{
    MountIdentity, TargetBaseline, WorkspaceWriteError, WorkspaceWriteRefusal, cleanup_stage, cstr,
    inspect_target_leaf, invalid, io_before, stage_name, stat_entry_at, verify_parent_chain,
};
use std::{ffi::CString, fs::File, io, os::fd::AsRawFd};

pub(super) struct ReplaceCtx<'a> {
    pub(super) root: &'a File,
    pub(super) chain: &'a [(&'a str, File, (u64, u64))],
    pub(super) parent: &'a File,
    pub(super) stage: &'a CString,
    pub(super) leaf: &'a CString,
    pub(super) stage_baseline: TargetBaseline,
    pub(super) expected: TargetBaseline,
    pub(super) root_mount: MountIdentity,
    pub(super) dot_git: Option<(u64, u64)>,
    pub(super) root_check: &'a dyn Fn() -> io::Result<()>,
}

/// True when the kernel or mount does not support flagged rename operations
/// (`RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_SWAP`).
pub(super) fn is_rename_flag_unsupported(err: &io::Error) -> bool {
    let Some(code) = err.raw_os_error() else {
        return err.kind() == io::ErrorKind::Unsupported;
    };
    code == libc::ENOSYS
        || code == libc::EINVAL
        || code == libc::EOPNOTSUPP
        || code == libc::ENOTSUP
}

fn exchange_at(parent: &File, a: &CString, b: &CString) -> Result<(), io::Error> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: retained parent directory fd and two NUL-terminated literal
        // names; RENAME_EXCHANGE atomically swaps `a` and `b` without data loss.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                a.as_ptr(),
                parent.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: retained parent directory fd and two NUL-terminated literal
        // names; RENAME_SWAP atomically swaps `a` and `b` without data loss.
        if unsafe {
            libc::renameatx_np(
                parent.as_raw_fd(),
                a.as_ptr(),
                parent.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_SWAP,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, a, b);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic rename exchange is unsupported on this platform",
        ))
    }
}

/// Atomically exchange `stage` and `leaf`, verify the displaced file's baseline
/// and parent custody, and swap back cleanly on any concurrent modification or
/// parent displacement before unlinking the displaced original. Falls back to
/// backup-hardlink + `renameat` when the mount does not support exchange flags.
pub(super) fn publish_replace(ctx: &ReplaceCtx<'_>) -> Result<(), WorkspaceWriteError> {
    match exchange_at(ctx.parent, ctx.stage, ctx.leaf) {
        Ok(()) => finish_exchange_replace(ctx),
        Err(err) if is_rename_flag_unsupported(&err) => publish_replace_fallback(ctx),
        Err(err) => {
            cleanup_stage(ctx.parent, ctx.stage);
            Err(io_before(err))
        }
    }
}

fn verify_displaced_custody(
    ctx: &ReplaceCtx<'_>,
    displaced_name: &CString,
    change_message: &str,
) -> Result<(), WorkspaceWriteError> {
    (ctx.root_check)().map_err(|error| {
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
    })?;
    verify_parent_chain(ctx.root, ctx.chain, ctx.root_mount)?;
    let displaced = inspect_target_leaf(ctx.parent, displaced_name, ctx.root_mount, ctx.dot_git)?;
    if displaced != Some(ctx.expected) {
        return Err(invalid(change_message));
    }
    Ok(())
}

fn finish_exchange_replace(ctx: &ReplaceCtx<'_>) -> Result<(), WorkspaceWriteError> {
    let custody =
        verify_displaced_custody(ctx, ctx.stage, "target file changed during atomic exchange");
    if let Err(reason) = custody {
        // Only swap back if `leaf` still matches our exact staged revision
        // (inode, size, mtime, mode), so a later in-place edit is never lost.
        match stat_entry_at(ctx.parent, ctx.leaf, libc::AT_SYMLINK_NOFOLLOW) {
            Ok(Some(m)) if TargetBaseline::from_meta(m) == ctx.stage_baseline => {}
            Ok(Some(_)) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "target changed after exchange ({reason}); rollback skipped to preserve the newer target"
                )));
            }
            Ok(None) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "target is absent after exchange ({reason}); rollback skipped"
                )));
            }
            Err(stat_err) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "rollback inspection after exchange conflict ({reason}) failed: {stat_err}; rollback skipped"
                )));
            }
        }
        if let Err(rollback_err) = exchange_at(ctx.parent, ctx.stage, ctx.leaf) {
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "rollback after exchange conflict ({reason}) failed: {rollback_err}"
            )));
        }
        if let Err(sync_err) = ctx.parent.sync_all() {
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "original restored after exchange conflict ({reason}), but rollback directory sync failed: {sync_err}"
            )));
        }
        // Verify the restored staging sibling still matches our staged revision
        // before unlinking it.
        match stat_entry_at(ctx.parent, ctx.stage, libc::AT_SYMLINK_NOFOLLOW) {
            Ok(Some(m)) if TargetBaseline::from_meta(m) == ctx.stage_baseline => {}
            Ok(Some(_)) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "original restored after exchange conflict ({reason}), but staging sibling changed before cleanup and was left on disk"
                )));
            }
            Ok(None) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "original restored after exchange conflict ({reason}), but staging sibling was already absent before cleanup"
                )));
            }
            Err(stat_err) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "original restored after exchange conflict ({reason}), but staging verification failed: {stat_err}"
                )));
            }
        }
        // SAFETY: retained parent directory fd and verified staged sibling.
        if unsafe { libc::unlinkat(ctx.parent.as_raw_fd(), ctx.stage.as_ptr(), 0) } < 0 {
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "original restored after exchange conflict ({reason}), but staging cleanup failed: {}",
                io::Error::last_os_error()
            )));
        }
        if let Err(sync_err) = ctx.parent.sync_all() {
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "original restored and staging removed after exchange conflict ({reason}), but final directory sync failed: {sync_err}"
            )));
        }
        return Err(WorkspaceWriteError::Restored(format!(
            "conflict during exchange ({reason}); original restored and staging removed"
        )));
    }
    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after exchange: {error}"
        ))
    })?;
    // SAFETY: retained parent directory fd and verified displaced original at `stage`.
    if unsafe { libc::unlinkat(ctx.parent.as_raw_fd(), ctx.stage.as_ptr(), 0) } < 0 {
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup removal failed: {}",
            io::Error::last_os_error()
        )));
    }
    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after backup removal: {error}"
        ))
    })?;
    Ok(())
}

/// Parent-fd-anchored backup-hardlink + `renameat` fallback for mounts where
/// `renameat2(RENAME_EXCHANGE)` / `renameatx_np(RENAME_SWAP)` is unsupported.
pub(super) fn publish_replace_fallback(ctx: &ReplaceCtx<'_>) -> Result<(), WorkspaceWriteError> {
    let backup = match stage_name().and_then(|name| cstr(&name)) {
        Ok(name) => name,
        Err(err) => {
            cleanup_stage(ctx.parent, ctx.stage);
            return Err(err);
        }
    };
    // SAFETY: retained parent directory fd and literal names; flags=0 does not
    // follow symlinks and creates a hard link to the current target inode.
    if unsafe {
        libc::linkat(
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
            ctx.parent.as_raw_fd(),
            backup.as_ptr(),
            0,
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        cleanup_stage(ctx.parent, ctx.stage);
        return Err(io_before(err));
    }

    let pre_rename = (|| -> Result<(), WorkspaceWriteError> {
        verify_displaced_custody(
            ctx,
            &backup,
            "target file changed before fallback replacement",
        )?;
        let current = inspect_target_leaf(ctx.parent, ctx.leaf, ctx.root_mount, ctx.dot_git)?;
        if current != Some(ctx.expected) {
            return Err(invalid("target file changed before fallback replacement"));
        }
        ctx.parent.sync_all().map_err(io_before)
    })();
    if let Err(err) = pre_rename {
        cleanup_stage(ctx.parent, &backup);
        cleanup_stage(ctx.parent, ctx.stage);
        return Err(err);
    }

    // SAFETY: retained parent directory fd and literal sibling names.
    if unsafe {
        libc::renameat(
            ctx.parent.as_raw_fd(),
            ctx.stage.as_ptr(),
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
        )
    } < 0
    {
        let err = io::Error::last_os_error();
        cleanup_stage(ctx.parent, &backup);
        cleanup_stage(ctx.parent, ctx.stage);
        return Err(io_before(err));
    }

    if let Err(reason) = verify_displaced_custody(
        ctx,
        &backup,
        "target file changed during fallback replacement",
    ) {
        return Err(rollback_fallback(ctx, &backup, reason));
    }

    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after fallback replacement: {error}"
        ))
    })?;
    // SAFETY: retained parent directory fd and verified backup sibling.
    if unsafe { libc::unlinkat(ctx.parent.as_raw_fd(), backup.as_ptr(), 0) } < 0 {
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but backup sibling removal failed: {}",
            io::Error::last_os_error()
        )));
    }
    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after backup removal: {error}"
        ))
    })?;
    Ok(())
}

fn rollback_fallback(
    ctx: &ReplaceCtx<'_>,
    backup: &CString,
    reason: WorkspaceWriteError,
) -> WorkspaceWriteError {
    // Only restore if `leaf` still matches our exact staged revision, so a
    // newer post-rename edit is never overwritten.
    match stat_entry_at(ctx.parent, ctx.leaf, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(Some(m)) if TargetBaseline::from_meta(m) == ctx.stage_baseline => {}
        Ok(Some(_)) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "target changed after fallback replacement ({reason}); rollback skipped to preserve the newer target"
            ));
        }
        Ok(None) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "target is absent after fallback replacement ({reason}); rollback skipped"
            ));
        }
        Err(stat_err) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "rollback inspection after fallback conflict ({reason}) failed: {stat_err}; rollback skipped"
            ));
        }
    }
    // SAFETY: retained parent directory fd and verified backup/leaf siblings;
    // moving `backup` back onto `leaf` restores the original inode and removes
    // the backup sibling atomically.
    if unsafe {
        libc::renameat(
            ctx.parent.as_raw_fd(),
            backup.as_ptr(),
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
        )
    } < 0
    {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "rollback after fallback conflict ({reason}) failed: {}",
            io::Error::last_os_error()
        ));
    }
    if let Err(sync_err) = ctx.parent.sync_all() {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "original restored after fallback conflict ({reason}), but rollback directory sync failed: {sync_err}"
        ));
    }
    WorkspaceWriteError::Restored(format!(
        "conflict during fallback replacement ({reason}); original restored and backup removed"
    ))
}
