//! Existing-file replacement for Unix workspace writes: prefers atomic
//! `renameat2(RENAME_EXCHANGE)` / `renameatx_np(RENAME_SWAP)` and falls back to
//! a parent-fd-anchored `renameat(leaf -> backup)` + exclusive `linkat(stage -> leaf)`
//! sequence on mounts where exchange flags are unsupported (WSL2 `/mnt/c`,
//! VirtioFS, FUSE, NFS/SMB, non-APFS macOS volumes).
use super::{
    MountIdentity, TargetBaseline, WorkspaceWriteError, WorkspaceWriteRefusal, cstr,
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

fn unlink_sibling(parent: &File, name: &CString) -> Result<(), io::Error> {
    // SAFETY: retained parent directory fd and NUL-terminated literal sibling name.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::NotFound {
            return Err(err);
        }
    }
    Ok(())
}

fn before_publish_with_stage_cleanup(
    parent: &File,
    stage: &CString,
    cause: WorkspaceWriteError,
) -> WorkspaceWriteError {
    match unlink_sibling(parent, stage) {
        Ok(()) => cause,
        Err(cleanup_err) => WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(
            io::Error::other(format!(
                "{cause}; additionally, staging sibling '{}' could not be removed: {cleanup_err}",
                stage.to_string_lossy()
            )),
        )),
    }
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
/// `renameat(leaf -> backup)` + `linkat(stage -> leaf)` when exchange flags are
/// unsupported by the mount.
pub(super) fn publish_replace(ctx: &ReplaceCtx<'_>) -> Result<(), WorkspaceWriteError> {
    match exchange_at(ctx.parent, ctx.stage, ctx.leaf) {
        Ok(()) => finish_exchange_replace(ctx),
        Err(err) if is_rename_flag_unsupported(&err) => publish_replace_fallback(ctx),
        Err(err) => Err(before_publish_with_stage_cleanup(
            ctx.parent,
            ctx.stage,
            io_before(err),
        )),
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

/// Confirm `entry` still matches our exact staged revision (inode, size, mtime,
/// mode) before any rollback so a newer post-publish edit is never overwritten.
/// Names `retained_note` whenever rollback is skipped so recovery can locate
/// the displaced original.
fn verify_entry_matches_stage(
    parent: &File,
    entry: &CString,
    stage_baseline: TargetBaseline,
    phase: &str,
    reason: &WorkspaceWriteError,
    retained_note: &str,
) -> Result<(), WorkspaceWriteError> {
    match stat_entry_at(parent, entry, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(Some(m)) if TargetBaseline::from_meta(m) == stage_baseline => Ok(()),
        Ok(Some(_)) => Err(WorkspaceWriteError::PublishedUncertain(format!(
            "target changed after {phase} ({reason}); rollback skipped to preserve the newer target; {retained_note}"
        ))),
        Ok(None) => Err(WorkspaceWriteError::PublishedUncertain(format!(
            "target is absent after {phase} ({reason}); rollback skipped; {retained_note}"
        ))),
        Err(stat_err) => Err(WorkspaceWriteError::PublishedUncertain(format!(
            "rollback inspection after {phase} conflict ({reason}) failed: {stat_err}; rollback skipped; {retained_note}"
        ))),
    }
}

fn finish_exchange_replace(ctx: &ReplaceCtx<'_>) -> Result<(), WorkspaceWriteError> {
    let custody =
        verify_displaced_custody(ctx, ctx.stage, "target file changed during atomic exchange");
    if let Err(reason) = custody {
        let retained = format!(
            "displaced original remains in '{}'",
            ctx.stage.to_string_lossy()
        );
        verify_entry_matches_stage(
            ctx.parent,
            ctx.leaf,
            ctx.stage_baseline,
            "exchange",
            &reason,
            &retained,
        )?;
        if let Err(rollback_err) = exchange_at(ctx.parent, ctx.stage, ctx.leaf) {
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "rollback after exchange conflict ({reason}) failed: {rollback_err}; {retained}"
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
                    "original restored after exchange conflict ({reason}), but staging sibling '{}' changed before cleanup and was left on disk",
                    ctx.stage.to_string_lossy()
                )));
            }
            Ok(None) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "original restored after exchange conflict ({reason}), but staging sibling '{}' was already absent before cleanup",
                    ctx.stage.to_string_lossy()
                )));
            }
            Err(stat_err) => {
                return Err(WorkspaceWriteError::PublishedUncertain(format!(
                    "original restored after exchange conflict ({reason}), but staging verification for '{}' failed: {stat_err}",
                    ctx.stage.to_string_lossy()
                )));
            }
        }
        if let Err(unlink_err) = unlink_sibling(ctx.parent, ctx.stage) {
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "original restored after exchange conflict ({reason}), but staging sibling '{}' cleanup failed: {unlink_err}",
                ctx.stage.to_string_lossy()
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
            "containing directory sync failed after exchange: {error}; displaced backup '{}' remains on disk",
            ctx.stage.to_string_lossy()
        ))
    })?;
    if let Err(unlink_err) = unlink_sibling(ctx.parent, ctx.stage) {
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup '{}' removal failed: {unlink_err}",
            ctx.stage.to_string_lossy()
        )));
    }
    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after backup removal: {error}"
        ))
    })?;
    Ok(())
}

/// Verify that `parent` supports `linkat` on regular files before displacing
/// `leaf`, so mounts without hard-link support fail cleanly as `BeforePublish`
/// without ever moving `leaf`.
fn probe_linkat_support(
    parent: &File,
    stage: &CString,
    probe: &CString,
) -> Result<(), WorkspaceWriteError> {
    // SAFETY: retained parent directory fd and literal private staging/probe names.
    if unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            stage.as_ptr(),
            parent.as_raw_fd(),
            probe.as_ptr(),
            0,
        )
    } < 0
    {
        return Err(before_publish_with_stage_cleanup(
            parent,
            stage,
            io_before(io::Error::last_os_error()),
        ));
    }
    if let Err(unlink_err) = unlink_sibling(parent, probe) {
        return Err(before_publish_with_stage_cleanup(
            parent,
            stage,
            io_before(io::Error::other(format!(
                "fallback linkat probe sibling '{}' cleanup failed: {unlink_err}",
                probe.to_string_lossy()
            ))),
        ));
    }
    Ok(())
}

/// Fallback replacement for mounts lacking `RENAME_EXCHANGE`/`RENAME_SWAP`:
/// 1. Probe `linkat` on `stage` before touching `leaf`.
/// 2. Atomically displace `leaf -> backup` via `renameat` so whatever was at
///    `leaf` (including any concurrent save) is captured in `backup`.
/// 3. Verify root/parent custody and that `backup` matches `expected`; on
///    conflict, restore `backup -> leaf` via exclusive `linkat`.
/// 4. Publish `stage -> leaf` via exclusive `linkat` (refusing `EEXIST` if a
///    concurrent creator wrote `leaf`), verify post-publish custody, then
///    remove `stage` and `backup` and sync `parent`.
pub(super) fn publish_replace_fallback(ctx: &ReplaceCtx<'_>) -> Result<(), WorkspaceWriteError> {
    let backup = match stage_name().and_then(|name| cstr(&name)) {
        Ok(name) => name,
        Err(err) => {
            return Err(before_publish_with_stage_cleanup(
                ctx.parent, ctx.stage, err,
            ));
        }
    };
    probe_linkat_support(ctx.parent, ctx.stage, &backup)?;

    // SAFETY: retained parent directory fd and literal sibling names; `backup`
    // does not exist, so `renameat` atomically captures whatever is at `leaf`.
    if unsafe {
        libc::renameat(
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
            ctx.parent.as_raw_fd(),
            backup.as_ptr(),
        )
    } < 0
    {
        return Err(before_publish_with_stage_cleanup(
            ctx.parent,
            ctx.stage,
            io_before(io::Error::last_os_error()),
        ));
    }

    if let Err(reason) = verify_displaced_custody(
        ctx,
        &backup,
        "target file changed before fallback replacement",
    ) {
        return Err(restore_backup_to_leaf(ctx, &backup, &reason, None));
    }

    // SAFETY: retained parent directory fd and literal names; `linkat` fails
    // atomically with `EEXIST` if a concurrent writer created `leaf`.
    if unsafe {
        libc::linkat(
            ctx.parent.as_raw_fd(),
            ctx.stage.as_ptr(),
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
            0,
        )
    } < 0
    {
        let link_err = io::Error::last_os_error();
        if link_err.kind() == io::ErrorKind::AlreadyExists {
            let stage_note = match unlink_sibling(ctx.parent, ctx.stage) {
                Ok(()) => String::new(),
                Err(unlink_err) => format!(
                    "; staging sibling '{}' cleanup failed: {unlink_err}",
                    ctx.stage.to_string_lossy()
                ),
            };
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "another writer recreated the target during fallback replacement; this write was not published and the previous version remains in '{}'{}",
                backup.to_string_lossy(),
                stage_note
            )));
        }
        let reason = io_before(link_err);
        return Err(restore_backup_to_leaf(ctx, &backup, &reason, None));
    }

    let post_custody = (ctx.root_check)()
        .map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
        })
        .and_then(|()| verify_parent_chain(ctx.root, ctx.chain, ctx.root_mount));
    if let Err(reason) = post_custody {
        return Err(rollback_published_fallback(ctx, &backup, &reason));
    }

    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after fallback replacement: {error}; siblings '{}' and '{}' remain on disk",
            ctx.stage.to_string_lossy(),
            backup.to_string_lossy()
        ))
    })?;
    if let Err(unlink_err) = unlink_sibling(ctx.parent, ctx.stage) {
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but staging sibling '{}' removal failed: {unlink_err}; backup '{}' also remains on disk",
            ctx.stage.to_string_lossy(),
            backup.to_string_lossy()
        )));
    }
    if let Err(unlink_err) = unlink_sibling(ctx.parent, &backup) {
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but backup sibling '{}' removal failed: {unlink_err}",
            backup.to_string_lossy()
        )));
    }
    ctx.parent.sync_all().map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "containing directory sync failed after backup removal: {error}"
        ))
    })?;
    Ok(())
}

fn restore_backup_to_leaf(
    ctx: &ReplaceCtx<'_>,
    backup: &CString,
    reason: &WorkspaceWriteError,
    extra_sibling: Option<&CString>,
) -> WorkspaceWriteError {
    // SAFETY: retained parent directory fd and literal names; `linkat` refuses
    // with `EEXIST` rather than clobbering a concurrently created `leaf`.
    if unsafe {
        libc::linkat(
            ctx.parent.as_raw_fd(),
            backup.as_ptr(),
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
            0,
        )
    } < 0
    {
        let restore_err = io::Error::last_os_error();
        let stage_note = match unlink_sibling(ctx.parent, ctx.stage) {
            Ok(()) => String::new(),
            Err(unlink_err) => format!(
                "; staging sibling '{}' cleanup also failed: {unlink_err}",
                ctx.stage.to_string_lossy()
            ),
        };
        let extra_note = extra_sibling.map_or_else(String::new, |extra| {
            match unlink_sibling(ctx.parent, extra) {
                Ok(()) => String::new(),
                Err(unlink_err) => format!(
                    "; rollback sibling '{}' cleanup also failed: {unlink_err}",
                    extra.to_string_lossy()
                ),
            }
        });
        return WorkspaceWriteError::PublishedUncertain(format!(
            "rollback after fallback conflict ({reason}) failed: {restore_err}; displaced original remains in '{}'{}{}",
            backup.to_string_lossy(),
            stage_note,
            extra_note
        ));
    }
    if let Some(extra) = extra_sibling
        && let Err(unlink_err) = unlink_sibling(ctx.parent, extra)
    {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "original restored after fallback conflict ({reason}), but rollback sibling '{}' cleanup failed: {unlink_err}; backup '{}' and staging '{}' may also remain on disk",
            extra.to_string_lossy(),
            backup.to_string_lossy(),
            ctx.stage.to_string_lossy()
        ));
    }
    if let Err(unlink_err) = unlink_sibling(ctx.parent, backup) {
        let stage_note = match unlink_sibling(ctx.parent, ctx.stage) {
            Ok(()) => String::new(),
            Err(stage_err) => format!(
                "; staging sibling '{}' cleanup also failed: {stage_err}",
                ctx.stage.to_string_lossy()
            ),
        };
        return WorkspaceWriteError::PublishedUncertain(format!(
            "original restored after fallback conflict ({reason}), but backup sibling '{}' cleanup failed: {unlink_err}{}",
            backup.to_string_lossy(),
            stage_note
        ));
    }
    if let Err(unlink_err) = unlink_sibling(ctx.parent, ctx.stage) {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "original restored after fallback conflict ({reason}), but staging sibling '{}' cleanup failed: {unlink_err}",
            ctx.stage.to_string_lossy()
        ));
    }
    if let Err(sync_err) = ctx.parent.sync_all() {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "original restored and siblings removed after fallback conflict ({reason}), but rollback directory sync failed: {sync_err}"
        ));
    }
    WorkspaceWriteError::Restored(format!(
        "conflict during fallback replacement ({reason}); original restored and siblings removed"
    ))
}

/// Rename `leaf` aside to a fresh sibling before verifying it still matches our
/// staged revision, closing the check-then-unlink race so a concurrent editor
/// save can never be deleted during rollback.
fn rollback_published_fallback(
    ctx: &ReplaceCtx<'_>,
    backup: &CString,
    reason: &WorkspaceWriteError,
) -> WorkspaceWriteError {
    let retained_pair = format!(
        "backup '{}' and staging '{}' remain on disk",
        backup.to_string_lossy(),
        ctx.stage.to_string_lossy()
    );
    let displaced = match stage_name().and_then(|name| cstr(&name)) {
        Ok(name) => name,
        Err(name_err) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "rollback after fallback conflict ({reason}) could not allocate rollback sibling ({name_err}); {retained_pair}"
            ));
        }
    };
    // SAFETY: retained parent directory fd and literal sibling names; moving
    // `leaf -> displaced` captures whatever is at `leaf` without deleting it.
    if unsafe {
        libc::renameat(
            ctx.parent.as_raw_fd(),
            ctx.leaf.as_ptr(),
            ctx.parent.as_raw_fd(),
            displaced.as_ptr(),
        )
    } < 0
    {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "rollback rename-aside after fallback conflict ({reason}) failed: {}; {retained_pair}",
            io::Error::last_os_error()
        ));
    }
    let retained_all = format!(
        "displaced target '{}', backup '{}', and staging '{}' remain on disk",
        displaced.to_string_lossy(),
        backup.to_string_lossy(),
        ctx.stage.to_string_lossy()
    );
    match verify_entry_matches_stage(
        ctx.parent,
        &displaced,
        ctx.stage_baseline,
        "fallback replacement",
        reason,
        &retained_all,
    ) {
        Ok(()) => restore_backup_to_leaf(ctx, backup, reason, Some(&displaced)),
        Err(uncertain) => {
            // Put the concurrent target back at `leaf` via exclusive `linkat`
            // so the editor's save is never stranded in `displaced`.
            // SAFETY: retained parent directory fd and literal names.
            if unsafe {
                libc::linkat(
                    ctx.parent.as_raw_fd(),
                    displaced.as_ptr(),
                    ctx.parent.as_raw_fd(),
                    ctx.leaf.as_ptr(),
                    0,
                )
            } == 0
            {
                let cleanup_note = match unlink_sibling(ctx.parent, &displaced) {
                    Ok(()) => String::new(),
                    Err(unlink_err) => format!(
                        "; temporary rollback sibling '{}' cleanup failed: {unlink_err}",
                        displaced.to_string_lossy()
                    ),
                };
                let sync_note = match ctx.parent.sync_all() {
                    Ok(()) => String::new(),
                    Err(sync_err) => format!("; directory sync failed: {sync_err}"),
                };
                return WorkspaceWriteError::PublishedUncertain(format!(
                    "target changed after fallback replacement ({reason}); newer target preserved at leaf; {retained_pair}{}{}",
                    cleanup_note, sync_note
                ));
            }
            uncertain
        }
    }
}
