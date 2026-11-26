//! Windows `ReplaceFileW` replacement and verified rollback beneath pinned
//! root and parent directory handles.
use super::*;

pub(super) struct ReplaceCtx<'a> {
    pub root: &'a File,
    pub chain: &'a [(&'a str, File, NativeObjectKey)],
    pub parent: &'a File,
    pub parent_path: &'a Path,
    pub leaf_str: &'a str,
    pub stage_str: &'a str,
    pub stage_key: NativeObjectKey,
    pub stage_baseline: TargetBaseline,
    pub expected: TargetBaseline,
    pub root_check: &'a dyn Fn() -> io::Result<()>,
}

fn is_pre_publish_replace_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|c| c as u32),
        Some(
            ERROR_UNABLE_TO_REMOVE_REPLACED
                | ERROR_FILE_NOT_FOUND
                | ERROR_PATH_NOT_FOUND
                | ERROR_ACCESS_DENIED
                | ERROR_SHARING_VIOLATION
                | ERROR_INVALID_PARAMETER
        )
    )
}

fn restore_displaced_backup(
    ctx: &ReplaceCtx<'_>,
    target_wide: &[u16],
    backup_wide: &[u16],
    backup_path: &Path,
) -> WorkspaceWriteError {
    // Verify `target` still holds our exact staged object before swapping back;
    // if a later editor save already replaced `target`, keep both versions.
    let Ok(mut leaf_units) = utf16_component(ctx.leaf_str) else {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "target conflicted; displaced original retained at {}",
            backup_path.display()
        ));
    };
    let current = nt_open_relative(
        ctx.parent,
        &mut leaf_units,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    let intact_stage =
        matches!(current, Ok(ref f) if matches_staged(f, ctx.stage_key, ctx.stage_baseline));
    drop(current);
    if !intact_stage {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "target changed again after replacement; current target kept and displaced backup retained at {}",
            backup_path.display()
        ));
    }

    let restore_str = format!("{}.restore", ctx.stage_str);
    let restore_path = ctx.parent_path.join(&restore_str);
    let Ok(restore_wide) = wide_path(&restore_path) else {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "target conflicted; displaced backup retained at {}",
            backup_path.display()
        ));
    };
    // SAFETY: root and parent chain are pinned and verified; swap backup back to target.
    let restored = unsafe {
        ReplaceFileW(
            target_wide.as_ptr(),
            backup_wide.as_ptr(),
            restore_wide.as_ptr(),
            0,
            ptr::null(),
            ptr::null(),
        )
    };
    if restored == 0 {
        let err = io::Error::last_os_error();
        return WorkspaceWriteError::PublishedUncertain(format!(
            "rollback ReplaceFileW failed ({err}); displaced backup retained at {}",
            backup_path.display()
        ));
    }

    // Dispose the restore sibling ONLY if it positively matches our exact staged object.
    let Ok(mut restore_units) = utf16_component(&restore_str) else {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "prior target restored, but restore sibling retained at {}",
            restore_path.display()
        ));
    };
    let restore_file = match nt_open_relative(
        ctx.parent,
        &mut restore_units,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    ) {
        Ok(file) => file,
        Err(err) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "prior target restored, but restore sibling could not be opened ({err}); inspect {}",
                restore_path.display()
            ));
        }
    };
    if !matches_staged(&restore_file, ctx.stage_key, ctx.stage_baseline) {
        return WorkspaceWriteError::PublishedUncertain(format!(
            "prior target restored, but restore sibling at {} no longer matched staged revision and was retained",
            restore_path.display()
        ));
    }
    match dispose_checked(&restore_file) {
        Ok(()) => WorkspaceWriteError::Restored(
            "target changed concurrently during replacement; prior target restored and staging removed"
                .into(),
        ),
        Err(err) => WorkspaceWriteError::PublishedUncertain(format!(
            "prior target restored, but removing staged restore sibling failed: {err}"
        )),
    }
}

/// Replace an existing file via `ReplaceFileW` so the displaced original is
/// retained at a sibling backup name, verified against `expected`, and either
/// deleted cleanly or restored/retained on conflict.
pub(super) fn publish_replace(
    ctx: &ReplaceCtx<'_>,
    held_target: File,
) -> Result<(), WorkspaceWriteError> {
    let backup_str = format!("{}.bak", ctx.stage_str);
    let target_path = ctx.parent_path.join(ctx.leaf_str);
    let stage_path = ctx.parent_path.join(ctx.stage_str);
    let backup_path = ctx.parent_path.join(&backup_str);
    let target_wide = wide_path(&target_path)?;
    let stage_wide = wide_path(&stage_path)?;
    let backup_wide = wide_path(&backup_path)?;

    // SAFETY: terminated UTF-16 paths beneath pinned non-movable root & parent handles.
    let replaced = unsafe {
        ReplaceFileW(
            target_wide.as_ptr(),
            stage_wide.as_ptr(),
            backup_wide.as_ptr(),
            0,
            ptr::null(),
            ptr::null(),
        )
    };
    if replaced == 0 {
        let error = io::Error::last_os_error();
        drop(held_target);
        if is_pre_publish_replace_error(&error) {
            let mut stage_units = utf16_component(ctx.stage_str)?;
            if let Ok(stage_file) = nt_open_relative(
                ctx.parent,
                &mut stage_units,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            ) && matches_staged(&stage_file, ctx.stage_key, ctx.stage_baseline)
            {
                dispose_stage(&stage_file);
            }
            return Err(io_before(error));
        }
        let mut observed = Vec::new();
        if sibling_exists(ctx.parent, ctx.stage_str) {
            observed.push(stage_path.display().to_string());
        }
        if sibling_exists(ctx.parent, &backup_str) {
            observed.push(backup_path.display().to_string());
        }
        let detail = if observed.is_empty() {
            format!("ReplaceFileW failed ({error}); no recovery siblings observed on disk")
        } else {
            format!(
                "ReplaceFileW failed ({error}); observed recovery siblings: {}",
                observed.join(", ")
            )
        };
        return Err(WorkspaceWriteError::PublishedUncertain(detail));
    }

    let mut backup_units = utf16_component(&backup_str)?;
    let backup_file = nt_open_relative(
        ctx.parent,
        &mut backup_units,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    )
    .map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup could not be opened: {error}"
        ))
    })?;
    let backup_rev = se_state_files::observe_file_revision(&backup_file).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup revision unreadable: {error}"
        ))
    })?;

    // If root or parent custody failed, NEVER run another full-path mutation;
    // retain the displaced original at its backup path and report its location.
    if let Err(err) = (ctx.root_check)()
        .map_err(|e| WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(e)))
        .and_then(|()| verify_parent_chain(ctx.root, ctx.chain))
    {
        drop(backup_file);
        drop(held_target);
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "workspace custody failed after replacement ({err}); displaced original retained at {}",
            backup_path.display()
        )));
    }

    if TargetBaseline::from_revision(backup_rev) != ctx.expected {
        drop(backup_file);
        drop(held_target);
        return Err(restore_displaced_backup(
            ctx,
            &target_wide,
            &backup_wide,
            &backup_path,
        ));
    }

    drop(held_target);
    dispose_checked(&backup_file).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup removal failed: {error}"
        ))
    })?;
    Ok(())
}
