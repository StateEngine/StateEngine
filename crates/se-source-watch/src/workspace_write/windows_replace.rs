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
                | ERROR_UNABLE_TO_MOVE_REPLACEMENT
                | ERROR_FILE_NOT_FOUND
                | ERROR_PATH_NOT_FOUND
                | ERROR_ACCESS_DENIED
                | ERROR_SHARING_VIOLATION
                | ERROR_INVALID_PARAMETER
        )
    )
}

fn verify_leaf_matches(
    parent: &File,
    name: &str,
    expected_key: NativeObjectKey,
    expected_baseline: TargetBaseline,
) -> Result<bool, io::Error> {
    let mut units = utf16_component(name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let file = match nt_open_relative(
        parent,
        &mut units,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    ) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    matches_revision(&file, expected_key, expected_baseline)
}

fn retire_verified_restore(
    ctx: &ReplaceCtx<'_>,
    restore_str: &str,
    restore_path: &Path,
) -> WorkspaceWriteError {
    let Ok(mut restore_units) = utf16_component(restore_str) else {
        let status = describe_siblings(ctx.parent, &[(restore_str, restore_path)]);
        return WorkspaceWriteError::PublishedUncertain(format!(
            "prior target restored, but restore sibling name invalid; {status}"
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
                "prior target restored, but restore sibling at {} could not be opened: {err}",
                restore_path.display()
            ));
        }
    };
    match matches_revision(&restore_file, ctx.stage_key, ctx.stage_baseline) {
        Ok(true) => {}
        Ok(false) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "prior target restored, but restore sibling at {} no longer matched staged revision and was retained",
                restore_path.display()
            ));
        }
        Err(err) => {
            return WorkspaceWriteError::PublishedUncertain(format!(
                "prior target restored, but restore sibling at {} could not be verified ({err}) and was retained",
                restore_path.display()
            ));
        }
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

fn restore_displaced_backup(
    ctx: &ReplaceCtx<'_>,
    target_wide: &[u16],
    backup_wide: &[u16],
    backup_str: &str,
    backup_path: &Path,
    backup_key: NativeObjectKey,
    backup_baseline: TargetBaseline,
) -> WorkspaceWriteError {
    // Verify `target` still holds our exact staged object before swapping back;
    // if a later editor save already replaced `target` or inspection fails, retain both.
    match verify_leaf_matches(ctx.parent, ctx.leaf_str, ctx.stage_key, ctx.stage_baseline) {
        Ok(true) => {}
        Ok(false) => {
            let status = describe_siblings(ctx.parent, &[(backup_str, backup_path)]);
            return WorkspaceWriteError::PublishedUncertain(format!(
                "target changed again after replacement; current target kept ({status})"
            ));
        }
        Err(err) => {
            let status = describe_siblings(ctx.parent, &[(backup_str, backup_path)]);
            return WorkspaceWriteError::PublishedUncertain(format!(
                "rollback target inspection failed ({err}); current target kept ({status})"
            ));
        }
    }

    let restore_str = format!("{}.restore", ctx.stage_str);
    let restore_path = ctx.parent_path.join(&restore_str);
    let Ok(restore_wide) = wide_path(&restore_path) else {
        let status = describe_siblings(ctx.parent, &[(backup_str, backup_path)]);
        return WorkspaceWriteError::PublishedUncertain(format!(
            "target conflicted and restore path invalid ({status})"
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
        let status = describe_siblings(
            ctx.parent,
            &[(backup_str, backup_path), (&restore_str, &restore_path)],
        );
        return WorkspaceWriteError::PublishedUncertain(format!(
            "rollback ReplaceFileW failed ({err}); {status}"
        ));
    }

    // Verify incoming target matches displaced backup before retiring restore sibling.
    match verify_leaf_matches(ctx.parent, ctx.leaf_str, backup_key, backup_baseline) {
        Ok(true) => retire_verified_restore(ctx, &restore_str, &restore_path),
        Ok(false) => {
            let status = describe_siblings(
                ctx.parent,
                &[(backup_str, backup_path), (&restore_str, &restore_path)],
            );
            WorkspaceWriteError::PublishedUncertain(format!(
                "rollback completed but target did not match expected displaced revision; {status}"
            ))
        }
        Err(err) => {
            let status = describe_siblings(
                ctx.parent,
                &[(backup_str, backup_path), (&restore_str, &restore_path)],
            );
            WorkspaceWriteError::PublishedUncertain(format!(
                "rollback completed but target verification failed ({err}); {status}"
            ))
        }
    }
}

fn handle_replace_failure(
    ctx: &ReplaceCtx<'_>,
    error: io::Error,
    stage_path: &Path,
    backup_str: &str,
    backup_path: &Path,
) -> WorkspaceWriteError {
    if is_pre_publish_replace_error(&error)
        && matches!(probe_sibling(ctx.parent, backup_str), SiblingState::Absent)
    {
        if let Ok(mut stage_units) = utf16_component(ctx.stage_str)
            && let Ok(stage_file) = nt_open_relative(
                ctx.parent,
                &mut stage_units,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            )
            && matches!(
                matches_revision(&stage_file, ctx.stage_key, ctx.stage_baseline),
                Ok(true)
            )
        {
            dispose_stage(&stage_file);
        }
        return io_before(error);
    }
    let status = describe_siblings(
        ctx.parent,
        &[(ctx.stage_str, stage_path), (backup_str, backup_path)],
    );
    WorkspaceWriteError::PublishedUncertain(format!("ReplaceFileW failed ({error}); {status}"))
}

fn open_displaced_backup(
    parent: &File,
    backup_str: &str,
) -> Result<(File, NativeObjectKey, TargetBaseline), WorkspaceWriteError> {
    let mut backup_units = utf16_component(backup_str)?;
    let backup_file = nt_open_relative(
        parent,
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
    let backup_key = se_state_files::observe_object_key(&backup_file).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup identity unreadable: {error}"
        ))
    })?;
    let backup_rev = se_state_files::observe_file_revision(&backup_file).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup revision unreadable: {error}"
        ))
    })?;
    Ok((
        backup_file,
        backup_key,
        TargetBaseline::from_revision(backup_rev),
    ))
}

/// Replace an existing file via `ReplaceFileW` so the displaced original is
/// retained at a sibling backup name, verified against `expected` along with
/// the incoming target revision, and either deleted cleanly or restored/retained
/// on conflict.
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
        return Err(handle_replace_failure(
            ctx,
            error,
            &stage_path,
            &backup_str,
            &backup_path,
        ));
    }

    let (backup_file, backup_key, backup_baseline) =
        open_displaced_backup(ctx.parent, &backup_str)?;

    // If root or parent custody failed, NEVER run another full-path mutation;
    // retain the displaced original at its backup path and report its location.
    if let Err(err) = (ctx.root_check)()
        .map_err(|e| WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(e)))
        .and_then(|()| verify_parent_chain(ctx.root, ctx.chain))
    {
        drop(backup_file);
        drop(held_target);
        let status = describe_siblings(ctx.parent, &[(&backup_str, &backup_path)]);
        return Err(WorkspaceWriteError::PublishedUncertain(format!(
            "workspace custody failed after replacement ({err}); {status}"
        )));
    }

    if backup_baseline != ctx.expected {
        drop(backup_file);
        drop(held_target);
        return Err(restore_displaced_backup(
            ctx,
            &target_wide,
            &backup_wide,
            &backup_str,
            &backup_path,
            backup_key,
            backup_baseline,
        ));
    }

    // Verify incoming target holds our exact staged revision before deleting backup.
    match verify_leaf_matches(ctx.parent, ctx.leaf_str, ctx.stage_key, ctx.stage_baseline) {
        Ok(true) => {}
        Ok(false) => {
            drop(backup_file);
            drop(held_target);
            let status = describe_siblings(ctx.parent, &[(&backup_str, &backup_path)]);
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "replacement completed but target did not match staged revision; backup retained ({status})"
            )));
        }
        Err(err) => {
            drop(backup_file);
            drop(held_target);
            let status = describe_siblings(ctx.parent, &[(&backup_str, &backup_path)]);
            return Err(WorkspaceWriteError::PublishedUncertain(format!(
                "replacement completed but target verification failed ({err}); backup retained ({status})"
            )));
        }
    }

    drop(held_target);
    dispose_checked(&backup_file).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "replacement published but displaced backup removal failed: {error}"
        ))
    })?;
    Ok(())
}
