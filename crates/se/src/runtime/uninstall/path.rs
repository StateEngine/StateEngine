use super::*;
pub(super) fn reconcile_paths(plan: &ValidatedUninstallPlan, effects: &mut UninstallEffects) {
    effects.path_complete = true;
    for edit in plan.path_edits() {
        let result = path_edit(edit, &mut effects.path);
        match result {
            Ok(action) => effects.integrations.push(IntegrationEffect {
                path: edit.target.clone(),
                entry: edit.block.clone(),
                action,
                witness: witness(
                    WitnessState::Witnessed,
                    "exact owned PATH block reconciliation with outside native readback",
                    None,
                ),
            }),
            Err(error) => {
                effects.path_complete = false;
                effects.integrations.push(IntegrationEffect {
                    path: edit.target.clone(),
                    entry: edit.block.clone(),
                    action: FileOutcome::ConflictKept,
                    witness: witness(
                        WitnessState::Failed,
                        "PATH preserved or publication explicitly unresolved",
                        Some(error.to_string()),
                    ),
                });
            }
        }
    }
    effects.path.witness = witness(
        if effects.path_complete {
            WitnessState::Witnessed
        } else {
            WitnessState::Failed
        },
        "all planned user PATH targets reconciled through native readback",
        None,
    );
}
fn converted(edit: &UninstallPathEdit) -> Result<PathEdit> {
    Ok(PathEdit {
        target: edit.target.clone(),
        before_sha256: edit
            .before_sha256
            .as_ref()
            .map(|value| Sha256::parse_hex(value))
            .transpose()?,
        block: edit.block.clone(),
        before_bytes: edit.before_bytes,
    })
}
#[cfg(not(windows))]
fn path_edit(edit: &UninstallPathEdit, path: &mut PathEffect) -> Result<FileOutcome> {
    let Some(mut pin) = OwnedFile::open(Path::new(&edit.target)).map_err(native_error)? else {
        return Ok(FileOutcome::AlreadyAbsent);
    };
    let bytes = pin.read(1024 * 1024).map_err(native_error)?;
    let current = std::str::from_utf8(&bytes).map_err(|_| conflict(&edit.target))?;
    let expected = pin.sha256().map_err(native_error)?;
    if let Some(truncate) = edit.profile_truncation(&bytes)? {
        if truncate.expected_sha256 != expected {
            return Err(conflict(&edit.target));
        }
        pin.truncate(expected, truncate.length)
            .map_err(native_error)?;
        path.before_entries
            .push(format!("{}: recorded full or torn append", edit.target));
        path.after_entries.push(format!(
            "{}: recorded original prefix restored",
            edit.target
        ));
        return Ok(FileOutcome::Removed);
    }

    path.before_entries
        .push(format!("{}: owned profile block", edit.target));
    let outcome = match remove_profile_block(&edit.target, Some(current), &converted(edit)?)? {
        EntryChange::AlreadyAbsent => {
            path.after_entries
                .push(format!("{}: already reconciled", edit.target));
            FileOutcome::AlreadyAbsent
        }
        EntryChange::Replace(after) => {
            pin.replace(expected, after.as_bytes())
                .map_err(native_error)?;
            path.after_entries
                .push(format!("{}: owned block removed", edit.target));
            FileOutcome::Removed
        }
        EntryChange::RemoveCreatedTarget => {
            pin.remove(expected).map_err(native_error)?;
            FileOutcome::Removed
        }
    };
    Ok(outcome)
}
#[cfg(windows)]
fn path_edit(edit: &UninstallPathEdit, path: &mut PathEffect) -> Result<FileOutcome> {
    let native = se_proc::NativeUserPath::open();
    let observed = native
        .read()
        .map_err(|e| se_core::scope::unreadable("user PATH", &e.to_string()))?;
    if let Some(current) = observed.value() {
        path.before_entries = current.split(';').map(str::to_owned).collect();
    }
    let change = remove_path_entry(observed.value(), &converted(edit)?)?;
    let replacement = match &change {
        EntryChange::AlreadyAbsent => observed.value(),
        EntryChange::Replace(value) => Some(value.as_str()),
        EntryChange::RemoveCreatedTarget => None,
    };
    let after = native
        .compare_and_set(&observed, replacement)
        .map_err(|e| se_core::scope::unreadable("user PATH", &e.to_string()))?;
    if let Some(value) = after.after.value() {
        path.after_entries = value.split(';').map(str::to_owned).collect();
    }
    Ok(if matches!(change, EntryChange::AlreadyAbsent) {
        FileOutcome::AlreadyAbsent
    } else {
        FileOutcome::Removed
    })
}
