//! The witnessed effects around the running image: owned files and PATH before
//! it, the record, created directories and the recovery rescan after it.
use super::*;

/// Reconciles PATH (or preserves it for a `--no-modify-path` replacement)
/// and removes every owned file except the running image. Reports whether all
/// of them and the recovery rescan resolved.
pub(super) fn remove_owned_files(
    plan: &ValidatedUninstallPlan,
    installed: &UninstallFile,
    parents: &[PathBuf],
    effects: &mut UninstallEffects,
    preserve: bool,
) -> bool {
    let mut safe = true;
    if preserve {
        preserve_paths(plan, effects);
    } else {
        reconcile_paths(plan, effects);
    }
    safe &= effects.path_complete;
    for file in plan
        .files()
        .iter()
        .filter(|file| file.path != installed.path)
    {
        let fish = preserve && se_core::ops::installation::is_fish_path_file(&file.path);
        let result = if fish {
            preserve_file(file)
        } else {
            remove_file(file)
        };
        safe &= file_settled(&result, preserve);
        effects.install_files.push(result);
    }
    effects.recovery = recovery::merge(std::mem::take(&mut effects.recovery), scan(plan, parents));
    safe &= effects.recovery.iter().all(recovery::resolved);
    safe
}

fn file_settled(effect: &FileEffect, preserve: bool) -> bool {
    gone(&effect.outcome)
        || (preserve
            && se_core::ops::installation::is_fish_path_file(&effect.path)
            && matches!(effect.outcome, FileOutcome::Unchanged))
}

fn preserve_file(file: &UninstallFile) -> FileEffect {
    let expected = match digest_bytes(&file.sha256) {
        Ok(value) => value,
        Err(error) => {
            return FileEffect {
                path: file.path.clone(),
                outcome: FileOutcome::Unreadable,
                witness: witness(
                    WitnessState::Failed,
                    "owned Fish PATH file digest is invalid",
                    Some(error.to_string()),
                ),
            };
        }
    };
    match OwnedFile::open(Path::new(&file.path)) {
        Ok(None) => FileEffect {
            path: file.path.clone(),
            outcome: FileOutcome::AlreadyAbsent,
            witness: witness(
                WitnessState::Witnessed,
                "owned Fish PATH file already absent; custody preserved",
                None,
            ),
        },
        Ok(Some(mut owned)) => match owned.sha256() {
            Ok(actual) if actual == expected => FileEffect {
                path: file.path.clone(),
                outcome: FileOutcome::Unchanged,
                witness: witness(
                    WitnessState::Witnessed,
                    "owned Fish PATH file read back unchanged; custody preserved for replacement",
                    None,
                ),
            },
            Ok(_) => FileEffect {
                path: file.path.clone(),
                outcome: FileOutcome::ConflictKept,
                witness: witness(
                    WitnessState::Failed,
                    "owned Fish PATH file changed; preserved",
                    None,
                ),
            },
            Err(error) => FileEffect {
                path: file.path.clone(),
                outcome: FileOutcome::Unreadable,
                witness: witness(
                    WitnessState::Failed,
                    "owned Fish PATH file custody check failed",
                    Some(error.to_string()),
                ),
            },
        },
        Err(error) => FileEffect {
            path: file.path.clone(),
            outcome: FileOutcome::Unreadable,
            witness: witness(
                WitnessState::Failed,
                "owned Fish PATH file custody check failed",
                Some(error.to_string()),
            ),
        },
    }
}

/// Settles the record, created directories and recovery inventory once the
/// running image's outcome is known.
pub(super) fn settle(
    plan: &ValidatedUninstallPlan,
    parents: &[PathBuf],
    held: &mut HeldRecord,
    safe: bool,
    preserve: bool,
    clear_replace_custody: bool,
    effects: &mut UninstallEffects,
) {
    let image_removed = effects
        .install_files
        .iter()
        .all(|file| file_settled(file, preserve));
    let settled = safe && image_removed;
    effects.integrations.push(remove_record(held, settled));
    if settled && clear_replace_custody {
        if let Some(effect) = remove_stale_replace_custody(plan.state_home()) {
            effects.integrations.push(effect);
        }
    }
    remove_directories(plan, settled, effects);
    reconcile_recovery(plan, parents, effects);
}

fn remove_stale_replace_custody(state_home: &Path) -> Option<IntegrationEffect> {
    let path = state_home.join("standalone-install.replace.json");
    let (action, proof) = match OwnedFile::open(&path) {
        Ok(None) => return None,
        Ok(Some(mut file)) => match file
            .sha256()
            .and_then(|digest| file.remove(digest))
            .map_err(native_error)
        {
            Ok(()) => (
                FileOutcome::Removed,
                witness(
                    WitnessState::Witnessed,
                    "stale replacement custody removed on plain uninstall",
                    None,
                ),
            ),
            Err(error) => (
                FileOutcome::Unreadable,
                witness(
                    WitnessState::Failed,
                    "stale replacement custody removal failed",
                    Some(error.to_string()),
                ),
            ),
        },
        Err(error) => (
            FileOutcome::Unreadable,
            witness(
                WitnessState::Failed,
                "stale replacement custody inspection failed",
                Some(error.to_string()),
            ),
        ),
    };
    Some(IntegrationEffect {
        path: path.display().to_string(),
        entry: "stale replacement custody".into(),
        action,
        witness: proof,
    })
}

fn remove_record(held: &mut HeldRecord, settled: bool) -> IntegrationEffect {
    let (action, proof) = if settled {
        match (|| {
            held.file
                .take()
                .ok_or_else(|| conflict(&held.path.to_string_lossy()))?
                .remove(held.digest)
                .map_err(native_error)
        })() {
            Ok(()) => (
                FileOutcome::Removed,
                witness(
                    WitnessState::Witnessed,
                    "native owned record removal and outside absence",
                    None,
                ),
            ),
            Err(error) => (
                FileOutcome::Unreadable,
                witness(
                    WitnessState::Failed,
                    "owned installation record removal failed",
                    Some(error.to_string()),
                ),
            ),
        }
    } else {
        (
            FileOutcome::Pending,
            witness(
                WitnessState::Unknown,
                "record removal awaits witnessed image and installation effects",
                None,
            ),
        )
    };
    IntegrationEffect {
        path: held.path.display().to_string(),
        entry: "owned installation record".into(),
        action,
        witness: proof,
    }
}

fn remove_directories(
    plan: &ValidatedUninstallPlan,
    settled: bool,
    effects: &mut UninstallEffects,
) {
    let mut directories: Vec<_> = plan.created_directories().iter().collect();
    directories.sort_by_key(|path| std::cmp::Reverse(Path::new(path).components().count()));
    for path in directories {
        let (outcome, state, detail) = if !settled {
            (
                DirectoryOutcome::Pending,
                WitnessState::Unknown,
                Some("installed image or another effect remains unresolved".into()),
            )
        } else {
            match se_proc::remove_empty_directory(Path::new(path)) {
                Ok(DirectoryRemoval::Removed) => {
                    (DirectoryOutcome::Removed, WitnessState::Witnessed, None)
                }
                Ok(DirectoryRemoval::AlreadyAbsent) => (
                    DirectoryOutcome::AlreadyAbsent,
                    WitnessState::Witnessed,
                    None,
                ),
                Ok(DirectoryRemoval::NotEmpty) => (
                    DirectoryOutcome::NotEmptyPreserved,
                    WitnessState::Witnessed,
                    None,
                ),
                Err(error) => (
                    if error.code == StateFileErrorCode::LocationUnsafe {
                        DirectoryOutcome::Unsafe
                    } else {
                        DirectoryOutcome::Unreadable
                    },
                    WitnessState::Failed,
                    Some(error.to_string()),
                ),
            }
        };
        effects.directories.push(DirectoryEffect {
            path: path.clone(),
            outcome,
            witness: witness(
                state,
                "native empty-directory removal and outside readback",
                detail,
            ),
        });
    }
}

/// Only a successful native removal of a planned ancestor can explain why
/// a directory scanned before effects is now absent. Other failures stay visible.
fn reconcile_recovery(
    plan: &ValidatedUninstallPlan,
    parents: &[PathBuf],
    effects: &mut UninstallEffects,
) {
    for entry in recovery::merge(effects.recovery.clone(), scan(plan, parents)) {
        let removed = effects.directories.iter().any(|directory| {
            matches!(directory.outcome, DirectoryOutcome::Removed)
                && directory.witness.state == WitnessState::Witnessed
                && Path::new(&entry.directory).starts_with(&directory.path)
        });
        if let Some(before) = effects
            .recovery
            .iter_mut()
            .find(|old| old.directory == entry.directory)
        {
            if removed {
                before.witness = witness(
                    WitnessState::Witnessed,
                    "finite pre-effect inventory followed by native empty-directory removal and absence",
                    None,
                );
            } else {
                *before = entry;
            }
        }
    }
}
