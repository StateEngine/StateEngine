//! Preserve native effects even when final receipt validation cannot complete.
use super::{UninstallEffects, ValidatedUninstallPlan, bounded_path};
use crate::ops::outputs::*;
use se_types::{Detail, IdempotencyKey, Read, Result, SeError, details};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// This is completion after effects, not admission. A failed check must not
/// discard an already witnessed removal or turn an omitted readback into absence.
pub fn finish_uninstall(
    plan: &ValidatedUninstallPlan,
    key: IdempotencyKey,
    mut effects: UninstallEffects,
) -> Result<UninstallOutput> {
    let (complete, issues) = match check_readback(plan, &effects) {
        Ok(complete) => (complete, Vec::new()),
        Err(error) => (false, vec![error.body]),
    };
    if !complete {
        missing_outcomes(plan, &mut effects);
    }
    Ok(UninstallOutput {
        home_cleanup: None,
        idempotency_key: key,
        complete,
        install_files: effects.install_files,
        directories: effects.directories,
        integrations: effects.integrations,
        stops: effects.stops,
        revocations: effects.revocations,
        path: effects.path,
        preserved: effects.preserved,
        recovery: effects.recovery,
        issues,
    })
}

fn same_paths(
    planned: impl Iterator<Item = PathBuf>,
    actual: impl Iterator<Item = String>,
    actual_count: usize,
) -> bool {
    let expected: BTreeSet<_> = planned.collect();
    let observed: BTreeSet<_> = actual.map(PathBuf::from).collect();
    expected == observed && observed.len() == actual_count
}
fn check_readback(plan: &ValidatedUninstallPlan, effects: &UninstallEffects) -> Result<bool> {
    let recovery_directories = plan.recovery_directories();
    if !same_paths(
        recovery_directories.iter().cloned(),
        effects.recovery.iter().map(|entry| entry.directory.clone()),
        effects.recovery.len(),
    ) {
        return Err(SeError::invalid(
            "uninstall recovery readback",
            "one finite native recovery-sibling inventory for every exact planned parent directory",
        ));
    }
    let targets: BTreeSet<_> = plan
        .files()
        .iter()
        .map(|file| file.path.as_str())
        .chain(plan.path_edits().iter().map(|edit| edit.target.as_str()))
        .collect();
    for directory in &effects.recovery {
        if let se_types::Read::Present { value: copies } = &directory.copies {
            let mut seen = BTreeSet::new();
            if copies.len() > 256 {
                return Err(SeError::invalid(
                    "recovery inventory",
                    "at most 256 entries; an exhausted scan must report unreadable/incomplete",
                ));
            }
            for copy in copies {
                let path = Path::new(&copy.path);
                if !bounded_path(&copy.path)
                    || path.parent() != Some(Path::new(&directory.directory))
                    || !path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(".se-edit-backup-"))
                    || !seen.insert(&copy.path)
                    || copy.restored_to.as_ref().is_some_and(|target| {
                        !targets.contains(target.as_str())
                            || Path::new(target).parent() != path.parent()
                    })
                {
                    return Err(SeError::invalid(
                        "recovery copy",
                        "a unique exact backup sibling, preserved unless native proof restores an exact planned target in the same directory",
                    ));
                }
            }
        }
    }
    for directory in &effects.recovery {
        if let se_types::Read::Present { value: files } = &directory.temporary_files {
            let mut seen = BTreeSet::new();
            if files.len() > 256 {
                return Err(SeError::invalid(
                    "temporary-file inventory",
                    "at most 256 exact entries, otherwise an explicit incomplete result",
                ));
            }
            for file in files {
                let path = Path::new(&file.path);
                if !bounded_path(&file.path)
                    || path.parent() != Some(Path::new(&directory.directory))
                    || !seen.insert(&file.path)
                    || plan.temporary_file(path).is_none()
                {
                    return Err(SeError::invalid(
                        "temporary file",
                        "a unique recorded or exact eight-alphanumeric native-owned temporary sibling",
                    ));
                }
            }
        }
    }
    let recovery_complete = effects.recovery.iter().all(|entry| {
        entry.witness.state == WitnessState::Witnessed
            && match &entry.temporary_files {
                se_types::Read::Absent { .. } => true,
                se_types::Read::Present { value: files } => files.iter().all(|file| {
                    matches!(
                        file.outcome,
                        FileOutcome::Removed | FileOutcome::AlreadyAbsent
                    ) && file.witness.state == WitnessState::Witnessed
                }),
                _ => false,
            }
            && match &entry.copies {
                se_types::Read::Absent { .. } => true,
                se_types::Read::Present { value } => value.iter().all(|copy| {
                    copy.restored_to.is_some() && copy.witness.state == WitnessState::Witnessed
                }),
                _ => false,
            }
    });
    if !same_paths(
        plan.files().iter().map(|file| PathBuf::from(&file.path)),
        effects.install_files.iter().map(|file| file.path.clone()),
        effects.install_files.len(),
    ) || !same_paths(
        plan.created_directories().iter().map(PathBuf::from),
        effects
            .directories
            .iter()
            .map(|directory| directory.path.clone()),
        effects.directories.len(),
    ) {
        return Err(SeError::new(Detail::StateConflict(details::StateConflict {subject:"uninstall readback".into(),reason:"each exact planned file and directory requires its own outcome, including unreadable or conflicting paths".into(),next_step:"Read each owned path and retry without discarding unresolved outcomes.".into()})));
    }
    if plan.path_edits().iter().any(|edit| {
        !effects
            .integrations
            .iter()
            .any(|effect| effect.path == edit.target && effect.entry == edit.block)
    }) {
        return Err(SeError::new(Detail::StateConflict(
            details::StateConflict {
                subject: "uninstall PATH readback".into(),
                reason: "a planned PATH edit has no reported outcome".into(),
                next_step: "Inspect each recorded PATH target before retrying uninstall.".into(),
            },
        )));
    }
    let files_complete = effects.install_files.iter().all(|file| {
        matches!(
            file.outcome,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        ) && file.witness.state == WitnessState::Witnessed
    });
    let directories_complete = effects.directories.iter().all(|directory| {
        matches!(
            directory.outcome,
            DirectoryOutcome::Removed
                | DirectoryOutcome::AlreadyAbsent
                | DirectoryOutcome::NotEmptyPreserved
        ) && directory.witness.state == WitnessState::Witnessed
    });
    let integrations_complete = effects.integrations.iter().all(|entry| {
        matches!(
            entry.action,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        ) && entry.witness.state == WitnessState::Witnessed
    });
    Ok(files_complete
        && recovery_complete
        && directories_complete
        && integrations_complete
        && effects
            .stops
            .iter()
            .all(|stop| stop.complete && stop.witness.state == WitnessState::Witnessed)
        && effects
            .revocations
            .iter()
            .all(|revocation| revocation.witness.state == WitnessState::Witnessed)
        && effects.path_complete
        && effects.path.witness.state == WitnessState::Witnessed)
}

fn unobserved() -> Witness {
    Witness {
        state: WitnessState::Unknown,
        method: "no executor readback".into(),
        observed_at: "not observed".into(),
        detail: Some(
            "No outcome was supplied; inspect this path before retrying uninstall.".into(),
        ),
    }
}
fn missing_outcomes(plan: &ValidatedUninstallPlan, effects: &mut UninstallEffects) {
    let parents = plan.recovery_directories();
    for file in plan.files() {
        if !effects
            .install_files
            .iter()
            .any(|effect| effect.path == file.path)
        {
            effects.install_files.push(FileEffect {
                path: file.path.clone(),
                outcome: FileOutcome::Pending,
                witness: unobserved(),
            });
        }
    }
    for path in plan.created_directories() {
        if !effects
            .directories
            .iter()
            .any(|effect| &effect.path == path)
        {
            effects.directories.push(DirectoryEffect {
                path: path.clone(),
                outcome: DirectoryOutcome::Pending,
                witness: unobserved(),
            });
        }
    }
    for edit in plan.path_edits() {
        if !effects
            .integrations
            .iter()
            .any(|effect| effect.path == edit.target && effect.entry == edit.block)
        {
            effects.integrations.push(IntegrationEffect {
                path: edit.target.clone(),
                entry: edit.block.clone(),
                action: FileOutcome::Pending,
                witness: unobserved(),
            });
        }
    }
    for directory in parents {
        let directory = directory.display().to_string();
        if !effects
            .recovery
            .iter()
            .any(|effect| effect.directory == directory)
        {
            effects.recovery.push(RecoveryDirectoryEffect {
                directory,
                copies: Read::Unknown {
                    what: "recovery copies were not inventoried".into(),
                },
                temporary_files: Read::Unknown {
                    what: "installer temporaries were not inventoried".into(),
                },
                witness: unobserved(),
            });
        }
    }
}
