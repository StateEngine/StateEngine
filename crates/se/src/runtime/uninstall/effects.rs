use super::*;
pub(super) fn native_error(error: StateFileError) -> SeError {
    se_core::scope::unreadable("native installation custody", &error.to_string()).with_cause(error)
}
pub(super) fn clock() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => format!(
            "{}.{:09}Z (Unix seconds)",
            value.as_secs(),
            value.subsec_nanos()
        ),
        Err(error) => format!("clock unreadable: {error}"),
    }
}
pub(super) fn witness(state: WitnessState, method: &str, detail: Option<String>) -> Witness {
    Witness {
        state,
        method: method.into(),
        observed_at: clock(),
        detail,
    }
}
pub(super) fn file_effect(
    path: &str,
    outcome: FileOutcome,
    state: WitnessState,
    detail: &str,
) -> FileEffect {
    FileEffect {
        path: path.into(),
        outcome,
        witness: witness(
            state,
            "held native file custody and independent pathname readback",
            Some(detail.into()),
        ),
    }
}
pub(super) fn digest_bytes(value: &str) -> Result<[u8; 32]> {
    Ok(Sha256::parse_hex(value)?.as_bytes().to_owned())
}
pub(super) fn remove_file(file: &UninstallFile) -> FileEffect {
    let result: std::result::Result<bool, StateFileError> = (|| {
        let Some(pin) = OwnedFile::open(Path::new(&file.path))? else {
            return Ok(false);
        };
        let expected = digest_bytes(&file.sha256).map_err(|_| se_proc::StateFileError {
            code: StateFileErrorCode::SourceChanged,
            operation: "invalid planned digest",
            path: PathBuf::from(&file.path),
            source: None,
        })?;
        pin.remove(expected)?;
        Ok(true)
    })();
    match result {
        Ok(removed) => file_effect(
            &file.path,
            if removed {
                FileOutcome::Removed
            } else {
                FileOutcome::AlreadyAbsent
            },
            WitnessState::Witnessed,
            "fresh no-follow native absence",
        ),
        Err(error) => file_effect(
            &file.path,
            if matches!(
                error.code,
                StateFileErrorCode::SourceChanged | StateFileErrorCode::LocationUnsafe
            ) {
                FileOutcome::ConflictKept
            } else {
                FileOutcome::Unreadable
            },
            WitnessState::Failed,
            &error.to_string(),
        ),
    }
}
pub(super) fn scan(
    plan: &ValidatedUninstallPlan,
    parents: &[PathBuf],
) -> Vec<RecoveryDirectoryEffect> {
    parents.iter().map(|directory| {
        let (copies,state,detail)=match se_proc::scan_recovery(directory) {
            Ok(paths)=>(Read::Present {value:paths.into_iter().map(|path|RecoveryCopy {path:path.display().to_string(),restored_to:None,
                witness:witness(WitnessState::Unknown,"recovery sibling preserved; filename grants no mutation authority",None)}).collect()},WitnessState::Witnessed,None),
            Err(error) if error.source.as_ref().is_some_and(|cause|cause.kind()==io::ErrorKind::NotFound)=>(Read::Absent { checked:format!("native no-follow directory lookup: {error}; {}",clock()) },WitnessState::Witnessed,None),
            Err(error)=>(Read::Unreadable {source:directory.display().to_string(),reason:error.to_string(),error:None},WitnessState::Failed,Some(error.to_string())),
        };
        RecoveryDirectoryEffect {directory:directory.display().to_string(),copies,temporary_files:temporary_inventory(plan,directory),witness:witness(state,"finite native no-follow recovery-sibling scan",detail)}
    }).collect()
}
pub(super) fn pending_assets(
    plan: &ValidatedUninstallPlan,
    effects: &mut UninstallEffects,
    reason: &str,
) {
    effects.install_files = plan
        .files()
        .iter()
        .map(|file| {
            file_effect(
                &file.path,
                FileOutcome::Pending,
                WitnessState::Unknown,
                reason,
            )
        })
        .collect();
    effects.directories = plan
        .created_directories()
        .iter()
        .map(|path| DirectoryEffect {
            path: path.clone(),
            outcome: DirectoryOutcome::Pending,
            witness: witness(
                WitnessState::Unknown,
                "directory preserved before installation effects",
                Some(reason.into()),
            ),
        })
        .collect();
    effects.path.witness = witness(
        WitnessState::Unknown,
        "PATH preserved before installation effects",
        Some(reason.into()),
    );
}
pub(super) fn preserved(home: &Path) -> Vec<String> {
    [
        "state.db",
        "atlas.db",
        "config.toml",
        "backups",
        "pins",
        "launches",
        "logs",
    ]
    .iter()
    .map(|name| home.join(name).display().to_string())
    .collect()
}

fn temporary_inventory(plan: &ValidatedUninstallPlan, directory: &Path) -> Read<Vec<FileEffect>> {
    let names = match se_proc::scan_temporary(directory) {
        Ok(names) => names,
        Err(error)
            if error
                .source
                .as_ref()
                .is_some_and(|cause| cause.kind() == io::ErrorKind::NotFound) =>
        {
            return Read::Absent {
                checked: format!("native no-follow directory lookup: {error}; {}", clock()),
            };
        }
        Err(error) => {
            return Read::Unreadable {
                source: directory.display().to_string(),
                reason: error.to_string(),
                error: None,
            };
        }
    };
    Read::Present {
        value: names.into_iter()
            .filter(|path| plan.temporary_file(path).is_some())
            .map(|path| file_effect(&path.to_string_lossy(), FileOutcome::Pending, WitnessState::Unknown,
                "matching installer temporary name observed; native claim and leaf custody required before cleanup"))
            .collect(),
    }
}

/// The non-cloneable account-wide guard excludes every conforming installer,
/// including a child whose holder died. Only exact core-approved names in
/// planned parents receive native no-follow/current-user file custody.
pub(super) fn cleanup_temporary(
    plan: &ValidatedUninstallPlan,
    _claim: &se_proc::NativeInstallationClaim,
    directories: &mut [RecoveryDirectoryEffect],
) {
    use se_core::ops::installation::TemporaryFileAuthority;
    for directory in directories {
        let Read::Present { value: files } = &mut directory.temporary_files else {
            continue;
        };
        for file in files {
            let result: Result<FileEffect> = (|| {
                let path = Path::new(&file.path);
                let authority = plan
                    .temporary_file(path)
                    .ok_or_else(|| invalid("temporary name is outside the admitted plan"))?;
                let Some(mut pin) = OwnedFile::open(path).map_err(native_error)? else {
                    return Ok(file_effect(
                        &file.path,
                        FileOutcome::AlreadyAbsent,
                        WitnessState::Witnessed,
                        "native no-follow absence under shared installation claim",
                    ));
                };
                let digest = match authority {
                    TemporaryFileAuthority::Recorded { sha256 } => digest_bytes(&sha256)?,
                    TemporaryFileAuthority::NativeOwnedName => {
                        pin.sha256().map_err(native_error)?
                    }
                };
                pin.remove(digest).map_err(native_error)?;
                Ok(file_effect(
                    &file.path,
                    FileOutcome::Removed,
                    WitnessState::Witnessed,
                    "exact planned staging name, shared native installer claim, owned regular single-link file and outside absence",
                ))
            })();
            *file = result.unwrap_or_else(|error| {
                file_effect(
                    &file.path,
                    FileOutcome::ConflictKept,
                    WitnessState::Failed,
                    &error.to_string(),
                )
            });
        }
    }
}
