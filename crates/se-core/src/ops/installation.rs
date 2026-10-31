//! Explicit owned paths and non-secret PATH blocks; native custody executes the plan.
use super::outputs::{
    DirectoryEffect, DirectoryOutcome, FileEffect, FileOutcome, IntegrationEffect, PathEffect,
    RecoveryDirectoryEffect, RevocationEffect, StopFact, UninstallOutput, WitnessState,
};
use se_types::{Detail, IdempotencyKey, Result, SeError, details};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallFile {
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallPathEdit {
    pub target: String,
    pub before_sha256: Option<String>,
    pub block: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallPlan {
    /// Native bootstrap supplies the actual state home; this is not an install root.
    pub state_home: PathBuf,
    pub owner: String,
    pub files: Vec<UninstallFile>,
    pub created_directories: Vec<String>,
    pub path_edits: Vec<UninstallPathEdit>,
}
fn absolute(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}
fn bounded_path(path: &str) -> bool {
    !path.is_empty() && path.len() <= 32768 && !path.contains('\0') && absolute(path)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl UninstallPlan {
    /// Scan these held native directories before any installation/PATH effect.
    /// The adapter reports every .se-edit-backup-* sibling, even when ownership
    /// or association cannot be proved, and preserves any unresolved copy.
    pub fn recovery_directories(&self) -> Result<Vec<PathBuf>> {
        self.validate()?;
        Ok(self
            .files
            .iter()
            .map(|file| Path::new(&file.path))
            .chain(
                self.path_edits
                    .iter()
                    .map(|edit| Path::new(&edit.target))
                    .filter(|path| path.is_absolute()),
            )
            .filter_map(Path::parent)
            .map(Path::to_path_buf)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    pub fn validate(&self) -> Result<()> {
        if !self.state_home.is_absolute()
            || self
                .state_home
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || self.owner.is_empty()
            || self.owner.len() > 512
            || self.owner.contains('\0')
        {
            return Err(SeError::invalid(
                "installation",
                "a native absolute state home and verified bounded OS owner",
            ));
        }
        if self.files.is_empty()
            || self.files.len() > 256
            || self.created_directories.len() > 128
            || self.path_edits.len() > 16
        {
            return Err(SeError::invalid(
                "installation manifest",
                "1..256 exact owned files, at most 128 created directories and 16 PATH edits",
            ));
        }
        let protected_files = [
            "state.db",
            "state.db-wal",
            "state.db-shm",
            "atlas.db",
            "atlas.db-wal",
            "atlas.db-shm",
            "config.toml",
        ];
        let protected_trees = ["backups", "pins", "launches", "logs"];
        let mut files = BTreeSet::new();
        for file in &self.files {
            let path = Path::new(&file.path);
            if !bounded_path(&file.path)
                || path.file_name().is_none()
                || !digest(&file.sha256)
                || !files.insert(path.to_path_buf())
            {
                return Err(SeError::invalid(
                    "owned file",
                    "a unique exact absolute path and lowercase SHA-256",
                ));
            }
            if protected_files
                .iter()
                .any(|name| path == self.state_home.join(name))
                || protected_trees
                    .iter()
                    .any(|name| path.starts_with(self.state_home.join(name)))
            {
                return Err(SeError::invalid(
                    "owned file",
                    "installation assets only; history, backups, credentials, configuration and logs are preserved",
                ));
            }
        }
        let mut directories = BTreeSet::new();
        for directory in &self.created_directories {
            let path = Path::new(directory);
            if !bounded_path(directory)
                || path.parent().is_none()
                || !directories.insert(path.to_path_buf())
                || files.contains(path)
            {
                return Err(SeError::invalid(
                    "created directory",
                    "a unique exact non-root absolute path, removed only if empty",
                ));
            }
        }
        let mut targets = BTreeSet::new();
        for edit in &self.path_edits {
            let target_ok = if cfg!(windows) {
                edit.target == "HKCU\\Environment\\Path"
            } else {
                bounded_path(&edit.target) && Path::new(&edit.target).file_name().is_some()
            };
            if !target_ok
                || !targets.insert(&edit.target)
                || edit.block.is_empty()
                || edit.block.len() > 8192
                || edit.block.contains('\0')
                || edit.before_sha256.as_ref().is_some_and(|v| !digest(v))
            {
                return Err(SeError::invalid(
                    "PATH edit",
                    "a unique native target, optional prior SHA-256 and bounded non-secret inserted block/entry",
                ));
            }
        }
        Ok(())
    }
    pub fn file_path(&self, index: usize) -> Result<PathBuf> {
        self.validate()?;
        self.files
            .get(index)
            .map(|file| PathBuf::from(&file.path))
            .ok_or_else(|| {
                SeError::invalid(
                    "uninstall file index",
                    "an exact owned file in the admitted manifest",
                )
            })
    }
}
#[derive(Clone, Debug)]
pub struct UninstallEffects {
    pub install_files: Vec<FileEffect>,
    pub directories: Vec<DirectoryEffect>,
    pub integrations: Vec<IntegrationEffect>,
    pub stops: Vec<StopFact>,
    pub revocations: Vec<RevocationEffect>,
    pub path: PathEffect,
    /// Removing the exact owned block/entry is distinct from observing a user edit.
    pub path_complete: bool,
    pub preserved: Vec<String>,
    pub recovery: Vec<RecoveryDirectoryEffect>,
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
pub fn finish_uninstall(
    plan: &UninstallPlan,
    key: IdempotencyKey,
    effects: UninstallEffects,
) -> Result<UninstallOutput> {
    plan.validate()?;
    let recovery_directories = plan.recovery_directories()?;
    if !same_paths(
        recovery_directories.into_iter(),
        effects.recovery.iter().map(|entry| entry.directory.clone()),
        effects.recovery.len(),
    ) {
        return Err(SeError::invalid(
            "uninstall recovery readback",
            "one finite native recovery-sibling inventory for every exact planned parent directory",
        ));
    }
    let targets: BTreeSet<_> = plan
        .files
        .iter()
        .map(|file| file.path.as_str())
        .chain(plan.path_edits.iter().map(|edit| edit.target.as_str()))
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
    let recovery_complete = effects.recovery.iter().all(|entry| {
        entry.witness.state == WitnessState::Witnessed
            && match &entry.copies {
                se_types::Read::Absent { .. } => true,
                se_types::Read::Present { value } => value.iter().all(|copy| {
                    copy.restored_to.is_some() && copy.witness.state == WitnessState::Witnessed
                }),
                _ => false,
            }
    });
    if !same_paths(
        plan.files.iter().map(|file| PathBuf::from(&file.path)),
        effects.install_files.iter().map(|file| file.path.clone()),
        effects.install_files.len(),
    ) || !same_paths(
        plan.created_directories.iter().map(PathBuf::from),
        effects
            .directories
            .iter()
            .map(|directory| directory.path.clone()),
        effects.directories.len(),
    ) {
        return Err(SeError::new(Detail::StateConflict(details::StateConflict {subject:"uninstall readback".into(),reason:"each exact planned file and directory requires its own outcome, including unreadable or conflicting paths".into(),next_step:"Read each owned path and retry without discarding unresolved outcomes.".into()})));
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
    let complete = files_complete
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
        && effects.path.witness.state == WitnessState::Witnessed;
    Ok(UninstallOutput {
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
    })
}
