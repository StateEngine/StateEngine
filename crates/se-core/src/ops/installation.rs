//! A validated file-only uninstall plan and completion from independently read effects.
//! Native staging, owner/terminal proof, stop and parent/helper custody stay in adapters.
use super::outputs::{
    FileEffect, FileOutcome, IntegrationEffect, PathEffect, RevocationEffect, StopFact,
    UninstallOutput, WitnessState,
};
use se_types::{Detail, IdempotencyKey, Result, SeError, details};
use std::{
    collections::BTreeSet,
    path::{Component, PathBuf},
};

#[derive(Clone, Debug)]
pub struct UninstallFile {
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug)]
pub struct UninstallPathEdit {
    pub target: String,
    pub before: Option<String>,
    pub after: String,
}
#[derive(Clone, Debug)]
pub struct UninstallPlan {
    pub install_root: PathBuf,
    pub owner: String,
    pub files: Vec<UninstallFile>,
    pub path_edits: Vec<UninstallPathEdit>,
}
impl UninstallPlan {
    pub fn validate(&self) -> Result<()> {
        if !self.install_root.is_absolute()
            || self.owner.is_empty()
            || self.owner.len() > 512
            || self.owner.contains('\0')
        {
            return Err(SeError::invalid(
                "installation",
                "an absolute native install root and bounded verified OS owner",
            ));
        }
        if self.files.is_empty() || self.files.len() > 256 || self.path_edits.len() > 16 {
            return Err(SeError::invalid(
                "installation manifest",
                "1..256 owned files and at most 16 exact PATH edits",
            ));
        }
        let mut names = BTreeSet::new();
        for file in &self.files {
            let path = PathBuf::from(&file.path);
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || file.path.is_empty()
                || file.path.len() > 32768
                || file.path.contains('\0')
                || file.path.contains(':')
                || file.path.starts_with(['/', '\\'])
                || file
                    .path
                    .split(['/', '\\'])
                    .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return Err(SeError::invalid(
                    "owned installation file",
                    "a relative path without prefixes or parent traversal; native custody must reject links",
                ));
            }
            if !names.insert(file.path.replace('\\', "/")) {
                return Err(SeError::invalid(
                    "installation manifest",
                    "unique owned file paths",
                ));
            }
            if file.sha256.len() != 64
                || !file
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(SeError::invalid(
                    "file sha256",
                    "64 lowercase hexadecimal digits",
                ));
            }
        }
        let mut targets = BTreeSet::new();
        for edit in &self.path_edits {
            if edit.target.is_empty()
                || edit.target.len() > 32768
                || edit.target.contains('\0')
                || !targets.insert(&edit.target)
                || edit.after.len() > 1024 * 1024
                || edit.before.as_ref().is_some_and(|v| v.len() > 1024 * 1024)
            {
                return Err(SeError::invalid(
                    "PATH edit",
                    "a unique exact native target and bounded before/after bytes",
                ));
            }
            if cfg!(windows) {
                if edit.target != "HKCU\\Environment\\Path" {
                    return Err(SeError::invalid(
                        "PATH edit target",
                        "HKCU\\Environment\\Path",
                    ));
                }
            } else if !PathBuf::from(&edit.target).is_absolute() {
                return Err(SeError::invalid(
                    "PATH edit target",
                    "an absolute owned login-profile path",
                ));
            }
        }
        Ok(())
    }
    pub fn file_path(&self, index: usize) -> Result<PathBuf> {
        self.validate()?;
        let file = self.files.get(index).ok_or_else(|| {
            SeError::invalid("uninstall file index", "an entry in the admitted manifest")
        })?;
        Ok(self.install_root.join(&file.path))
    }
}
#[derive(Clone, Debug)]
pub struct UninstallEffects {
    pub install_files: Vec<FileEffect>,
    pub integrations: Vec<IntegrationEffect>,
    pub stops: Vec<StopFact>,
    pub revocations: Vec<RevocationEffect>,
    pub path: PathEffect,
    pub preserved: Vec<String>,
}
pub fn finish_uninstall(
    plan: &UninstallPlan,
    key: IdempotencyKey,
    effects: UninstallEffects,
) -> Result<UninstallOutput> {
    plan.validate()?;
    let expected_paths: BTreeSet<_> = plan
        .files
        .iter()
        .map(|file| {
            plan.install_root
                .join(&file.path)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let effect_paths: BTreeSet<_> = effects
        .install_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    if effects.install_files.len() != plan.files.len() || effect_paths != expected_paths {
        return Err(SeError::new(Detail::StateConflict(details::StateConflict {subject:"uninstall readback".into(),reason:"each planned file requires its own outcome, including unreadable or conflicting files".into(),next_step:"Read each owned path and retry without discarding unresolved outcomes.".into()})));
    }
    let files_complete = effects.install_files.iter().all(|file| {
        matches!(
            file.outcome,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        ) && file.witness.state == WitnessState::Witnessed
    });
    let integrations_complete = effects.integrations.iter().all(|entry| {
        matches!(
            entry.action,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        ) && entry.witness.state == WitnessState::Witnessed
    });
    let complete = files_complete
        && integrations_complete
        && effects
            .stops
            .iter()
            .all(|stop| stop.complete && stop.witness.state == WitnessState::Witnessed)
        && effects
            .revocations
            .iter()
            .all(|revocation| revocation.witness.state == WitnessState::Witnessed)
        && effects.path.witness.state == WitnessState::Witnessed;
    Ok(UninstallOutput {
        idempotency_key: key,
        complete,
        install_files: effects.install_files,
        integrations: effects.integrations,
        stops: effects.stops,
        revocations: effects.revocations,
        path: effects.path,
        preserved: effects.preserved,
    })
}
