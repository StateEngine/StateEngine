//! Installation input adapter. Core owns uninstall admission, plans and receipts.
//! These read-only observations do not grant custody for a later file mutation.
use se_core::ops::installation::{
    UninstallFile, UninstallPathEdit, UninstallPlan, ValidatedUninstallPlan,
};
use se_types::{Detail, Result, SeError, Sha256, details};
use serde::Deserialize;
use sha2::{Digest, Sha256 as Hasher};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRecord {
    pub schema: String,
    pub owner: String,
    pub files: Vec<InstallFile>,
    pub created_directories: Vec<PathBuf>,
    pub path_edits: Vec<PathEdit>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallFile {
    pub path: PathBuf,
    pub sha256: Sha256,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathEdit {
    pub target: String,
    // None records absence, not an empty prior file/value. Profile text is not copied.
    #[serde(deserialize_with = "nullable_before")]
    pub before_sha256: Option<Sha256>,
    pub block: String,
    #[serde(default)]
    pub before_bytes: Option<u64>,
}

fn nullable_before<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<Sha256>, D::Error> {
    Option::<Sha256>::deserialize(decoder)
}

#[derive(Debug)]
pub struct Installation {
    pub record_path: PathBuf,
    pub record: InstallRecord,
}

impl Installation {
    /// Translate observations into the one core-owned plan. This validates
    /// protected history/configuration exclusions before any executor runs.
    pub fn plan(&self) -> Result<ValidatedUninstallPlan> {
        let state_home = self
            .record_path
            .parent()
            .ok_or_else(|| invalid("installation record has no state home"))?;
        let path_text = |path: &Path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("installation paths must be valid UTF-8"))
        };
        let plan = UninstallPlan {
            state_home: state_home.to_owned(),
            owner: self.record.owner.clone(),
            files: self
                .record
                .files
                .iter()
                .map(|file| {
                    Ok(UninstallFile {
                        path: path_text(&file.path)?,
                        sha256: file.sha256.hex(),
                    })
                })
                .collect::<Result<_>>()?,
            created_directories: self
                .record
                .created_directories
                .iter()
                .map(|path| path_text(path))
                .collect::<Result<_>>()?,
            path_edits: self
                .record
                .path_edits
                .iter()
                .map(|edit| UninstallPathEdit {
                    target: edit.target.clone(),
                    before_sha256: edit.before_sha256.as_ref().map(Sha256::hex),
                    block: edit.block.clone(),
                    before_bytes: edit.before_bytes,
                })
                .collect(),
        };
        plan.validate()
    }
}

/// The executor applies one of these through its native file/registry custody
/// adapter, then obtains a new outside readback. These are never receipts.
pub enum EntryChange {
    AlreadyAbsent,
    Replace(String),
    RemoveCreatedTarget,
}

#[cfg(not(windows))]
pub fn remove_profile_block(
    path: &str,
    current: Option<&str>,
    edit: &PathEdit,
) -> Result<EntryChange> {
    let Some(current) = current else {
        return Ok(EntryChange::AlreadyAbsent);
    };
    if edit.block.is_empty() {
        return Err(invalid("owned profile block is empty"));
    }
    let mut matches = current.match_indices(&edit.block);
    let found = matches.next();
    if matches.next().is_some() {
        return Err(conflict(path));
    }
    match found {
        Some((start, block)) => {
            let mut after = String::with_capacity(current.len() - block.len());
            after.push_str(&current[..start]);
            after.push_str(&current[start + block.len()..]);
            if after.is_empty() && edit.before_sha256.is_none() {
                Ok(EntryChange::RemoveCreatedTarget)
            } else {
                Ok(EntryChange::Replace(after))
            }
        }
        None if matches_before(current, edit.before_sha256.as_ref()) => {
            Ok(EntryChange::AlreadyAbsent)
        }
        None => Err(conflict(path)),
    }
}

#[cfg(windows)]
pub fn remove_path_entry(current: Option<&str>, edit: &PathEdit) -> Result<EntryChange> {
    let Some(current) = current else {
        return Ok(EntryChange::AlreadyAbsent);
    };
    if edit.block.is_empty() || edit.block.contains(';') {
        return Err(invalid(
            "owned user-PATH entry is empty or contains a separator",
        ));
    }
    let mut entries: Vec<_> = current.split(';').collect();
    let selected: Vec<_> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.eq_ignore_ascii_case(&edit.block))
        .map(|(index, _)| index)
        .collect();
    match selected.as_slice() {
        [index] if entries[*index] == edit.block => {
            if current == edit.block && edit.before_sha256.is_none() {
                return Ok(EntryChange::RemoveCreatedTarget);
            }
            entries.remove(*index);
            Ok(EntryChange::Replace(entries.join(";")))
        }
        [] if matches_before(current, edit.before_sha256.as_ref()) => {
            Ok(EntryChange::AlreadyAbsent)
        }
        _ => Err(conflict(&edit.target)),
    }
}

fn matches_before(value: &str, expected: Option<&Sha256>) -> bool {
    match expected {
        Some(expected) => Hasher::digest(value.as_bytes()).as_slice() == expected.as_bytes(),
        None => value.is_empty(),
    }
}

fn conflict(path: &str) -> SeError {
    SeError::new(Detail::IntegrationConflict(details::IntegrationConflict {
        path: path.into(),
        entry: "owned StateEngine PATH block or entry".into(),
    }))
}

fn invalid(reason: &str) -> SeError {
    SeError::new(Detail::ConfigurationInvalid(details::ConfigurationInvalid {
        subject: "installation record".into(),
        reason: reason.into(),
        next_step: "Preserve the installation and restore its matching owned record before retrying uninstall".into(),
    }))
}

fn unreadable(path: &Path, error: std::io::Error) -> SeError {
    SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
        subject: path.display().to_string(),
        reason: error.to_string(),
        next_step: "Restore access to the installation record; no removal was attempted".into(),
    }))
    .with_cause(error)
}

#[path = "runtime/uninstall.rs"]
mod uninstall;
pub fn uninstall(
    cx: &crate::bootstrap::Bootstrap,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<(
    ValidatedUninstallPlan,
    se_core::ops::installation::UninstallEffects,
)> {
    uninstall::execute(cx, diagnostic)
}

#[cfg(windows)]
#[path = "runtime/handoff.rs"]
pub(crate) mod handoff;

#[cfg(windows)]
pub(crate) mod helper_cleanup;

#[path = "runtime/host.rs"]
pub mod host;
