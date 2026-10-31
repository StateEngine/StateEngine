//! Installation input adapter. Core owns uninstall admission, plans and receipts.
//! These read-only observations do not grant custody for a later file mutation.
use se_core::ops::installation::{UninstallFile, UninstallPathEdit, UninstallPlan};
use se_types::{Detail, Result, SeError, Sha256, details};
use serde::Deserialize;
use sha2::{Digest, Sha256 as Hasher};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

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
    pub fn plan(&self) -> Result<UninstallPlan> {
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
        plan.validate()?;
        Ok(plan)
    }
}

/// The executor applies one of these through its native file/registry custody
/// adapter, then obtains a new outside readback. These are never receipts.
pub enum EntryChange {
    AlreadyAbsent,
    Replace(String),
    RemoveCreatedTarget,
}

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

/// Load the record in the StateEngine data home. The supplied owner is a native
/// adapter observation, never a command-line claim. The executor must reacquire
/// no-follow custody and compare actual bytes before applying the core plan.
pub fn read_installation(
    home: &Path,
    executable: &Path,
    verified_owner: &str,
) -> Result<Installation> {
    absolute_clean(executable)?;
    inspect_no_links(executable)?;
    absolute_clean(home)?;
    let record_path = home.join("standalone-install.json");
    inspect_no_links(&record_path)?;
    let mut claimed = se_proc::OwnedFile::open(&record_path)
        .map_err(|error| {
            se_core::scope::unreadable("installation record", &error.to_string()).with_cause(error)
        })?
        .ok_or_else(|| invalid("installation record is absent"))?;
    claimed.claim_installation_record().map_err(|error| {
        se_core::scope::unreadable("installation record", &error.to_string()).with_cause(error)
    })?;
    let bytes = claimed.read(1024 * 1024).map_err(|error| {
        se_core::scope::unreadable("installation record", &error.to_string()).with_cause(error)
    })?;
    let record: InstallRecord = serde_json::from_slice(&bytes).map_err(|error| {
        // Display only the decoder position. A PATH/profile may contain private
        // user data; never include record source bytes in a diagnostic.
        invalid(&format!(
            "invalid installation record at line {}, column {}",
            error.line(),
            error.column()
        ))
        .with_cause(error)
    })?;
    if record.schema != "stateengine-install/v1" {
        return Err(invalid("expected stateengine-install/v1"));
    }
    if record.owner != verified_owner || verified_owner.is_empty() {
        return Err(SeError::new(Detail::OsUserMismatch(
            details::OsUserMismatch {
                expected: record.owner.clone(),
                actual: verified_owner.into(),
            },
        )));
    }
    let mut files = BTreeSet::new();
    let mut contains_image = false;
    for file in &record.files {
        absolute_clean(&file.path)?;
        if !files.insert(file.path.clone()) {
            return Err(invalid("installation record repeats an owned file"));
        }
        if file.path == executable {
            contains_image = true;
        }
    }
    if !contains_image {
        return Err(invalid(
            "installation record does not own the running executable",
        ));
    }
    let mut directories = BTreeSet::new();
    for directory in &record.created_directories {
        absolute_clean(directory)?;
        if !directories.insert(directory) {
            return Err(invalid("installation record repeats a created directory"));
        }
    }
    let mut targets = BTreeSet::new();
    for edit in &record.path_edits {
        if !targets.insert(&edit.target) {
            return Err(invalid("installation record repeats a PATH target"));
        }
        #[cfg(target_os = "windows")]
        if edit.target != "HKCU\\Environment\\Path" {
            return Err(invalid(
                "Windows installation may edit only HKCU\\Environment\\Path",
            ));
        }
        #[cfg(not(target_os = "windows"))]
        absolute_clean(Path::new(&edit.target))?;
    }
    let installation = Installation {
        record_path,
        record,
    };
    installation.plan()?;
    Ok(installation)
}

fn absolute_clean(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid(
            "installation paths must be absolute and contain no dot components",
        ));
    }
    Ok(())
}

/// Read-only preflight. A successful walk is not a held no-follow native handle.
fn inspect_no_links(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !current.is_absolute() {
            continue;
        }
        let metadata =
            std::fs::symlink_metadata(&current).map_err(|error| unreadable(&current, error))?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(invalid(&format!(
                "installation path {} is a link or reparse point",
                current.display()
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn is_reparse_point(_: &std::fs::Metadata) -> bool {
    false
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
) -> Result<(UninstallPlan, se_core::ops::installation::UninstallEffects)> {
    uninstall::execute(cx, diagnostic)
}

#[cfg(windows)]
#[path = "runtime/handoff.rs"]
pub(crate) mod handoff;

#[cfg(windows)]
pub(crate) mod helper_cleanup;

#[path = "runtime/host.rs"]
pub mod host;
