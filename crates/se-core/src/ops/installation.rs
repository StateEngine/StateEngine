//! Explicit owned paths and non-secret PATH blocks; native custody executes the plan.
use super::outputs::{
    DirectoryEffect, FileEffect, IntegrationEffect, PathEffect, RecoveryDirectoryEffect,
    RevocationEffect, StopFact,
};
use se_types::{Result, SeError};
use sha2::{Digest, Sha256};
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
    /// Exact original profile length; absent on registry PATH edits and older records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_bytes: Option<u64>,
    pub block: String,
}
/// An exact tail repair, executed only against the same native file/digest.
#[derive(Clone, Debug)]
pub struct ProfileTruncation {
    pub expected_sha256: [u8; 32],
    pub length: u64,
}
impl UninstallPathEdit {
    /// Recognise a full or torn append only when every preceding byte matches
    /// the recorded original. A user edit or unrelated suffix yields no repair.
    pub fn profile_truncation(&self, contents: &[u8]) -> Result<Option<ProfileTruncation>> {
        if self.block.is_empty()
            || self.block.len() > 8192
            || self
                .before_sha256
                .as_ref()
                .is_some_and(|value| !digest(value))
        {
            return Err(SeError::invalid(
                "profile append recovery",
                "a bounded recorded block and optional original SHA-256",
            ));
        }
        let block = self.block.as_bytes();
        if let Some(length) = self.before_bytes {
            let Ok(split) = usize::try_from(length) else {
                return Ok(None);
            };
            if split >= contents.len() {
                return Ok(None);
            }
            let original_matches = match &self.before_sha256 {
                Some(expected) => format!("{:x}", Sha256::digest(&contents[..split])) == *expected,
                None => split == 0,
            };
            return Ok(
                (original_matches && block.starts_with(&contents[split..])).then(|| {
                    ProfileTruncation {
                        expected_sha256: Sha256::digest(contents).into(),
                        length,
                    }
                }),
            );
        }
        let first = contents.len().saturating_sub(block.len());
        let mut prefix = Sha256::new();
        prefix.update(&contents[..first]);
        for split in first..contents.len() {
            let tail = &contents[split..];
            if block.starts_with(tail) {
                let original_matches = match &self.before_sha256 {
                    Some(expected) => format!("{:x}", prefix.clone().finalize()) == *expected,
                    None => split == 0,
                };
                if original_matches {
                    return Ok(Some(ProfileTruncation {
                        expected_sha256: Sha256::digest(contents).into(),
                        length: split as u64,
                    }));
                }
            }
            prefix.update(&contents[split..split + 1]);
        }
        Ok(None)
    }
}
/// Name matching never substitutes for the native no-follow/current-user proof.
#[derive(Clone, Debug)]
pub enum TemporaryFileAuthority {
    Recorded { sha256: String },
    NativeOwnedName,
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
    pub fn temporary_file(&self, path: &Path) -> Result<Option<TemporaryFileAuthority>> {
        self.validate()?;
        if !path.is_absolute()
            || !self
                .recovery_directories()?
                .iter()
                .any(|parent| path.parent() == Some(parent.as_path()))
        {
            return Ok(None);
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Ok(None);
        };
        let Some(suffix) = name
            .strip_prefix(".se-profile-")
            .or_else(|| name.strip_prefix(".se-publish-"))
        else {
            return Ok(None);
        };
        if let Some(file) = self.files.iter().find(|file| Path::new(&file.path) == path) {
            return Ok(Some(TemporaryFileAuthority::Recorded {
                sha256: file.sha256.clone(),
            }));
        }
        Ok(
            (suffix.len() == 8 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()))
                .then_some(TemporaryFileAuthority::NativeOwnedName),
        )
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
                || (edit.before_sha256.is_none()
                    && edit.before_bytes.is_some_and(|length| length != 0))
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
mod receipt;
pub use receipt::finish_uninstall;
