//! Explicit user-started provider registration. Hook payloads are signals;
//! only protected registration and native ancestry can authorize a binding.
use se_types::{NativePath, ProjectId, Result, SeError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
};
#[cfg(feature = "listener")]
pub mod metadata;
pub mod settings;
pub mod status;
pub const JOURNAL: &str = "claude-adoption.json";
const LIMIT: usize = 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project: ProjectId,
    pub root: NativePath,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub schema: u16,
    pub settings: NativePath,
    pub provider: NativePath,
    pub config_home: NativePath,
    pub hooks: Vec<(String, serde_json::Value)>,
    pub layout: settings::Layout,
    pub installed: bool,
    pub projects: Vec<Project>,
}
impl Registration {
    pub fn project(&self, cwd: &Path) -> Result<Option<&Project>> {
        if self.schema != 1 || self.projects.len() > 4096 {
            return Err(invalid("the supported bounded adoption journal"));
        }
        // Exact registered roots only. A hook in an unrelated child project
        // cannot inherit an ancestor's registration or caller session.
        Ok(self
            .projects
            .iter()
            .find(|p| p.root.to_local().is_ok_and(|root| root == cwd)))
    }
}
pub fn read(home: &Path) -> Result<Option<Registration>> {
    let files = match se_proc::NativeStateFiles::open(home) {
        Ok(files) => files,
        Err(error)
            if error
                .source
                .as_ref()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(native(error)),
    };
    let Some(file) = files.readback(&home.join(JOURNAL)).map_err(native)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    crate::client::wire::decode_json(&bytes, LIMIT).map(Some)
}
pub fn publish(home: &Path, registration: &Registration) -> Result<()> {
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    let path = home.join(JOURNAL);
    let bytes = serde_json::to_vec(registration).map_err(|_| invalid("serializable journal"))?;
    if bytes.len() > LIMIT {
        return Err(invalid("journal within one MiB"));
    }
    if let Some(mut previous) = se_proc::OwnedFile::open(&path).map_err(native)? {
        let hash = previous.sha256().map_err(native)?;
        previous.replace(hash, &bytes).map_err(native)
    } else {
        let mut staged = files.create_staging(home).map_err(native)?;
        staged.file.write_all(&bytes).map_err(io)?;
        staged.file.sync_all().map_err(io)?;
        drop(staged.file);
        files
            .publish_no_replace(&staged.path, &path)
            .map_err(native)
    }
}
pub fn remove(home: &Path) -> Result<()> {
    let path = home.join(JOURNAL);
    if let Some(mut file) = se_proc::OwnedFile::open(&path).map_err(native)? {
        let digest = file.sha256().map_err(native)?;
        file.remove(digest).map_err(native)?;
    }
    Ok(())
}
pub(crate) fn invalid(expected: &str) -> SeError {
    SeError::invalid("provider adoption", expected)
}
pub(crate) fn native(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("provider adoption file", &error.to_string()).with_cause(error)
}
pub(crate) fn io(error: std::io::Error) -> SeError {
    se_core::scope::unreadable("provider adoption file", &error.to_string())
}
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Start,
    Prompt,
    Capture,
    Stop,
    End,
    Mail,
}
impl Action {
    pub const ALL: [Self; 6] = [
        Self::Start,
        Self::Prompt,
        Self::Capture,
        Self::Stop,
        Self::End,
        Self::Mail,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Prompt => "prompt",
            Self::Capture => "capture",
            Self::Stop => "stop",
            Self::End => "end",
            Self::Mail => "mail",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.name() == value)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub project: ProjectId,
    pub cwd: NativePath,
    pub conversation: se_types::ProviderSessionId,
    pub transcript: NativePath,
    pub action: Action,
    pub cursor: Option<se_types::Cursor>,
    pub offered: Vec<se_types::MessageId>,
}
#[cfg(feature = "listener")]
pub(crate) struct NativeCall {
    pub input: Input,
    pub provider: se_proc::native_ipc::NativeIpcPeer,
}

#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub fn resolve_provider(
    configuration: &se_core::config_policy::ConfigFile,
    file: Option<&Path>,
) -> Result<std::path::PathBuf> {
    crate::process::launch_util::resolve_provider(
        configuration,
        se_types::Provider::Claude,
        file,
        None,
    )
}
