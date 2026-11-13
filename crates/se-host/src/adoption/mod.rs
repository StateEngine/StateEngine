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
pub mod codex;
pub mod diagnostic;
#[cfg(feature = "listener")]
pub mod install;
#[cfg(feature = "listener")]
pub mod metadata;
pub mod settings;
pub mod status;
pub const JOURNAL: &str = "claude-adoption.json";
const LIMIT: usize = 1024 * 1024;
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Claude,
    Codex,
}
impl Kind {
    pub const ALL: [Self; 2] = [Self::Claude, Self::Codex];
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
        }
    }
    pub fn journal(self) -> &'static str {
        match self {
            Self::Claude => JOURNAL,
            Self::Codex => "codex-adoption.json",
        }
    }
    pub fn settings(self) -> &'static str {
        match self {
            Self::Claude => "settings.json",
            Self::Codex => "config.toml",
        }
    }
    pub fn provider(self) -> se_store::Provider {
        match self {
            Self::Claude => se_store::Provider::Claude,
            Self::Codex => se_store::Provider::Codex,
        }
    }
    pub fn policy(self) -> se_core::config_policy::Provider {
        match self {
            Self::Claude => se_core::config_policy::Provider::Claude,
            Self::Codex => se_core::config_policy::Provider::Codex,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project: ProjectId,
    pub root: NativePath,
    #[serde(default)]
    pub discovery: Option<[u8; 32]>,
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
    #[serde(default)]
    pub discovery: Option<[u8; 32]>,
    #[serde(default)]
    pub discovery_refusal: Option<String>,
    #[serde(default)]
    pub installation: Option<String>,
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
    read_for(home, Kind::Claude)
}
pub fn read_for(home: &Path, kind: Kind) -> Result<Option<Registration>> {
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
    let Some(file) = files.readback(&home.join(kind.journal())).map_err(native)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    crate::client::wire::decode_json(&bytes, LIMIT).map(Some)
}
pub fn publish(home: &Path, registration: &Registration) -> Result<()> {
    publish_for(home, Kind::Claude, registration)
}
pub fn publish_for(home: &Path, kind: Kind, registration: &Registration) -> Result<()> {
    let files = se_proc::NativeStateFiles::open(home).map_err(native)?;
    let path = home.join(kind.journal());
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
    remove_for(home, Kind::Claude)
}
pub fn remove_for(home: &Path, kind: Kind) -> Result<()> {
    let path = home.join(kind.journal());
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
    #[serde(default)]
    pub kind: Kind,
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
    resolve_provider_for(Kind::Claude, configuration, file)
}
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub fn resolve_provider_for(
    kind: Kind,
    configuration: &se_core::config_policy::ConfigFile,
    file: Option<&Path>,
) -> Result<std::path::PathBuf> {
    let provider = match kind {
        Kind::Claude => se_types::Provider::Claude,
        Kind::Codex => se_types::Provider::Codex,
    };
    crate::process::launch_util::resolve_provider(configuration, provider, file)
}

/// A discovery receipt is only a cache hint. Configuration or executable drift
/// invalidates it; native ancestry remains the authority for every hook call.
pub fn discovery_stamp(registration: &Registration) -> Result<[u8; 32]> {
    let (pin, _, mut config) = settings::read_document(&registration.settings.to_local()?)?;
    if pin.is_none() {
        return Err(invalid(
            "provider configuration is absent; repeat adoption setup",
        ));
    }
    // Terminal preferences written during startup do not change hook discovery.
    config.as_object_mut().map(|object| object.remove("tui"));
    let provider = std::fs::File::open(registration.provider.to_local()?).map_err(io)?;
    let revision = se_proc::observe_file_revision(&provider).map_err(io)?;
    let mut hash = Sha256::new();
    hash.update(revision.volume);
    hash.update(revision.file);
    hash.update(revision.size.to_le_bytes());
    hash.update(revision.mtime_unix_nanos.to_le_bytes());
    if let Some(ctime) = revision.ctime_unix_nanos {
        hash.update(ctime.to_le_bytes());
    }
    hash.update(
        serde_json::to_vec(&(config, &registration.hooks))
            .map_err(|_| invalid("provider hook discovery configuration"))?,
    );
    Ok(hash.finalize().into())
}
