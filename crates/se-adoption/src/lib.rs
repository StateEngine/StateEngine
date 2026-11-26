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
    pub fn policy(self) -> se_config::config_policy::Provider {
        match self {
            Self::Claude => se_config::config_policy::Provider::Claude,
            Self::Codex => se_config::config_policy::Provider::Codex,
        }
    }
}
/// Provider-owned setup and discovery within the host's journaled installation.
#[cfg(feature = "listener")]
pub(crate) trait Adapter: Send + Sync {
    #[cfg(any(target_os = "linux", windows))]
    fn prepare(&self, command: &Path, host: &HostSetup) -> Result<ProviderSetup>;
    #[cfg(any(target_os = "linux", windows))]
    /// `atlas` adds the Atlas context hook, as the managed launch does when
    /// `[atlas]` has both `enabled` and `hooks` set.
    fn hooks(
        &self,
        executable: &Path,
        home: &Path,
        atlas: bool,
    ) -> Result<Vec<(String, serde_json::Value)>>;
    fn discover(&self, _home: &Path, _saved: &mut Registration, _root: &Path) -> Result<()> {
        Ok(())
    }
    fn active(&self, _home: &Path, _project: &ProjectId) -> Result<bool> {
        Ok(true)
    }
    fn notice(&self) -> Option<String> {
        None
    }
}
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub(crate) struct ProviderSetup {
    pub executable: std::path::PathBuf,
    pub config_home: std::path::PathBuf,
}
#[cfg(feature = "listener")]
struct ClaudeAdoption;
#[cfg(feature = "listener")]
static CLAUDE_ADOPTION: ClaudeAdoption = ClaudeAdoption;
#[cfg(feature = "listener")]
impl Adapter for ClaudeAdoption {
    #[cfg(any(target_os = "linux", windows))]
    fn prepare(&self, command: &Path, _host: &HostSetup) -> Result<ProviderSetup> {
        se_harness::harness::qualify_claude_adoption(command)?;
        Ok(ProviderSetup {
            executable: command.to_owned(),
            config_home: se_harness::harness::claude::config_home(
                &std::env::vars_os().collect::<Vec<_>>(),
            )?,
        })
    }
    #[cfg(any(target_os = "linux", windows))]
    fn hooks(
        &self,
        executable: &Path,
        home: &Path,
        atlas: bool,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        settings::hooks(executable, home, atlas)
    }
    fn notice(&self) -> Option<String> {
        Some("Review and trust the StateEngine hooks in Claude Code when the provider asks; declining keeps the provider usable with the integration inactive".into())
    }
}
#[cfg(feature = "listener")]
struct CodexAdoption;
#[cfg(feature = "listener")]
static CODEX_ADOPTION: CodexAdoption = CodexAdoption;
#[cfg(feature = "listener")]
pub use codex_adapter::FirstSetup;
/// Host policy that first setup uses but adoption does not own.
#[cfg(feature = "listener")]
pub struct HostSetup {
    /// The host's provider executable policy, the same one launches use.
    pub resolve: ProviderResolver,
    /// The user's own Codex login, available only to first setup.
    pub codex_login: fn(&FirstSetup) -> Result<std::path::PathBuf>,
}
#[cfg(feature = "listener")]
mod codex_adapter {
    use super::*;
    /// Proof that Codex first setup is asking for a login. Only this module
    /// can make one, so no other adapter or agent launch obtains that login.
    pub struct FirstSetup(());
    impl Adapter for CodexAdoption {
        #[cfg(any(target_os = "linux", windows))]
        fn prepare(&self, command: &Path, host: &HostSetup) -> Result<ProviderSetup> {
            let executable = codex::native_executable(command)?;
            let home = (host.codex_login)(&FirstSetup(()))?;
            settings::prepare(&home, &home.join(Kind::Codex.settings()))?;
            codex::qualify(&executable)?;
            Ok(ProviderSetup {
                executable,
                config_home: home,
            })
        }
        #[cfg(any(target_os = "linux", windows))]
        fn hooks(
            &self,
            executable: &Path,
            home: &Path,
            atlas: bool,
        ) -> Result<Vec<(String, serde_json::Value)>> {
            codex::hooks(executable, home, atlas)
        }
        fn discover(&self, home: &Path, saved: &mut Registration, root: &Path) -> Result<()> {
            codex::trust(home, saved, root)
        }
        fn active(&self, home: &Path, project: &ProjectId) -> Result<bool> {
            status::witnessed(home, Kind::Codex, project)
        }
    }
}
#[cfg(feature = "listener")]
impl Kind {
    fn adapter(self) -> &'static dyn Adapter {
        match self {
            Self::Claude => &CLAUDE_ADOPTION,
            Self::Codex => &CODEX_ADOPTION,
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
        let roots = self.projects.iter().map(|p| p.root.to_local().ok());
        let matched = se_repository::registered_worktree(cwd, roots)
            .map_err(|error| se_core::scope::unreadable("provider adoption worktree", &error))?;
        Ok(matched.map(|index| &self.projects[index]))
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
    se_mcp::wire::decode_json(&bytes, LIMIT).map(Some)
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
        // Publication flushes the staged data before moving its name.
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
pub fn invalid(expected: &str) -> SeError {
    SeError::invalid("provider adoption", expected)
}
pub fn native(error: se_proc::StateFileError) -> SeError {
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
    /// Indexed Atlas context before a tool call; observes nothing and commits nothing.
    Context,
}
impl Action {
    /// The lifecycle actions a hook names on its command line, each with its
    /// own status row. A context lookup has neither.
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
            Self::Context => "context",
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
    /// What a [`Action::Context`] call asks Atlas about; absent for every other action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<se_core::ops::AtlasHookTarget>,
}
#[cfg(feature = "listener")]
pub struct NativeCall {
    pub input: Input,
    pub provider: se_proc::native_ipc::NativeIpcPeer,
}

/// The host's provider executable policy: configuration, selected file and
/// optional harness in, one canonical native executable out.
#[cfg(feature = "listener")]
pub type ProviderResolver = fn(
    &se_config::config_policy::ConfigFile,
    se_types::Provider,
    Option<&Path>,
    Option<&str>,
) -> Result<std::path::PathBuf>;
#[cfg(all(feature = "listener", any(target_os = "linux", windows)))]
pub fn resolve_provider_for(
    kind: Kind,
    configuration: &se_config::config_policy::ConfigFile,
    file: Option<&Path>,
    resolve: ProviderResolver,
) -> Result<std::path::PathBuf> {
    let provider = match kind {
        Kind::Claude => se_types::Provider::Claude,
        Kind::Codex => se_types::Provider::Codex,
    };
    resolve(configuration, provider, file, None)
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
