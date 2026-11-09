//! Closed file settings and safe named-profile resolution. No file or environment access.
use schemars::JsonSchema;
use se_types::{Detail, Result, SeError, details};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroUsize},
};

pub use se_types::{DEFAULT_BLOCKING_JOBS, MAX_BLOCKING_JOBS, MIN_BLOCKING_JOBS};

pub use se_types::Provider;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Sandbox {
    ReadOnly,
    #[default]
    WorkspaceWrite,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Approval {
    OnRequest,
    Untrusted,
    Never,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Requested finite-work cap. Absence selects two jobs, independently of
    /// core count; explicit 2..=8 caps remain bounded by native availability.
    /// Unknown or one-core hosts keep one foreground slot
    /// and the original independent maintenance slot.
    #[serde(default)]
    pub blocking_jobs: Option<u32>,
}
impl RuntimeConfig {
    pub fn resolve_blocking_jobs(&self, cores: Option<NonZeroUsize>) -> Result<NonZeroU32> {
        if self
            .blocking_jobs
            .is_some_and(|jobs| !(MIN_BLOCKING_JOBS..=MAX_BLOCKING_JOBS).contains(&jobs))
        {
            return Err(invalid(
                "runtime.blocking_jobs",
                "expected an integer in 2..=8",
            ));
        }
        let native = cores.map_or(1, |cores| {
            cores.get().min(MAX_BLOCKING_JOBS as usize) as u32
        });
        NonZeroU32::new(
            self.blocking_jobs
                .unwrap_or(DEFAULT_BLOCKING_JOBS)
                .min(native),
        )
        .ok_or_else(|| {
            invalid(
                "runtime.blocking_jobs",
                "expected a positive bounded work cap",
            )
        })
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LaunchConfig {
    #[serde(default)]
    pub provider: Provider,
    #[serde(default)]
    pub terminal: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub model: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    /// SE Code copies provider configuration into a new private service profile.
    /// The seed is never used as the managed service's database or write target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_profile: Option<String>,
}
fn default_profile() -> String {
    "default".into()
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    #[serde(default = "default_claude")]
    pub claude: ProviderConfig,
    #[serde(default = "default_codex")]
    pub codex: ProviderConfig,
    #[serde(default = "default_secode")]
    pub secode: ProviderConfig,
}
fn default_claude() -> ProviderConfig {
    ProviderConfig {
        command: None,
        model: String::new(),
        profile: default_profile(),
        seed_profile: None,
    }
}
fn default_codex() -> ProviderConfig {
    ProviderConfig {
        command: None,
        model: String::new(),
        profile: default_profile(),
        seed_profile: None,
    }
}
fn default_secode() -> ProviderConfig {
    ProviderConfig {
        command: None,
        model: String::new(),
        profile: default_profile(),
        seed_profile: None,
    }
}
impl Default for Providers {
    fn default() -> Self {
        Self {
            claude: default_claude(),
            codex: default_codex(),
            secode: default_secode(),
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)]
    pub sandbox: Sandbox,
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub approval: Option<Approval>,
    #[serde(default)]
    pub bypass: bool,
    /// Explicit permission for a dedicated workspace's Git metadata. Omitted
    /// from default serialization so existing resolved-profile wires stay put.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub git_write: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AtlasConfig {
    pub enabled: bool,
    /// Opt in until native end-to-end latency has qualified this platform.
    pub hooks: bool,
}
impl Default for AtlasConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hooks: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    #[serde(default = "capture_enabled")]
    pub enabled: bool,
}
fn capture_enabled() -> bool {
    true
}
impl Default for CaptureConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}
fn default_profiles() -> BTreeMap<String, Profile> {
    BTreeMap::from([("default".into(), Profile::default())])
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub version: u16,
    #[serde(default)]
    pub default_project: String,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub launch: LaunchConfig,
    #[serde(default)]
    pub providers: Providers,
    #[serde(default = "default_profiles")]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub atlas: AtlasConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
}
impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            version: 1,
            default_project: String::new(),
            runtime: RuntimeConfig::default(),
            launch: LaunchConfig::default(),
            providers: Providers::default(),
            profiles: default_profiles(),
            atlas: AtlasConfig::default(),
            capture: CaptureConfig::default(),
        }
    }
}
fn invalid(subject: &str, reason: &str) -> SeError {
    SeError::new(Detail::ConfigurationInvalid(
        details::ConfigurationInvalid {
            subject: subject.into(),
            reason: reason.into(),
            next_step: "Correct the selected user config.toml and retry.".into(),
        },
    ))
}
impl ConfigFile {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(invalid("version", "expected version = 1"));
        }
        if self
            .runtime
            .blocking_jobs
            .is_some_and(|jobs| !(MIN_BLOCKING_JOBS..=MAX_BLOCKING_JOBS).contains(&jobs))
        {
            return Err(invalid(
                "runtime.blocking_jobs",
                "expected an integer in 2..=8",
            ));
        }
        if self
            .runtime
            .listen_port
            .is_some_and(|port| !(20000..=29999).contains(&port))
        {
            return Err(invalid(
                "runtime.listen_port",
                "expected a port in 20000..29999",
            ));
        }
        if self.default_project.len() > 512 || self.default_project.contains('\0') {
            return Err(invalid(
                "default_project",
                "expected a bounded project name or id",
            ));
        }
        if self.launch.terminal.len() > 4096 || self.launch.terminal.contains('\0') {
            return Err(invalid(
                "launch.terminal",
                "expected a bounded terminal command",
            ));
        }
        for (name, profile) in &self.profiles {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err(invalid(
                    "profiles",
                    "profile names use 1..64 ASCII letters, digits, underscore or hyphen",
                ));
            }
            if name == "default" && profile.bypass {
                return Err(invalid(
                    "profiles.default.bypass",
                    "bypass requires an explicitly selected named profile",
                ));
            }
            if profile.git_write
                && (name == "default"
                    || profile.sandbox != Sandbox::WorkspaceWrite
                    || profile.bypass)
            {
                return Err(invalid(
                    "profiles.git_write",
                    "Git writes require an explicitly selected named workspace-write profile without bypass",
                ));
            }
        }
        for (name, provider) in [
            ("claude", &self.providers.claude),
            ("codex", &self.providers.codex),
            ("secode", &self.providers.secode),
        ] {
            if let Some(seed) = &provider.seed_profile
                && (name != "secode"
                    || seed.len() > 4096
                    || seed.chars().any(char::is_control)
                    || !std::path::Path::new(seed).is_absolute())
            {
                return Err(invalid(
                    "providers.secode.seed_profile",
                    "an absolute SE Code provider-configuration seed, only for SE Code",
                ));
            }
            if provider.command.as_ref().is_some_and(|command| {
                command.is_empty() || command.len() > 4096 || command.contains('\0')
            }) {
                return Err(invalid(
                    name,
                    "provider command is empty, oversized or contains NUL",
                ));
            }
            if provider.model.len() > 128 || provider.model.contains('\0') {
                return Err(invalid(
                    name,
                    "model exceeds 128 UTF-8 bytes or contains NUL",
                ));
            }
            if provider.profile != "default" && !self.profiles.contains_key(&provider.profile) {
                return Err(invalid(name, "provider names an absent permission profile"));
            }
        }
        Ok(())
    }
    pub fn provider(&self, provider: Provider) -> &ProviderConfig {
        match provider {
            Provider::Claude => &self.providers.claude,
            Provider::Codex => &self.providers.codex,
            Provider::SeCode => &self.providers.secode,
        }
    }
    pub fn provider_command(&self, provider: Provider) -> &str {
        self.provider(provider)
            .command
            .as_deref()
            .unwrap_or(match provider {
                Provider::Claude => "claude",
                Provider::Codex => "codex",
                Provider::SeCode => "secode",
            })
    }
    pub fn resolve_profile(
        &self,
        name: &str,
        provider: Provider,
        detached: bool,
    ) -> Result<ResolvedProfile> {
        self.validate()?;
        let default = Profile::default();
        let profile = if name == "default" {
            self.profiles.get(name).unwrap_or(&default)
        } else {
            self.profiles
                .get(name)
                .ok_or_else(|| invalid("profile", "saved named profile is absent"))?
        };
        let approval = profile.approval.unwrap_or(
            if matches!(provider, Provider::Codex | Provider::SeCode) && detached {
                Approval::Never
            } else {
                Approval::OnRequest
            },
        );
        Ok(ResolvedProfile {
            name: name.into(),
            sandbox: if profile.bypass {
                EffectiveSandbox::Bypass
            } else {
                match profile.sandbox {
                    Sandbox::ReadOnly => EffectiveSandbox::ReadOnly,
                    Sandbox::WorkspaceWrite => EffectiveSandbox::WorkspaceWrite,
                }
            },
            approval,
            network: profile.network,
            bypass: profile.bypass,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedProfile {
    pub name: String,
    pub sandbox: EffectiveSandbox,
    pub approval: Approval,
    pub network: bool,
    pub bypass: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EffectiveSandbox {
    ReadOnly,
    WorkspaceWrite,
    Bypass,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigKeyMeta {
    pub human_only: bool,
    pub agent_record: bool,
}
pub fn key_metadata(key: &str) -> Result<ConfigKeyMeta> {
    if let Some((name, field)) = key
        .strip_prefix("agent.")
        .and_then(|key| key.rsplit_once('.'))
        && !name.is_empty()
        && matches!(field, "model" | "profile" | "can-create")
    {
        return Ok(ConfigKeyMeta {
            human_only: true,
            agent_record: true,
        });
    }
    let parts: Vec<_> = key.split('.').collect();
    let (human_only, agent_record) = match parts.as_slice() {
        ["default_project"] | ["launch", "provider" | "terminal"] | ["atlas", "enabled" | "hooks"] => (false, false),
        ["runtime", "listen_port" | "blocking_jobs"] | ["capture", "enabled"] => (true, false),
        ["providers", "claude" | "codex" | "secode", "command" | "model" | "profile"] => (matches!(parts[2], "command" | "profile"), false),
        ["providers", "secode", "seed_profile"] => (true, false),
        ["profiles", name, "sandbox" | "network" | "approval" | "bypass" | "git_write"] if !name.is_empty() => (true, false),
        _ => return Err(SeError::new(Detail::InputUnknownField(details::InputUnknownField { op: "config".into(), field: key.into(), next_step: "Use se help config for available commands; saved agent fields are model, profile and can-create.".into() }))),
    };
    Ok(ConfigKeyMeta {
        human_only,
        agent_record,
    })
}

#[cfg(test)]
mod git_profile_tests {
    use super::*;

    #[test]
    fn git_permission_is_named_owner_only_and_does_not_extend_launch_receipts() -> Result<()> {
        let mut config = ConfigFile::default();
        config.profiles.insert(
            "git-workspace".into(),
            Profile {
                git_write: true,
                ..Default::default()
            },
        );
        config.validate()?;
        assert!(key_metadata("profiles.git-workspace.git_write")?.human_only);
        let selected = config.resolve_profile("git-workspace", Provider::Codex, true)?;
        assert_eq!(selected.sandbox, EffectiveSandbox::WorkspaceWrite);
        let wire = serde_json::to_value(selected)
            .map_err(|cause| invalid("test profile", &cause.to_string()))?;
        assert!(wire.get("git_write").is_none());
        assert!(!config.profiles["default"].git_write);
        Ok(())
    }

    #[test]
    fn default_read_only_and_bypass_profiles_cannot_silently_gain_git_permission() {
        for (name, sandbox, bypass) in [
            ("default", Sandbox::WorkspaceWrite, false),
            ("readonly", Sandbox::ReadOnly, false),
            ("unrestricted", Sandbox::WorkspaceWrite, true),
        ] {
            let mut config = ConfigFile::default();
            config.profiles.insert(
                name.into(),
                Profile {
                    sandbox,
                    bypass,
                    git_write: true,
                    ..Default::default()
                },
            );
            assert!(config.validate().is_err());
        }
    }
}

#[cfg(test)]
mod runtime_budget_tests {
    use super::*;
    #[test]
    fn atlas_is_enabled_unless_explicitly_disabled() -> Result<()> {
        assert!(ConfigFile::default().atlas.enabled);
        let omitted: AtlasConfig =
            serde_json::from_str("{}").map_err(|e| invalid("test Atlas config", &e.to_string()))?;
        let disabled: AtlasConfig = serde_json::from_str("{\"enabled\":false}")
            .map_err(|e| invalid("test Atlas config", &e.to_string()))?;
        assert!(omitted.enabled);
        assert!(!disabled.enabled);
        Ok(())
    }
    #[test]
    fn finite_work_cap_respects_native_cores_and_owner_configuration() -> Result<()> {
        for (cores, requested, expected) in [
            (2, None, 2),
            (4, None, 2),
            (48, None, 2),
            (48, Some(4), 4),
            (4, Some(8), 4),
        ] {
            let cores =
                NonZeroUsize::new(cores).ok_or_else(|| invalid("test cores", "positive"))?;
            let config = RuntimeConfig {
                blocking_jobs: requested,
                ..Default::default()
            };
            assert_eq!(config.resolve_blocking_jobs(Some(cores))?.get(), expected);
        }
        assert!(key_metadata("runtime.blocking_jobs")?.human_only);
        Ok(())
    }
    #[test]
    fn invalid_work_caps_are_refused_before_startup() -> Result<()> {
        let cores = NonZeroUsize::new(8).ok_or_else(|| invalid("test cores", "positive"))?;
        let one_core = NonZeroUsize::new(1).ok_or_else(|| invalid("test cores", "positive"))?;
        for observed in [None, Some(one_core)] {
            let configured = RuntimeConfig {
                blocking_jobs: Some(8),
                ..Default::default()
            };
            assert_eq!(configured.resolve_blocking_jobs(observed)?.get(), 1);
            assert_eq!(
                RuntimeConfig::default()
                    .resolve_blocking_jobs(observed)?
                    .get(),
                1
            );
        }
        for requested in [0, 1, 9, u32::MAX] {
            let mut config = ConfigFile::default();
            config.runtime.blocking_jobs = Some(requested);
            assert!(config.validate().is_err());
            assert!(config.runtime.resolve_blocking_jobs(Some(cores)).is_err());
        }
        Ok(())
    }
}
