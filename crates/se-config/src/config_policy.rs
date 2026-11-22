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
mod acp;
pub mod harness;
mod providers;
pub use acp::AcpConfig;
pub use providers::{ProviderConfig, Providers};
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
    /// Seconds between wakes for mail, 0 (off, the default) through 3600. Mail
    /// is always delivered; this only paces how often a busy agent is woken.
    #[serde(default)]
    pub mail_wake_interval_seconds: Option<u32>,
    /// Under a captain, how long a crew member with open work may sit idle
    /// before the engine nudges it: 1200 by default, 0 off, at most 86400.
    #[serde(default)]
    pub captain_nudge_idle_seconds: Option<u32>,
    /// Nudges without progress before the captain gets one stuck alert: 3 by
    /// default, 1 through 20.
    #[serde(default)]
    pub captain_nudge_attempts: Option<u32>,
}
impl RuntimeConfig {
    /// The captain nudge's idle interval and attempt cap, or None when off.
    /// Host start calls this so an out-of-range value refuses loudly.
    pub fn captain_nudge(&self) -> Result<Option<(std::time::Duration, u32)>> {
        let attempts = match self.captain_nudge_attempts.unwrap_or(3) {
            value @ 1..=20 => value,
            _ => {
                return Err(invalid(
                    "runtime.captain_nudge_attempts",
                    "expected 1 through 20",
                ));
            }
        };
        match self.captain_nudge_idle_seconds.unwrap_or(1_200) {
            0 => Ok(None),
            seconds @ 1..=86_400 => Ok(Some((
                std::time::Duration::from_secs(u64::from(seconds)),
                attempts,
            ))),
            _ => Err(invalid(
                "runtime.captain_nudge_idle_seconds",
                "expected 0 (off) through 86400 seconds",
            )),
        }
    }
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
fn default_profile() -> String {
    "default".into()
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
    /// Named, finite launch data for the shared protocol driver.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub harnesses: BTreeMap<String, harness::HarnessDescriptor>,
    pub version: u16,
    #[serde(default)]
    pub default_project: String,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub launch: LaunchConfig,
    #[serde(default)]
    pub providers: Providers,
    #[serde(default, skip_serializing_if = "AcpConfig::is_default")]
    pub acp: AcpConfig,
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
            harnesses: BTreeMap::new(),
            version: 1,
            default_project: String::new(),
            runtime: RuntimeConfig::default(),
            launch: LaunchConfig::default(),
            providers: Providers::default(),
            acp: AcpConfig::default(),
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
        self.acp.validate()?;
        harness::validate_registry(&self.harnesses)?;
        self.selected_harness(Provider::Acp, self.acp.harness.as_deref())?;
        for registration in se_types::HARNESS_REGISTRY {
            let name = registration.id;
            let provider = self.provider(registration.provider);
            if let Some(seed) = &provider.seed_profile
                && (!registration.seed_profile
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
        self.providers.get(provider)
    }
    pub fn provider_command(&self, provider: Provider) -> &str {
        self.provider(provider)
            .command
            .as_deref()
            .unwrap_or(provider.registration().default_command)
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
            if provider.registration().detached_no_approval && detached {
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
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
/// Each provider's own config directory variable that is set, made absolute against this
/// process's directory: providers' commands may run elsewhere, so this one path is both
/// checked and handed to them. A value that cannot be made absolute is a named refusal.
pub fn provider_config_dirs()
-> std::result::Result<Vec<(Provider, &'static str, std::path::PathBuf)>, String> {
    let mut dirs = Vec::new();
    for (provider, name) in [
        (Provider::Codex, "CODEX_HOME"),
        (Provider::Claude, "CLAUDE_CONFIG_DIR"),
    ] {
        if let Some(value) = std::env::var_os(name) {
            let dir = std::path::absolute(&value)
                .map_err(|e| format!("{name} cannot be resolved: {e}"))?;
            dirs.push((provider, name, dir));
        }
    }
    Ok(dirs)
}
/// Why a provider config directory cannot be used, from its own metadata; `None` when it can.
pub fn unusable_config_dir(name: &str, dir: &std::path::Path, title: &str) -> Option<String> {
    let problem = match std::fs::metadata(dir) {
        Ok(found) if found.is_dir() => return None,
        Ok(_) => "is not a directory".to_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("does not exist; sign in to {title} first or create it")
        }
        Err(e) => format!("cannot be read: {e}"),
    };
    Some(format!(
        "{name} points to {}, which {problem}",
        dir.display()
    ))
}
pub fn key_metadata(key: &str) -> Result<ConfigKeyMeta> {
    if let Some((name, field)) = key
        .strip_prefix("agent.")
        .and_then(|key| key.rsplit_once('.'))
        && !name.is_empty()
        && (matches!(field, "model" | "profile" | "can-create")
            || se_types::ProviderSettings::is_field(field))
    {
        return Ok(ConfigKeyMeta {
            human_only: true,
            agent_record: true,
        });
    }
    let parts: Vec<_> = key.split('.').collect();
    let (human_only, agent_record) = match parts.as_slice() {
        ["default_project"] | ["launch", "provider" | "terminal"] | ["atlas", "enabled" | "hooks"] => (false, false),
        ["runtime", "listen_port" | "blocking_jobs" | "mail_wake_interval_seconds" | "captain_nudge_idle_seconds" | "captain_nudge_attempts"] | ["capture", "enabled"] => (true, false),
        ["providers", "claude" | "codex" | "secode" | "acp", "command" | "model" | "profile"] => (matches!(parts[2], "command" | "profile"), false),
        ["providers", "secode", "seed_profile"] => (true, false),
        ["acp", "arguments" | "environment" | "mode"] => (true, false),
        ["profiles", name, "sandbox" | "network" | "approval" | "bypass" | "git_write"] if !name.is_empty() => (true, false),
        _ => return Err(SeError::new(Detail::InputUnknownField(details::InputUnknownField { op: "config".into(), field: key.into(), next_step: "Use se help config for available commands; saved agent fields are model, profile, can-create, model_provider, base_url, wire_api, reasoning_effort and context_window.".into() }))),
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
