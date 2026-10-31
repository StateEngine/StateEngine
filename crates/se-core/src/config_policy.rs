//! Closed file settings and safe named-profile resolution. No file or environment access.
use std::collections::BTreeMap;
use se_types::{details, Detail, Result, SeError};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Provider { #[default] Claude, Codex }
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Sandbox { ReadOnly, #[default] WorkspaceWrite }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Approval { OnRequest, Untrusted, Never }
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig { #[serde(default)] pub listen_port: Option<u16> }
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LaunchConfig {
    #[serde(default)] pub provider: Provider,
    #[serde(default)] pub terminal: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default)] pub command: Option<String>,
    #[serde(default)] pub model: String,
    #[serde(default = "default_profile")] pub profile: String,
}
fn default_profile() -> String { "default".into() }
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    #[serde(default = "default_claude")] pub claude: ProviderConfig,
    #[serde(default = "default_codex")] pub codex: ProviderConfig,
}
fn default_claude() -> ProviderConfig { ProviderConfig { command: None, model: String::new(), profile: default_profile() } }
fn default_codex() -> ProviderConfig { ProviderConfig { command: None, model: String::new(), profile: default_profile() } }
impl Default for Providers { fn default() -> Self { Self { claude: default_claude(), codex: default_codex() } } }
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default)] pub sandbox: Sandbox,
    #[serde(default)] pub network: bool,
    #[serde(default)] pub approval: Option<Approval>,
    #[serde(default)] pub bypass: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasConfig { #[serde(default)] pub enabled: bool }
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig { #[serde(default = "capture_enabled")] pub enabled: bool }
fn capture_enabled() -> bool { true }
impl Default for CaptureConfig { fn default() -> Self { Self { enabled: true } } }
fn default_profiles() -> BTreeMap<String, Profile> { BTreeMap::from([("default".into(), Profile::default())]) }
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub version: u16,
    #[serde(default)] pub default_project: String,
    #[serde(default)] pub runtime: RuntimeConfig,
    #[serde(default)] pub launch: LaunchConfig,
    #[serde(default)] pub providers: Providers,
    #[serde(default = "default_profiles")] pub profiles: BTreeMap<String, Profile>,
    #[serde(default)] pub atlas: AtlasConfig,
    #[serde(default)] pub capture: CaptureConfig,
}
impl Default for ConfigFile {
    fn default() -> Self { Self { version: 1, default_project: String::new(), runtime: RuntimeConfig::default(), launch: LaunchConfig::default(), providers: Providers::default(), profiles: default_profiles(), atlas: AtlasConfig::default(), capture: CaptureConfig::default() } }
}
fn invalid(subject: &str, reason: &str) -> SeError {
    SeError::new(Detail::ConfigurationInvalid(details::ConfigurationInvalid { subject: subject.into(), reason: reason.into(), next_step: "Correct the selected user config.toml and retry.".into() }))
}
impl ConfigFile {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 { return Err(invalid("version", "expected version = 1")); }
        if self.runtime.listen_port.is_some_and(|port| !(20000..=29999).contains(&port)) { return Err(invalid("runtime.listen_port", "expected a port in 20000..29999")); }
        if self.default_project.len() > 512 || self.default_project.contains('\0') { return Err(invalid("default_project", "expected a bounded project name or id")); }
        if self.launch.terminal.len() > 4096 || self.launch.terminal.contains('\0') { return Err(invalid("launch.terminal", "expected a bounded terminal command")); }
        for (name, profile) in &self.profiles {
            if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) { return Err(invalid("profiles", "profile names use 1..64 ASCII letters, digits, underscore or hyphen")); }
            if name == "default" && profile.bypass { return Err(invalid("profiles.default.bypass", "bypass requires an explicitly selected named profile")); }
        }
        for (name, provider) in [("claude", &self.providers.claude), ("codex", &self.providers.codex)] {
            if provider.command.as_ref().is_some_and(|command| command.is_empty() || command.len() > 4096 || command.contains('\0')) { return Err(invalid(name, "provider command is empty, oversized or contains NUL")); }
            if provider.model.len() > 128 || provider.model.contains('\0') { return Err(invalid(name, "model exceeds 128 UTF-8 bytes or contains NUL")); }
            if provider.profile != "default" && !self.profiles.contains_key(&provider.profile) { return Err(invalid(name, "provider names an absent permission profile")); }
        }
        Ok(())
    }
    pub fn provider(&self, provider: Provider) -> &ProviderConfig {
        match provider { Provider::Claude => &self.providers.claude, Provider::Codex => &self.providers.codex }
    }
    pub fn provider_command(&self, provider: Provider) -> &str {
        self.provider(provider).command.as_deref().unwrap_or(match provider { Provider::Claude => "claude", Provider::Codex => "codex" })
    }
    pub fn resolve_profile(&self, name: &str, provider: Provider, detached: bool) -> Result<ResolvedProfile> {
        self.validate()?;
        let default = Profile::default();
        let profile = if name == "default" { self.profiles.get(name).unwrap_or(&default) } else { self.profiles.get(name).ok_or_else(|| invalid("profile", "saved named profile is absent"))? };
        let approval = profile.approval.unwrap_or(if provider == Provider::Codex && detached { Approval::Never } else { Approval::OnRequest });
        Ok(ResolvedProfile { name: name.into(), sandbox: profile.sandbox, approval, network: profile.network, bypass: profile.bypass })
    }
}
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ResolvedProfile { pub name: String, pub sandbox: Sandbox, pub approval: Approval, pub network: bool, pub bypass: bool }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigKeyMeta { pub human_only: bool, pub agent_record: bool }
pub fn key_metadata(key: &str) -> Result<ConfigKeyMeta> {
    let parts: Vec<_> = key.split('.').collect();
    let (human_only, agent_record) = match parts.as_slice() {
        ["default_project"] | ["launch", "provider" | "terminal"] | ["atlas", "enabled"] => (false, false),
        ["runtime", "listen_port"] | ["capture", "enabled"] => (true, false),
        ["providers", "claude" | "codex", "command" | "model" | "profile"] => (matches!(parts[2], "command" | "profile"), false),
        ["profiles", name, "sandbox" | "network" | "approval" | "bypass"] if !name.is_empty() => (true, false),
        ["agent", name, "profile" | "model"] if !name.is_empty() => (false, true),
        ["agent", name, "can-create"] if !name.is_empty() => (true, true),
        _ => return Err(SeError::new(Detail::InputUnknownField(details::InputUnknownField { op: "config".into(), field: key.into(), next_step: "Use se config list for supported file keys; agent fields are profile, model and can-create.".into() }))),
    };
    Ok(ConfigKeyMeta { human_only, agent_record })
}
