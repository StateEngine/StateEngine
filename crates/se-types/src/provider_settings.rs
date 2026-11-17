//! Saved, non-secret overrides scoped to one agent, never shared provider defaults.
use crate::{Provider, Result, SeError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_api: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u64>,
}
impl ProviderSettings {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
    pub fn is_field(field: &str) -> bool {
        matches!(
            field,
            "model_provider" | "base_url" | "wire_api" | "reasoning_effort" | "context_window"
        )
    }
    pub fn validate(&self, provider: Provider) -> Result<()> {
        if !self.is_empty() && !matches!(provider, Provider::Codex | Provider::Claude) {
            return Err(SeError::invalid(
                "provider settings",
                "per-agent overrides require codex or claude; clear the overrides for this harness",
            ));
        }
        if provider == Provider::Claude
            && (self.model_provider.is_some()
                || self.base_url.is_some()
                || self.wire_api.is_some()
                || self.context_window.is_some())
        {
            return Err(SeError::invalid(
                "Claude provider settings",
                "only reasoning_effort is supported; model_provider, base_url, wire_api and context_window require codex",
            ));
        }
        if let Some(name) = &self.model_provider
            && (name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        {
            return Err(SeError::invalid(
                "model_provider",
                "1..64 ASCII letters, digits, underscores or hyphens",
            ));
        }
        if let Some(url) = &self.base_url {
            let parsed = url::Url::parse(url).ok();
            if url.len() > 2048
                || url.chars().any(|c| c.is_whitespace() || c.is_control())
                || parsed.as_ref().is_none_or(|parsed| {
                    !matches!(parsed.scheme(), "http" | "https")
                        || parsed.host_str().is_none()
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                        || parsed.query().is_some()
                        || parsed.fragment().is_some()
                })
            {
                return Err(SeError::invalid(
                    "base_url",
                    "a non-secret http(s) URL with a host and without credentials, query or fragment",
                ));
            }
        }
        if self
            .wire_api
            .as_deref()
            .is_some_and(|api| api != "responses")
        {
            return Err(SeError::invalid(
                "wire_api",
                "responses; other wire protocols are unsupported",
            ));
        }
        if (self.base_url.is_some() || self.wire_api.is_some()) && self.model_provider.is_none() {
            return Err(SeError::invalid(
                "model_provider",
                "set a provider name before its base_url or wire_api",
            ));
        }
        if let Some(effort) = self.reasoning_effort.as_deref() {
            let supported = if provider == Provider::Claude {
                matches!(effort, "low" | "medium" | "high" | "max")
            } else {
                matches!(
                    effort,
                    "none" | "minimal" | "low" | "medium" | "high" | "xhigh"
                )
            };
            if !supported {
                return Err(SeError::invalid(
                    "reasoning_effort",
                    "use a supported effort for the saved provider: Claude low/medium/high/max; Codex none/minimal/low/medium/high/xhigh",
                ));
            }
        }
        if self
            .context_window
            .is_some_and(|tokens| tokens == 0 || tokens > i64::MAX as u64)
        {
            return Err(SeError::invalid(
                "context_window",
                "a positive signed 64-bit token count, or null to inherit the provider default",
            ));
        }
        Ok(())
    }
}
