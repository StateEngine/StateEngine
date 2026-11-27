//! Owner-authored `[delegation]` allowlist and bounds for temporary agent delegation.
use super::{Profile, Provider, invalid};
use schemars::JsonSchema;
use se_types::{Detail, Result, SeError, details};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_MAX_ACTIVE_PER_PARENT: u32 = 4;
pub const MAX_ACTIVE_PER_PARENT: u32 = 16;
pub const DEFAULT_TTL_SECONDS: u32 = 3_600;
pub const MAX_TTL_SECONDS: u32 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegationAllowEntry {
    pub provider: Provider,
    pub profile: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DelegationConfig {
    /// Maximum concurrent active temporary children per parent (default 4, max 16).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_active_per_parent: Option<u32>,
    /// Default TTL backstop in seconds for delegated children (default 3600, max 86400).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    /// Owner-authored `(provider, profile)` allowlist for agent-initiated delegation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<DelegationAllowEntry>,
    /// Pairs a paired machine may start beside an approved agent here. Empty
    /// (the default) refuses every remote delegation, whatever `allow` lists.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remote_allow: Vec<DelegationAllowEntry>,
}

impl DelegationConfig {
    pub fn is_default(&self) -> bool {
        self.max_active_per_parent.is_none()
            && self.ttl_seconds.is_none()
            && self.allow.is_empty()
            && self.remote_allow.is_empty()
    }

    pub fn max_active_per_parent(&self) -> u32 {
        self.max_active_per_parent
            .unwrap_or(DEFAULT_MAX_ACTIVE_PER_PARENT)
    }

    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS)
    }

    pub(super) fn validate(&self, profiles: &BTreeMap<String, Profile>) -> Result<()> {
        if self
            .max_active_per_parent
            .is_some_and(|v| !(1..=MAX_ACTIVE_PER_PARENT).contains(&v))
        {
            return Err(invalid(
                "delegation.max_active_per_parent",
                "expected an integer in 1..=16",
            ));
        }
        if self
            .ttl_seconds
            .is_some_and(|v| !(1..=MAX_TTL_SECONDS).contains(&v))
        {
            return Err(invalid(
                "delegation.ttl_seconds",
                "expected an integer in 1..=86400 seconds",
            ));
        }
        validate_list("delegation.allow", &self.allow, profiles)?;
        validate_list("delegation.remote_allow", &self.remote_allow, profiles)
    }

    pub fn is_allowed(&self, provider: Provider, profile: &str) -> bool {
        listed(&self.allow, provider, profile)
    }

    pub fn require_allowed(&self, provider: Provider, profile: &str) -> Result<()> {
        require_listed("allow", "agent", &self.allow, provider, profile)
    }

    /// A paired machine's worker pair, checked only against `remote_allow`.
    pub fn require_remote_allowed(&self, provider: Provider, profile: &str) -> Result<()> {
        require_listed(
            "remote_allow",
            "remote",
            &self.remote_allow,
            provider,
            profile,
        )
    }
}

fn validate_list(
    field: &str,
    list: &[DelegationAllowEntry],
    profiles: &BTreeMap<String, Profile>,
) -> Result<()> {
    if list.len() > 64 {
        return Err(invalid(field, "expected at most 64 allowlist entries"));
    }
    for entry in list {
        if entry.profile.is_empty()
            || (entry.profile != "default" && !profiles.contains_key(&entry.profile))
        {
            return Err(invalid(
                field,
                "allowlist entry names an empty or absent permission profile",
            ));
        }
    }
    Ok(())
}

fn listed(list: &[DelegationAllowEntry], provider: Provider, profile: &str) -> bool {
    list.iter()
        .any(|entry| entry.provider == provider && entry.profile == profile)
}

fn require_listed(
    field: &str,
    who: &str,
    list: &[DelegationAllowEntry],
    provider: Provider,
    profile: &str,
) -> Result<()> {
    if listed(list, provider, profile) {
        return Ok(());
    }
    let name = provider.registration().id;
    let reason = if list.is_empty() {
        format!(
            "{who} delegation to ({name}, profile '{profile}') is not allowed because [delegation].{field} is empty"
        )
    } else {
        format!(
            "{who} delegation to ({name}, profile '{profile}') is not listed in [delegation].{field}"
        )
    };
    Err(SeError::new(Detail::ConfigurationInvalid(
        details::ConfigurationInvalid {
            subject: format!("delegation.{field}"),
            reason,
            next_step: format!(
                "Add {{ provider = \"{name}\", profile = \"{profile}\" }} under [delegation].{field} in config.toml and retry."
            ),
        },
    )))
}
