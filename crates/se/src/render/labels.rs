//! Plain profile terms shared by typed receipts and stored history values.
use se_core::config_policy::{Approval, EffectiveSandbox};
use se_types::Provider;
use serde::de::DeserializeOwned;

pub(super) fn permission(value: EffectiveSandbox) -> &'static str {
    match value {
        EffectiveSandbox::ReadOnly => "read-only",
        EffectiveSandbox::WorkspaceWrite => "workspace-write",
        EffectiveSandbox::Bypass => "bypass",
    }
}

pub(super) fn approval(value: Approval) -> &'static str {
    match value {
        Approval::OnRequest => "on-request",
        Approval::Untrusted => "untrusted",
        Approval::Never => "never",
    }
}

pub(super) fn network(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

pub(super) fn harness(value: Provider, selected: Option<&str>) -> &str {
    selected.unwrap_or_else(|| provider(value))
}

pub(super) fn provider(value: Provider) -> &'static str {
    match value {
        Provider::Claude => "Claude Code",
        Provider::Codex => "Codex",
        Provider::SeCode => "SE Code",
        Provider::Acp => "ACP harness",
    }
}

fn stored<T: DeserializeOwned>(value: &str) -> Result<T, serde::de::value::Error> {
    T::deserialize(serde::de::value::StrDeserializer::new(value))
}

pub(super) fn stored_permission(value: &str) -> &str {
    match stored::<se_store::PermissionProfile>(value) {
        Ok(se_store::PermissionProfile::ReadOnly) => permission(EffectiveSandbox::ReadOnly),
        Ok(se_store::PermissionProfile::WorkspaceWrite) => {
            permission(EffectiveSandbox::WorkspaceWrite)
        }
        Ok(se_store::PermissionProfile::NamedFullBypass) => permission(EffectiveSandbox::Bypass),
        // Unrecognized history remains visible verbatim, never guessed.
        Err(_) => value,
    }
}

pub(super) fn stored_provider(value: &str) -> &str {
    match stored::<se_store::Provider>(value) {
        Ok(se_store::Provider::Claude) => provider(Provider::Claude),
        Ok(se_store::Provider::Codex) => provider(Provider::Codex),
        Ok(se_store::Provider::SeCode) => "SE Code",
        Ok(se_store::Provider::Acp) => "ACP harness",
        Err(_) => value,
    }
}
