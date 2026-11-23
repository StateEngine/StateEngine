//! The closed config.toml key set, built as typed rows: every row is the
//! effective typed setting; only Option fields can be absent.
use crate::ops::ConfigValueOutput;
use se_config::config_policy::{Approval, ConfigFile, Provider, Sandbox};
use se_types::Read;
use serde_json::{Value, json};
fn push_row(
    rows: &mut Vec<ConfigValueOutput>,
    origin: &Option<String>,
    key: &str,
    value: Read<Value>,
) {
    rows.push(ConfigValueOutput {
        key: key.to_owned(),
        value,
        origin: origin.clone(),
    });
}
pub(crate) fn launch_runtime_rows(
    configuration: &ConfigFile,
    origin: &Option<String>,
) -> Vec<ConfigValueOutput> {
    let mut rows: Vec<ConfigValueOutput> = Vec::new();
    push_row(
        &mut rows,
        origin,
        "default_project",
        present(json!(configuration.default_project)),
    );
    push_row(
        &mut rows,
        origin,
        "launch.provider",
        present(json!(provider_wire(configuration.launch.provider))),
    );
    push_row(
        &mut rows,
        origin,
        "launch.terminal",
        present(json!(configuration.launch.terminal)),
    );
    push_row(
        &mut rows,
        origin,
        "runtime.listen_port",
        option(&configuration.runtime.listen_port),
    );
    push_row(
        &mut rows,
        origin,
        "runtime.blocking_jobs",
        option(&configuration.runtime.blocking_jobs),
    );
    push_row(
        &mut rows,
        origin,
        "runtime.mail_wake_interval_seconds",
        option(&configuration.runtime.mail_wake_interval_seconds),
    );
    push_row(
        &mut rows,
        origin,
        "runtime.captain_nudge_idle_seconds",
        option(&configuration.runtime.captain_nudge_idle_seconds),
    );
    push_row(
        &mut rows,
        origin,
        "runtime.captain_nudge_attempts",
        option(&configuration.runtime.captain_nudge_attempts),
    );
    rows
}
pub(crate) fn provider_rows(
    configuration: &ConfigFile,
    origin: &Option<String>,
) -> Vec<ConfigValueOutput> {
    let mut rows: Vec<ConfigValueOutput> = Vec::new();
    for registration in se_types::HARNESS_REGISTRY {
        let name = registration.id;
        let provider = configuration.provider(registration.provider);
        push_row(
            &mut rows,
            origin,
            &format!("providers.{name}.command"),
            option(&provider.command),
        );
        push_row(
            &mut rows,
            origin,
            &format!("providers.{name}.model"),
            present(json!(provider.model)),
        );
        push_row(
            &mut rows,
            origin,
            &format!("providers.{name}.profile"),
            present(json!(provider.profile)),
        );
    }
    push_row(
        &mut rows,
        origin,
        "providers.secode.seed_profile",
        option(&configuration.providers.secode.seed_profile),
    );
    rows
}
pub(crate) fn acp_profile_rows(
    configuration: &ConfigFile,
    origin: &Option<String>,
) -> Vec<ConfigValueOutput> {
    let mut rows: Vec<ConfigValueOutput> = Vec::new();
    for (key, value) in [
        ("acp.arguments", json!(configuration.acp.arguments)),
        ("acp.environment", json!(configuration.acp.environment)),
        ("acp.mode", json!(configuration.acp.mode)),
    ] {
        push_row(&mut rows, origin, key, present(value));
    }
    for (name, profile) in &configuration.profiles {
        push_row(
            &mut rows,
            origin,
            &format!("profiles.{name}.sandbox"),
            present(json!(sandbox_wire(profile.sandbox))),
        );
        push_row(
            &mut rows,
            origin,
            &format!("profiles.{name}.network"),
            present(json!(profile.network)),
        );
        let approval = match &profile.approval {
            Some(approval) => present(json!(approval_wire(*approval))),
            None => Read::Absent {
                checked: "not set in the effective configuration".into(),
            },
        };
        push_row(
            &mut rows,
            origin,
            &format!("profiles.{name}.approval"),
            approval,
        );
        push_row(
            &mut rows,
            origin,
            &format!("profiles.{name}.bypass"),
            present(json!(profile.bypass)),
        );
        push_row(
            &mut rows,
            origin,
            &format!("profiles.{name}.git_write"),
            present(json!(profile.git_write)),
        );
    }
    rows
}
pub(crate) fn service_rows(
    configuration: &ConfigFile,
    origin: &Option<String>,
) -> Vec<ConfigValueOutput> {
    let mut rows: Vec<ConfigValueOutput> = Vec::new();
    push_row(
        &mut rows,
        origin,
        "atlas.enabled",
        present(json!(configuration.atlas.enabled)),
    );
    push_row(
        &mut rows,
        origin,
        "atlas.hooks",
        present(json!(configuration.atlas.hooks)),
    );
    push_row(
        &mut rows,
        origin,
        "capture.enabled",
        present(json!(configuration.capture.enabled)),
    );
    rows
}
fn present(value: Value) -> Read<Value> {
    Read::Present { value }
}
fn option<T: serde::Serialize>(value: &Option<T>) -> Read<Value> {
    match value {
        Some(value) => Read::Present {
            value: json!(value),
        },
        None => Read::Absent {
            checked: "not set in the effective configuration".into(),
        },
    }
}
fn provider_wire(provider: Provider) -> &'static str {
    provider.id()
}
fn sandbox_wire(sandbox: Sandbox) -> &'static str {
    match sandbox {
        Sandbox::ReadOnly => "read-only",
        Sandbox::WorkspaceWrite => "workspace-write",
    }
}
fn approval_wire(approval: Approval) -> &'static str {
    match approval {
        Approval::OnRequest => "on-request",
        Approval::Untrusted => "untrusted",
        Approval::Never => "never",
    }
}
