//! Saved agent metadata is a FULL store write, never a project config layer.
//! The effective user configuration read is a static file-policy window.
use super::{ConfigGet, ConfigList, ConfigSet, inputs::Validate};
use crate::{
    commit::Cx,
    config_policy::{Approval, ConfigFile, EffectiveSandbox, Provider, Sandbox},
    dispatch::{Kernel, admitted},
    scope,
    store_error::store_error,
};
use se_store::{
    Actor, AtomicBatch, EventBody, Expected, GrantKey, PermissionProfile, ProjectionRecord,
    Snapshot,
};
use se_types::{
    AgentId, IdempotencyKey, Omission, Page, Read, Result, SeError, Sequence, Source, StopReason,
    WindowFields,
};
use serde_json::{Value, json};
use std::num::NonZeroU32;

#[derive(Clone, Copy)]
pub(crate) enum Field {
    Model,
    Profile,
    CanCreate,
}
impl Field {
    pub(crate) fn default_value(self) -> Option<Value> {
        match self {
            Self::CanCreate => Some(Value::Bool(false)),
            Self::Model | Self::Profile => None,
        }
    }
    pub(crate) fn parse(key: &str) -> Result<(&str, Self)> {
        // This field is a setting name, never its possibly sensitive value.
        let invalid_key = |expected: &str| {
            let mut error = SeError::new(se_types::Detail::UsageInvalidValue(
                se_types::details::UsageInvalidValue {
                    argument: "agent configuration key".into(),
                    got: key.chars().flat_map(char::escape_debug).collect(),
                    expected: expected.into(),
                },
            ));
            error.body = error.body.with_remedy(se_types::Remedy {
                text: "Use an agent setting such as agent.main.model; se config get --help lists the supported forms. Permission profiles are edited in config.toml.".into(),
                command: None,
            });
            error
        };
        if key.starts_with("atlas.") {
            return Err(SeError::new(se_types::Detail::ConfigurationInvalid(se_types::details::ConfigurationInvalid {
                subject: key.into(),
                reason: "Atlas settings are user config.toml entries; se config get/set supports saved agent settings.".into(),
                next_step: "Edit [atlas] in the selected config.toml (inside the data home printed by se status, unless SE_CONFIG selects another file); set enabled = true, then run se down and se up with the same --home. Use se atlas for query help.".into(),
            })));
        }
        let (selector, field) = key
            .strip_prefix("agent.")
            .and_then(|key| key.rsplit_once('.'))
            .filter(|(selector, _)| !selector.is_empty())
            .ok_or_else(|| invalid_key("agent.<AGENT>.model, .profile or .can-create"))?;
        Ok((
            selector,
            match field {
                "model" => Self::Model,
                "profile" => Self::Profile,
                "can-create" => Self::CanCreate,
                _ => {
                    return Err(invalid_key("agent.<AGENT>.model, .profile or .can-create"));
                }
            },
        ))
    }
    pub(crate) fn value(self, body: &EventBody<se_store::StoredText>) -> Result<Value> {
        match (self, body) {
            (Self::Model, EventBody::ProfileSaved { profile, .. }) => {
                Ok(serde_json::json!(profile.model))
            }
            (Self::Profile, EventBody::ProfileSaved { profile, .. }) => {
                Ok(Value::String(profile.named_profile.clone()))
            }
            (Self::CanCreate, EventBody::GrantRecorded { active, .. }) => Ok(Value::Bool(*active)),
            _ => Err(scope::unreadable(
                "saved agent setting",
                "immutable event kind differs from setting",
            )),
        }
    }
    pub(crate) fn record<R: Snapshot>(
        self,
        agent: &AgentId,
        cx: &mut Cx<'_, R>,
    ) -> Result<Read<ProjectionRecord>> {
        match self {
            Self::Model | Self::Profile => cx.read.profile(agent.clone()),
            Self::CanCreate => cx.read.grant(
                Actor::Agent(agent.clone()),
                GrantKey::AgentCanCreate(agent.clone()),
            ),
        }
        .map_err(|error| store_error(&error))
    }
}
pub struct AgentConfigThen {
    pub(crate) request: IdempotencyKey,
    pub(crate) key: String,
    pub(crate) field: Field,
    pub(crate) human_only: bool,
}
fn agent<R: Snapshot>(selector: &str, cx: &mut Cx<'_, R>) -> Result<AgentId> {
    match scope::selected_actor(cx, selector)? {
        Actor::Agent(agent) => Ok(agent),
        Actor::Human(_) | Actor::Remote(_) => Err(SeError::invalid(
            "agent selector",
            "a saved agent, not the owner",
        )),
    }
}
pub fn get<R: Snapshot>(input: ConfigGet, cx: &mut Cx<'_, R>) -> Result<super::ConfigValueOutput> {
    input.validate()?;
    let (selector, field) = Field::parse(&input.key)?;
    let agent = agent(selector, cx)?;
    let mut origin = format!("agent record {agent}");
    let value = match field.record(&agent, cx)? {
        Read::Present { value } => Read::Present {
            value: field.value(&value.current.body)?,
        },
        Read::Absent { checked } => match field.default_value() {
            Some(value) => {
                origin = format!("default for agent {agent}; {checked}");
                Read::Present { value }
            }
            None => Read::Absent { checked },
        },
        other => other.map(|_| Value::Null),
    };
    Ok(super::ConfigValueOutput {
        key: input.key,
        value,
        origin: input.origin.then_some(origin),
    })
}
/// Complete static window over the closed config.toml key set. Every row is
/// the effective typed setting; only Option fields can be absent. `--origin`
/// reports the adapter-resolved file-level origin on every row and refuses
/// when the bound adapter carries none instead of inventing one.
pub fn list(
    configuration: &ConfigFile,
    origin: Option<&str>,
    input: ConfigList,
) -> Result<super::ConfigPageOutput> {
    input.validate()?;
    let origin = match (input.origin, origin) {
        (true, Some(origin)) => Some(origin.to_owned()),
        (true, None) => {
            return Err(scope::unreadable(
                "configuration origin",
                "the bound adapter carries no configuration origin",
            ));
        }
        (false, _) => None,
    };
    let mut rows: Vec<super::ConfigValueOutput> = Vec::new();
    let row = |rows: &mut Vec<super::ConfigValueOutput>, key: &str, value: Read<Value>| {
        rows.push(super::ConfigValueOutput {
            key: key.to_owned(),
            value,
            origin: origin.clone(),
        });
    };
    row(
        &mut rows,
        "default_project",
        present(json!(configuration.default_project)),
    );
    row(
        &mut rows,
        "launch.provider",
        present(json!(provider_wire(configuration.launch.provider))),
    );
    row(
        &mut rows,
        "launch.terminal",
        present(json!(configuration.launch.terminal)),
    );
    row(
        &mut rows,
        "runtime.listen_port",
        option(&configuration.runtime.listen_port),
    );
    row(
        &mut rows,
        "runtime.blocking_jobs",
        option(&configuration.runtime.blocking_jobs),
    );
    for (name, provider) in [
        ("claude", &configuration.providers.claude),
        ("codex", &configuration.providers.codex),
        ("secode", &configuration.providers.secode),
    ] {
        row(
            &mut rows,
            &format!("providers.{name}.command"),
            option(&provider.command),
        );
        row(
            &mut rows,
            &format!("providers.{name}.model"),
            present(json!(provider.model)),
        );
        row(
            &mut rows,
            &format!("providers.{name}.profile"),
            present(json!(provider.profile)),
        );
    }
    row(
        &mut rows,
        "providers.secode.seed_profile",
        option(&configuration.providers.secode.seed_profile),
    );
    for (name, profile) in &configuration.profiles {
        row(
            &mut rows,
            &format!("profiles.{name}.sandbox"),
            present(json!(sandbox_wire(profile.sandbox))),
        );
        row(
            &mut rows,
            &format!("profiles.{name}.network"),
            present(json!(profile.network)),
        );
        let approval = match &profile.approval {
            Some(approval) => present(json!(approval_wire(*approval))),
            None => Read::Absent {
                checked: "not set in the effective configuration".into(),
            },
        };
        row(&mut rows, &format!("profiles.{name}.approval"), approval);
        row(
            &mut rows,
            &format!("profiles.{name}.bypass"),
            present(json!(profile.bypass)),
        );
        row(
            &mut rows,
            &format!("profiles.{name}.git_write"),
            present(json!(profile.git_write)),
        );
    }
    row(
        &mut rows,
        "atlas.enabled",
        present(json!(configuration.atlas.enabled)),
    );
    row(
        &mut rows,
        "atlas.hooks",
        present(json!(configuration.atlas.hooks)),
    );
    row(
        &mut rows,
        "capture.enabled",
        present(json!(configuration.capture.enabled)),
    );
    let bytes = serde_json::to_vec(&rows)
        .map_err(|cause| scope::unreadable("configuration page encoding", &cause.to_string()))?
        .len() as u64;
    let fields = WindowFields {
        source: Source::Configuration {
            location: origin
                .clone()
                .unwrap_or_else(|| "unbound configuration policy".into()),
        },
        from: Sequence::ZERO,
        to: Sequence::new(rows.len() as u64)?,
        start_cursor: None,
        end_cursor: None,
        returned: rows.len() as u64,
        limit: NonZeroU32::new(rows.len() as u32)
            .ok_or_else(|| SeError::invalid("configuration page", "at least one setting row"))?,
        bytes,
        max_bytes: NonZeroU32::new(192 * 1024)
            .ok_or_else(|| SeError::invalid("configuration page", "a nonzero byte budget"))?,
        omitted_before: Omission::None,
        omitted_after: Omission::None,
        unreadable: 0,
        stop_reason: StopReason::Exhausted,
    };
    Ok(super::ConfigPageOutput {
        page: Page::new(rows, se_types::Window::new(fields)?, None)?,
    })
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
    match provider {
        Provider::Claude => "claude",
        Provider::Codex => "codex",
        Provider::SeCode => "secode",
    }
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
fn replay_target<R: Snapshot>(key: &IdempotencyKey, cx: &mut Cx<'_, R>) -> Result<Option<AgentId>> {
    let receipt = cx
        .read
        .operation_receipt(cx.admission.actor.clone(), key.clone())
        .map_err(|error| store_error(&error))?;
    match receipt {
        Read::Present { value } => {
            let event = super::receipt::committed_event(cx.read, &value)?;
            match event.body {
                EventBody::ProfileSaved { agent, .. } => Ok(Some(agent)),
                EventBody::GrantRecorded {
                    principal: Actor::Agent(agent),
                    ..
                } => Ok(Some(agent)),
                _ => Err(SeError::new(se_types::Detail::IdempotencyKeyReused(
                    se_types::details::IdempotencyKeyReused {
                        key: key.to_string(),
                        original_event: value.primary_event,
                    },
                ))),
            }
        }
        Read::Absent { .. } => Ok(None),
        other => {
            scope::require_present(
                other,
                "agent setting request identity",
                "Read the original agent setting request in this project and retry with the same --key; do not allocate a new key.",
            )?;
            Ok(None)
        }
    }
}
pub fn set<R: Snapshot>(
    kernel: &Kernel,
    input: ConfigSet,
    configuration: &ConfigFile,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, AgentConfigThen)> {
    input.validate()?;
    admitted(cx)?;
    if !matches!(cx.admission.actor, Actor::Human(_)) {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "config.set".into(),
            },
        )));
    }
    let (selector, field) = Field::parse(&input.key)?;
    let human_only = crate::config_policy::key_metadata(&input.key)?.human_only;
    let agent = match replay_target(&input.idempotency_key, cx)? {
        Some(agent) => agent,
        None => agent(selector, cx)?,
    };
    let record = field.record(&agent, cx)?;
    let (expected, cause) = match &record {
        Read::Present { value } => (
            Expected::Revision(value.revision),
            Some(value.current.header.event.clone()),
        ),
        Read::Absent { .. } => (Expected::Absent, None),
        _ => {
            scope::require_present(
                record.clone(),
                "saved agent setting",
                "Read this agent setting in the same project before retrying with the original --key.",
            )?;
            return Err(scope::unreadable(
                "saved agent setting",
                "unavailable record",
            ));
        }
    };
    let body = match field {
        Field::CanCreate => EventBody::GrantRecorded {
            principal: Actor::Agent(agent.clone()),
            key: GrantKey::AgentCanCreate(agent),
            active: match input.value.as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(SeError::invalid("can-create", "true or false")),
            },
            expected,
        },
        Field::Model | Field::Profile => {
            let saved = scope::require_present(
                record,
                "saved agent profile",
                "Read the saved profile of this exact agent in the same project before retrying with the original --key.",
            )?;
            let EventBody::ProfileSaved { mut profile, .. } = saved.current.body else {
                return Err(scope::unreadable(
                    "saved agent profile",
                    "current event is not ProfileSaved",
                ));
            };
            match field {
                Field::Model => {
                    profile.model = if input.value == "null" {
                        None
                    } else {
                        super::inputs::bounded("model", &input.value, 256, false)?;
                        Some(input.value.clone())
                    }
                }
                Field::Profile => {
                    let provider = match profile.provider {
                        se_store::Provider::Claude => crate::config_policy::Provider::Claude,
                        se_store::Provider::Codex => crate::config_policy::Provider::Codex,
                        se_store::Provider::SeCode => crate::config_policy::Provider::SeCode,
                    };
                    let resolved = configuration.resolve_profile(&input.value, provider, false)?;
                    profile.permission = match resolved.sandbox {
                        EffectiveSandbox::ReadOnly => PermissionProfile::ReadOnly,
                        EffectiveSandbox::WorkspaceWrite => PermissionProfile::WorkspaceWrite,
                        EffectiveSandbox::Bypass => PermissionProfile::NamedFullBypass,
                    };
                    profile.named_profile = input.value.clone();
                }
                Field::CanCreate => unreachable!(),
            }
            EventBody::ProfileSaved {
                agent,
                profile,
                expected,
            }
        }
    };
    let mut event = kernel.event(body, cx)?;
    event.header.cause = cause;
    let intent = serde_json::to_value(&input)
        .map_err(|error| scope::unreadable("agent setting intent", &error.to_string()))?;
    let batch = kernel.batch(
        "config.set",
        input.idempotency_key.clone(),
        intent,
        event,
        cx,
    )?;
    Ok((
        batch,
        AgentConfigThen {
            request: input.idempotency_key,
            key: input.key,
            field,
            human_only,
        },
    ))
}
#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "a failing test names the missing configuration row"
)]
mod list_tests {
    use super::*;

    fn value<'a>(page: &'a super::super::ConfigPageOutput, key: &'a str) -> &'a Read<Value> {
        &page
            .page
            .items()
            .iter()
            .find(|row| row.key == key)
            .expect("listed row present")
            .value
    }

    #[test]
    fn list_reports_the_closed_key_set_in_stable_order() -> Result<()> {
        let page = list(&ConfigFile::default(), None, ConfigList { origin: false })?;
        let keys: Vec<&str> = page
            .page
            .items()
            .iter()
            .map(|row| row.key.as_str())
            .collect();
        assert_eq!(
            keys,
            [
                "default_project",
                "launch.provider",
                "launch.terminal",
                "runtime.listen_port",
                "runtime.blocking_jobs",
                "providers.claude.command",
                "providers.claude.model",
                "providers.claude.profile",
                "providers.codex.command",
                "providers.codex.model",
                "providers.codex.profile",
                "providers.secode.command",
                "providers.secode.model",
                "providers.secode.profile",
                "providers.secode.seed_profile",
                "profiles.default.sandbox",
                "profiles.default.network",
                "profiles.default.approval",
                "profiles.default.bypass",
                "profiles.default.git_write",
                "atlas.enabled",
                "atlas.hooks",
                "capture.enabled",
            ]
        );
        assert!(page.page.window().complete());
        assert!(page.page.next().is_none());
        assert!(page.page.items().iter().all(|row| row.origin.is_none()));
        Ok(())
    }

    #[test]
    fn list_shows_set_values_with_wire_strings_and_unset_options_as_absent() -> Result<()> {
        let mut configuration = ConfigFile::default();
        configuration.launch.provider = Provider::SeCode;
        configuration.launch.terminal = "conhost".into();
        configuration.runtime.blocking_jobs = Some(4);
        configuration.providers.codex.command = Some("/usr/local/bin/codex".into());
        configuration.providers.secode.seed_profile = Some("seed".into());
        let default_profile = configuration
            .profiles
            .get_mut("default")
            .expect("default profile present");
        default_profile.approval = Some(Approval::Untrusted);
        default_profile.sandbox = Sandbox::ReadOnly;
        default_profile.network = true;
        let page = list(&configuration, None, ConfigList { origin: false })?;
        assert_eq!(
            value(&page, "launch.provider"),
            &Read::Present {
                value: json!("secode")
            }
        );
        assert_eq!(
            value(&page, "launch.terminal"),
            &Read::Present {
                value: json!("conhost")
            }
        );
        assert_eq!(
            value(&page, "runtime.listen_port"),
            &Read::Absent {
                checked: "not set in the effective configuration".into()
            }
        );
        assert_eq!(
            value(&page, "runtime.blocking_jobs"),
            &Read::Present { value: json!(4) }
        );
        assert_eq!(
            value(&page, "providers.codex.command"),
            &Read::Present {
                value: json!("/usr/local/bin/codex")
            }
        );
        assert_eq!(
            value(&page, "providers.claude.command"),
            &Read::Absent {
                checked: "not set in the effective configuration".into()
            }
        );
        assert_eq!(
            value(&page, "providers.secode.seed_profile"),
            &Read::Present {
                value: json!("seed")
            }
        );
        assert_eq!(
            value(&page, "profiles.default.approval"),
            &Read::Present {
                value: json!("untrusted")
            }
        );
        assert_eq!(
            value(&page, "profiles.default.sandbox"),
            &Read::Present {
                value: json!("read-only")
            }
        );
        assert_eq!(
            value(&page, "profiles.default.network"),
            &Read::Present { value: json!(true) }
        );
        Ok(())
    }

    #[test]
    fn list_binds_the_file_level_origin_to_every_row_on_request() -> Result<()> {
        let configuration = ConfigFile::default();
        let page = list(
            &configuration,
            Some("config.toml /home/owner/.stateengine/config.toml"),
            ConfigList { origin: true },
        )?;
        assert!(page.page.items().iter().all(|row| {
            row.origin.as_deref() == Some("config.toml /home/owner/.stateengine/config.toml")
        }));
        assert!(list(&configuration, None, ConfigList { origin: true }).is_err());
        Ok(())
    }
}
