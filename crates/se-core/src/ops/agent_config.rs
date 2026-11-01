//! Saved agent metadata is a FULL store write, never a project config layer.
use super::{ConfigGet, ConfigSet, inputs::Validate};
use crate::{
    admission::{HumanTerminal, require_human_terminal},
    commit::Cx,
    config_policy::{ConfigFile, EffectiveSandbox},
    dispatch::{Kernel, admitted},
    scope,
    store_error::store_error,
};
use se_store::{
    Actor, AtomicBatch, EventBody, Expected, GrantKey, PermissionProfile, ProjectionRecord,
    Snapshot,
};
use se_types::{AgentId, IdempotencyKey, Read, Result, SeError};
use serde_json::Value;

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
        let (selector, field) = key
            .strip_prefix("agent.")
            .and_then(|key| key.rsplit_once('.'))
            .filter(|(selector, _)| !selector.is_empty())
            .ok_or_else(|| {
                SeError::invalid(
                    "agent configuration key",
                    "agent.<AGENT>.model, .profile or .can-create",
                )
            })?;
        Ok((
            selector,
            match field {
                "model" => Self::Model,
                "profile" => Self::Profile,
                "can-create" => Self::CanCreate,
                _ => {
                    return Err(SeError::invalid(
                        "agent configuration key",
                        "model, profile or can-create",
                    ));
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
    match scope::actor_selector(cx.read, selector)? {
        Actor::Agent(agent) => Ok(agent),
        Actor::Human(_) => Err(SeError::invalid(
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
    terminal: &HumanTerminal,
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
    if human_only {
        require_human_terminal("config.set", cx.admission, terminal)?;
    }
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
                        se_store::Provider::SeCode => {
                            return Err(SeError::invalid(
                                "provider",
                                "a standalone Claude or Codex agent",
                            ));
                        }
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
