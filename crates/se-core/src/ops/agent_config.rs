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
    AgentId, Cursor, IdempotencyKey, Omission, OmissionReason, Page, Read, Result, SeError,
    Sequence, Source, StopReason, WindowFields,
};
use serde_json::{Value, json};
use std::num::{NonZeroU32, NonZeroU64};

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
/// Bounded static pages over the closed config.toml key set. Every row is
/// the effective typed setting; only Option fields can be absent. `--origin`
/// reports the adapter-resolved file-level origin on every row and refuses
/// when the bound adapter carries none instead of inventing one. A page is
/// bounded by the requested row limit and the wire byte budget; the returned
/// cursor continues the list, so a valid large configuration lists completely
/// across pages instead of refusing the whole file.
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
    // The row set is static, so the cursor is a plain row count: the rows
    // before it are the pages the caller already received.
    let offset = cursor_offset(input.cursor.as_ref())?;
    let total = rows.len() as u64;
    if offset > total {
        return Err(SeError::invalid(
            "cursor",
            "a config list cursor within the row set; it names a row past the end",
        ));
    }
    // Exact per-row wire sizes: serde_json writes a Vec as `[a,b,c]`, so a
    // page's bytes are the two brackets, the row sizes, and one comma per gap.
    let sizes: Vec<u64> = rows
        .iter()
        .map(|row| {
            serde_json::to_vec(row)
                .map(|bytes| bytes.len() as u64)
                .map_err(|cause| {
                    scope::unreadable("configuration row encoding", &cause.to_string())
                })
        })
        .collect::<Result<Vec<u64>>>()?;
    const PAGE_MAX_BYTES: u32 = 192 * 1024;
    let limit = u64::from(input.limit);
    let mut end = offset;
    let mut bytes: u64 = 2;
    while end < total && end - offset < limit {
        let next = bytes
            .checked_add(if end == offset { 0 } else { 1 })
            .and_then(|sum| sum.checked_add(sizes[end as usize]))
            .ok_or_else(|| SeError::invalid("configuration page", "a nonoverflowing byte count"))?;
        if next > u64::from(PAGE_MAX_BYTES) {
            break;
        }
        bytes = next;
        end += 1;
    }
    if end == offset && offset < total {
        return Err(SeError::invalid(
            "configuration row",
            "a single row within the 192 KiB page byte budget",
        ));
    }
    let stop = if end == total {
        StopReason::Exhausted
    } else if end - offset == limit {
        StopReason::ItemLimit
    } else {
        StopReason::ByteLimit
    };
    let omitted_after = match stop {
        StopReason::Exhausted => Omission::None,
        other => Omission::Known {
            count: NonZeroU64::new(total - end).ok_or_else(|| {
                SeError::invalid("configuration page", "a nonempty remainder past the page")
            })?,
            reason: if other == StopReason::ItemLimit {
                OmissionReason::Limit
            } else {
                OmissionReason::Budget
            },
        },
    };
    let end_cursor = Cursor::new(format!("config-list/v1/{end}"))?;
    let fields = WindowFields {
        source: Source::Configuration {
            location: origin
                .clone()
                .unwrap_or_else(|| "effective configuration".into()),
        },
        from: Sequence::new(offset)?,
        to: Sequence::new(end)?,
        start_cursor: input.cursor.clone(),
        end_cursor: Some(end_cursor.clone()),
        returned: end - offset,
        limit: NonZeroU32::new(u32::from(input.limit))
            .ok_or_else(|| SeError::invalid("configuration page", "at least one setting row"))?,
        bytes,
        max_bytes: NonZeroU32::new(PAGE_MAX_BYTES)
            .ok_or_else(|| SeError::invalid("configuration page", "a nonzero byte budget"))?,
        omitted_before: Omission::None,
        omitted_after,
        unreadable: 0,
        stop_reason: stop,
    };
    let next = (stop != StopReason::Exhausted).then_some(end_cursor);
    let items = rows[offset as usize..end as usize].to_vec();
    Ok(super::ConfigPageOutput {
        page: Page::new(items, se_types::Window::new(fields)?, next)?,
    })
}
fn cursor_offset(cursor: Option<&Cursor>) -> Result<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let rest = cursor
        .as_str()
        .strip_prefix("config-list/v1/")
        .ok_or_else(|| SeError::invalid("cursor", "a config list cursor"))?;
    rest.parse()
        .map_err(|_| SeError::invalid("cursor", "a config list cursor"))
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
    use crate::config_policy::Profile;

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
        let page = list(
            &ConfigFile::default(),
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
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
        let page = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
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
            ConfigList {
                origin: true,
                limit: 100,
                cursor: None,
            },
        )?;
        assert!(page.page.items().iter().all(|row| {
            row.origin.as_deref() == Some("config.toml /home/owner/.stateengine/config.toml")
        }));
        assert!(
            list(
                &configuration,
                None,
                ConfigList {
                    origin: true,
                    limit: 100,
                    cursor: None,
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn list_pages_a_large_configuration_to_completion() -> Result<()> {
        let mut configuration = ConfigFile::default();
        for index in 0..600 {
            configuration
                .profiles
                .insert(format!("profile-{index:03}"), Profile::default());
        }
        let mut expected: Vec<String> = [
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
        ]
        .iter()
        .map(|key| (*key).to_string())
        .collect();
        for name in configuration.profiles.keys() {
            for field in ["sandbox", "network", "approval", "bypass", "git_write"] {
                expected.push(format!("profiles.{name}.{field}"));
            }
        }
        for key in ["atlas.enabled", "atlas.hooks", "capture.enabled"] {
            expected.push((*key).to_string());
        }
        let mut collected: Vec<String> = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let page = list(
                &configuration,
                None,
                ConfigList {
                    origin: false,
                    limit: 100,
                    cursor: cursor.clone(),
                },
            )?;
            let fields = page.page.window().fields().expect("producer window");
            assert!(fields.bytes <= 192 * 1024, "page within the byte budget");
            assert_eq!(fields.returned, page.page.items().len() as u64);
            for row in page.page.items() {
                collected.push(row.key.clone());
            }
            pages += 1;
            if page.page.window().complete() {
                assert!(page.page.next().is_none());
                assert_eq!(fields.stop_reason, StopReason::Exhausted);
                break;
            }
            assert_eq!(fields.stop_reason, StopReason::ItemLimit);
            assert_eq!(
                page.page.window().omitted().reason,
                Some(OmissionReason::Limit)
            );
            assert_eq!(
                page.page.window().omitted().count,
                Some(expected.len() as u64 - collected.len() as u64)
            );
            // A bounded page is not a failure: the owner CLI stays exit 0.
            assert_eq!(page.page.window().exit_code(false), 0);
            cursor = Some(page.page.next().cloned().expect("continuation cursor"));
        }
        assert_eq!(pages, 31);
        assert_eq!(collected, expected);
        Ok(())
    }

    #[test]
    fn list_continues_from_a_cursor_without_overlap_or_gap() -> Result<()> {
        let mut configuration = ConfigFile::default();
        for index in 0..300 {
            configuration
                .profiles
                .insert(format!("profile-{index:03}"), Profile::default());
        }
        let first = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
        let next = first.page.next().cloned().expect("continuation cursor");
        let last = first
            .page
            .items()
            .last()
            .expect("first page rows")
            .key
            .clone();
        let second = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: Some(next),
            },
        )?;
        let second_fields = second.page.window().fields().expect("producer window");
        assert_eq!(second_fields.from.get(), first_fields_to(first));
        assert_ne!(
            second.page.items().first().expect("second page rows").key,
            last
        );
        assert!(
            second.page.items().iter().all(|row| row.key != last),
            "no row repeats across the boundary"
        );
        Ok(())
    }
    fn first_fields_to(page: super::super::ConfigPageOutput) -> u64 {
        page.page
            .window()
            .fields()
            .expect("producer window")
            .to
            .get()
    }

    #[test]
    fn list_stops_a_page_at_the_byte_budget() -> Result<()> {
        let mut configuration = ConfigFile::default();
        for index in 0..300 {
            configuration
                .profiles
                .insert(format!("profile-{index:03}"), Profile::default());
        }
        let origin = format!("config.toml {}", "x".repeat(4000));
        let first = list(
            &configuration,
            Some(&origin),
            ConfigList {
                origin: true,
                limit: 500,
                cursor: None,
            },
        )?;
        let fields = first.page.window().fields().expect("producer window");
        assert_eq!(fields.stop_reason, StopReason::ByteLimit);
        assert!(fields.bytes <= 192 * 1024, "budgeted page");
        assert_eq!(
            first.page.window().omitted().reason,
            Some(OmissionReason::Budget)
        );
        assert_eq!(first.page.window().exit_code(false), 0);
        let mut cursor = first.page.next().cloned().expect("budget continuation");
        let mut seen = first.page.items().len();
        loop {
            let page = list(
                &configuration,
                Some(&origin),
                ConfigList {
                    origin: true,
                    limit: 500,
                    cursor: Some(cursor),
                },
            )?;
            seen += page.page.items().len();
            if page.page.window().complete() {
                assert!(page.page.next().is_none());
                break;
            }
            cursor = page.page.next().cloned().expect("continuation cursor");
        }
        assert_eq!(seen, 18 + 5 * 301);
        Ok(())
    }

    #[test]
    fn list_end_cursor_yields_an_empty_complete_page() -> Result<()> {
        let configuration = ConfigFile::default();
        let total = list(
            &ConfigFile::default(),
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?
        .page
        .window()
        .fields()
        .expect("producer window")
        .to
        .get();
        let page = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: Some(Cursor::new(format!("config-list/v1/{total}")).expect("end cursor")),
            },
        )?;
        assert!(page.page.window().complete());
        assert_eq!(page.page.items().len(), 0);
        assert!(page.page.next().is_none());
        Ok(())
    }

    #[test]
    fn list_refuses_bad_and_past_end_cursors() -> Result<()> {
        let configuration = ConfigFile::default();
        for cursor in [
            "config-list/v1/x",
            "other/v1/1",
            "config-list/v1/",
            "config-list/v1/999999",
        ] {
            let page = list(
                &configuration,
                None,
                ConfigList {
                    origin: false,
                    limit: 100,
                    cursor: Some(Cursor::new(cursor).expect("cursor")),
                },
            );
            assert!(page.is_err(), "cursor {cursor} must refuse");
        }
        Ok(())
    }

    #[test]
    fn list_refuses_limits_outside_the_supported_range() -> Result<()> {
        let configuration = ConfigFile::default();
        for limit in [0u16, 501] {
            let page = list(
                &configuration,
                None,
                ConfigList {
                    origin: false,
                    limit,
                    cursor: None,
                },
            );
            assert!(page.is_err(), "limit {limit} must refuse");
        }
        Ok(())
    }

    #[test]
    fn list_names_the_effective_configuration_without_an_origin() -> Result<()> {
        let configuration = ConfigFile::default();
        let page = list(
            &configuration,
            None,
            ConfigList {
                origin: false,
                limit: 100,
                cursor: None,
            },
        )?;
        assert_eq!(
            page.page.window().fields().expect("producer window").source,
            Source::Configuration {
                location: "effective configuration".into()
            }
        );
        let page = list(
            &configuration,
            Some("config.toml /home/owner/config.toml"),
            ConfigList {
                origin: true,
                limit: 100,
                cursor: None,
            },
        )?;
        assert_eq!(
            page.page.window().fields().expect("producer window").source,
            Source::Configuration {
                location: "config.toml /home/owner/config.toml".into()
            }
        );
        Ok(())
    }
}
