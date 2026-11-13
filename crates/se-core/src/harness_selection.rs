//! Shared harness choices and a setup plan over adapter-supplied observations.
//! Native discovery, installation, login and process effects remain host-owned.
use crate::config_policy::ConfigFile;
use schemars::JsonSchema;
use se_types::{ErrorBody, Provider, Read, Result, SeError, Sha256};
use serde::{Deserialize, Serialize};

/// A structured key avoids collisions between provider names and user descriptors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Selection {
    Provider { provider: Provider },
    Descriptor { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Choice {
    pub selection: Selection,
    pub title: String,
}

/// Listing a configured choice establishes neither installation nor support.
pub fn choices(configuration: &ConfigFile) -> Result<Vec<Choice>> {
    configuration.validate()?;
    let mut values: Vec<_> = [
        (Provider::Claude, "Claude Code"),
        (Provider::Codex, "Codex"),
        (Provider::SeCode, "SE Code"),
    ]
    .into_iter()
    .map(|(provider, title)| Choice {
        selection: Selection::Provider { provider },
        title: title.into(),
    })
    .collect();
    values.extend(configuration.harnesses.keys().map(|name| Choice {
        selection: Selection::Descriptor { name: name.clone() },
        title: name.clone(),
    }));
    // Legacy protocol settings remain selectable without inventing a named entry.
    if configuration.acp.harness.is_none()
        && !configuration.provider_command(Provider::Acp).is_empty()
    {
        values.push(Choice {
            selection: Selection::Provider {
                provider: Provider::Acp,
            },
            title: "Configured protocol agent".into(),
        });
    }
    Ok(values)
}

/// Existing init/agent-create inputs persist this exact pair.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Binding {
    pub provider: Provider,
    pub harness: Option<String>,
}

impl Selection {
    pub fn binding(&self, configuration: &ConfigFile) -> Result<Binding> {
        configuration.validate()?;
        match self {
            Self::Provider { provider } => {
                if *provider == Provider::Acp && configuration.acp.harness.is_some() {
                    return Err(SeError::invalid(
                        "protocol harness selection",
                        "select the named descriptor instead of an implicit default",
                    ));
                }
                Ok(Binding {
                    provider: *provider,
                    harness: None,
                })
            }
            Self::Descriptor { name } => Ok(Binding {
                provider: Provider::Acp,
                harness: configuration.selected_harness(Provider::Acp, Some(name))?,
            }),
        }
    }
}

/// Completion requires external readback at every step, including actual launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    Installation,
    Authentication,
    Configuration,
    Agent,
    Launch,
}

/// Configuration or launch-choice changes begin a fresh setup attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetupIdentity {
    pub selection: Selection,
    pub attempt: String,
    pub configuration_sha256: Sha256,
    pub model: Option<String>,
    pub permission_profile: String,
}

/// Hosts retain detailed native evidence; no credentials are part of this DTO.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub setup: SetupIdentity,
    pub step: Step,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub step: Step,
    pub readback: Read<Witness>,
}

/// Every surface renders and executes the same next action through the host.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Next {
    Observe {
        step: Step,
        reason: String,
    },
    Setup {
        step: Step,
        checked: String,
    },
    Unreadable {
        step: Step,
        source: String,
        reason: String,
        error: Option<Box<ErrorBody>>,
    },
    Ready,
}

/// Missing observation means unmeasured, while witnessed absence requests setup.
/// Failed or cancelled effects supply no completion witness; adapters retain
/// those outcomes beside this plan and re-observe before attempting setup again.
pub fn next(setup: &SetupIdentity, observations: &[Observation]) -> Result<Next> {
    if setup.attempt.is_empty()
        || setup.attempt.len() > 128
        || setup.attempt.chars().any(char::is_control)
    {
        return Err(SeError::invalid(
            "harness setup attempt",
            "1..128 printable bytes",
        ));
    }
    let steps = [
        Step::Installation,
        Step::Authentication,
        Step::Configuration,
        Step::Agent,
        Step::Launch,
    ];
    for (index, observation) in observations.iter().enumerate() {
        if observations[..index]
            .iter()
            .any(|prior| prior.step == observation.step)
        {
            return Err(SeError::invalid(
                "harness setup observations",
                "one readback per step",
            ));
        }
        if let Read::Present { value } = &observation.readback
            && (&value.setup != setup || value.step != observation.step)
        {
            return Err(SeError::invalid(
                "harness setup readback",
                "the selected harness, configuration, model, permission profile, attempt and step",
            ));
        }
    }
    for step in steps {
        let Some(observation) = observations.iter().find(|value| value.step == step) else {
            return Ok(Next::Observe {
                step,
                reason: "No readback has been supplied".into(),
            });
        };
        match &observation.readback {
            Read::Present { .. } => (),
            Read::Absent { checked } => {
                return Ok(Next::Setup {
                    step,
                    checked: checked.clone(),
                });
            }
            Read::Unreadable {
                source,
                reason,
                error,
            } => {
                return Ok(Next::Unreadable {
                    step,
                    source: source.clone(),
                    reason: reason.clone(),
                    error: error.clone(),
                });
            }
            Read::Unknown { what } => {
                return Ok(Next::Observe {
                    step,
                    reason: what.clone(),
                });
            }
        }
    }
    Ok(Next::Ready)
}
