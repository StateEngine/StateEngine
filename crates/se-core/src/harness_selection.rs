//! Shared harness choices and their existing persisted provider/descriptor binding.
//! Native discovery, installation, login and process effects remain host-owned.
use crate::config_policy::ConfigFile;
use schemars::JsonSchema;
use se_types::{Provider, Result, SeError};
use serde::{Deserialize, Serialize};
pub mod catalog;

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
    values.extend(
        catalog::presets()?
            .iter()
            .filter(|(name, _)| !configuration.harnesses.contains_key(*name))
            .map(|(name, preset)| Choice {
                selection: Selection::Descriptor { name: name.clone() },
                title: preset.title.clone(),
            }),
    );
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

/// CLI and MCP use the same choice names. Existing configured descriptor names
/// take precedence, preserving saved command meaning when a name matches a provider.
pub fn resolve(
    configuration: &ConfigFile,
    provider: Option<Provider>,
    requested: Option<&str>,
) -> Result<Binding> {
    configuration.validate()?;
    let Some(name) = requested else {
        let provider = provider.unwrap_or(configuration.launch.provider);
        return Ok(Binding {
            provider,
            harness: configuration.selected_harness(provider, None)?,
        });
    };
    crate::config_policy::harness::validate_name(name)?;
    let choice = if configuration.harnesses.contains_key(name) {
        Selection::Descriptor { name: name.into() }
    } else {
        let provider = match name {
            "claude" => Provider::Claude,
            "codex" => Provider::Codex,
            "secode" => Provider::SeCode,
            _ => {
                if catalog::presets()?.contains_key(name) {
                    return Err(SeError::new(se_types::Detail::FeatureUnavailable(
                        se_types::details::FeatureUnavailable {
                            subject: format!("harness {name}"),
                            reason: "installed harness is not configured in this home".into(),
                            next_step: format!(
                                "Run se init --harness {name} for a new agent from the project owner's terminal with the same --home, then retry this operation."
                            ),
                        },
                    )));
                }
                return Err(SeError::invalid("harness", "select a listed harness"));
            }
        };
        Selection::Provider { provider }
    };
    let binding = choice.binding(configuration)?;
    if provider.is_some_and(|explicit| explicit != binding.provider) {
        return Err(SeError::invalid(
            "harness provider",
            "omit --provider or select the provider belonging to this harness",
        ));
    }
    Ok(binding)
}
