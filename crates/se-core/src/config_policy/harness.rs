//! Finite ACP launch descriptors. Protocol, credentials and replay remain driver-owned.
use super::{AcpConfig, ConfigFile, Provider, invalid};
use schemars::JsonSchema;
use se_types::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Driver {
    AcpStdio,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarnessDescriptor {
    pub driver: Driver,
    /// Native executable or interpreter; no shell command strings.
    pub command: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Appended only when an agent has selected a model; native defaults otherwise.
    #[serde(default)]
    pub model_arguments: Vec<String>,
    /// Names only. Native provider login and credential acquisition stay with the harness.
    #[serde(default)]
    pub environment: Vec<String>,
    /// Optional native environment binding for the saved model, instead of an argv slot.
    pub model_environment: Option<String>,
    /// Exact named launch profiles mapped to the harness's own permission choices.
    pub permissions: BTreeMap<String, PermissionChoice>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionChoice {
    pub arguments: Vec<String>,
    /// Native mode settings only; account and credential values are inherited by name.
    pub environment: BTreeMap<String, String>,
    /// Required native mode readback. Empty retains the announced native default.
    pub mode: String,
}
pub struct InvocationSettings {
    pub arguments: Vec<String>,
    pub model_arguments: Vec<String>,
    pub environment: Vec<String>,
    pub values: BTreeMap<String, String>,
    pub model_environment: Option<String>,
    pub mode: String,
}
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(invalid(
            "harness",
            "use 1..64 ASCII letters, digits, underscore or hyphen",
        ));
    }
    Ok(())
}
pub(super) fn validate_registry(values: &BTreeMap<String, HarnessDescriptor>) -> Result<()> {
    if values.len() > 64 {
        return Err(invalid("harnesses", "at most 64 descriptors are supported"));
    }
    for (name, descriptor) in values {
        validate_name(name)?;
        if descriptor.command.is_empty()
            || descriptor.command.len() > 4096
            || descriptor.command.contains('\0')
            || descriptor.permissions.is_empty()
            || descriptor.permissions.len() > 64
        {
            return Err(invalid(
                "harness descriptor",
                "select a native command and 1..64 explicit permission mappings",
            ));
        }
        if let Some(model) = &descriptor.model_environment {
            validate_environment(model)?;
        }
        for (profile, choice) in &descriptor.permissions {
            validate_name(profile)?;
            let mut arguments = descriptor.arguments.clone();
            arguments.extend(descriptor.model_arguments.clone());
            arguments.extend(choice.arguments.clone());
            let mut environment = descriptor.environment.clone();
            environment.extend(choice.environment.keys().cloned());
            if let Some(model) = &descriptor.model_environment {
                environment.push(model.clone());
                if choice
                    .environment
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(model))
                {
                    return Err(invalid(
                        "harness model",
                        "the model environment binding also has a permission value",
                    ));
                }
            }
            AcpConfig {
                harness: None,
                arguments,
                environment,
                mode: choice.mode.clone(),
            }
            .validate()?;
            for (key, value) in &choice.environment {
                validate_environment(key)?;
                if value.len() > 512 || value.chars().any(char::is_control) {
                    return Err(invalid(
                        "harness permission environment",
                        "select a bounded native mode value",
                    ));
                }
            }
        }
    }
    Ok(())
}
fn validate_environment(name: &str) -> Result<()> {
    AcpConfig {
        environment: vec![name.into()],
        ..Default::default()
    }
    .validate()
}
impl ConfigFile {
    pub fn selected_harness(
        &self,
        provider: Provider,
        requested: Option<&str>,
    ) -> Result<Option<String>> {
        if provider != Provider::Acp {
            if requested.is_some() {
                return Err(invalid(
                    "harness",
                    "named descriptors use provider acp; select --provider acp or omit --provider",
                ));
            }
            return Ok(None);
        }
        let selected = requested.or(self.acp.harness.as_deref());
        if let Some(name) = selected {
            self.harness(name)?;
        }
        Ok(selected.map(str::to_owned))
    }
    pub fn harness(&self, name: &str) -> Result<&HarnessDescriptor> {
        validate_name(name)?;
        self.harnesses.get(name).ok_or_else(|| invalid("harness", &format!("descriptor {name:?} is absent; restore its original [harnesses] entry before launching this saved agent")))
    }
    pub fn acp_settings(&self, harness: Option<&str>, profile: &str) -> Result<InvocationSettings> {
        let Some(name) = harness else {
            return Ok(InvocationSettings {
                arguments: self.acp.arguments.clone(),
                model_arguments: Vec::new(),
                environment: self.acp.environment.clone(),
                values: BTreeMap::new(),
                model_environment: None,
                mode: self.acp.mode.clone(),
            });
        };
        let descriptor = self.harness(name)?;
        let permission = descriptor.permissions.get(profile).ok_or_else(|| invalid("harness permission", &format!("descriptor {name:?} has no mapping for launch profile {profile:?}; select a mapped profile or add its native harness permission choice")))?;
        let mut arguments = descriptor.arguments.clone();
        arguments.extend(permission.arguments.clone());
        Ok(InvocationSettings {
            arguments,
            model_arguments: descriptor.model_arguments.clone(),
            environment: descriptor.environment.clone(),
            values: permission.environment.clone(),
            model_environment: descriptor.model_environment.clone(),
            mode: permission.mode.clone(),
        })
    }
}
