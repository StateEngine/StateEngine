//! Installed-harness setup data; these recipes never install or acquire credentials.
use schemars::JsonSchema;
use se_config::config_policy::harness::HarnessDescriptor;
use se_types::{Result, SeError};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    pub title: String,
    pub setup_url: String,
    pub descriptor: HarnessDescriptor,
    pub package: Option<NodePackage>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodePackage {
    pub name: String,
    pub bin: String,
}

pub fn presets() -> Result<&'static BTreeMap<String, Preset>> {
    static DATA: OnceLock<std::result::Result<BTreeMap<String, Preset>, String>> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("catalog.json")).map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|error| SeError::invalid("harness catalogue", error))
}
