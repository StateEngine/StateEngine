//! Legacy configuration keys and shared harness defaults, emitted from the registry.
use super::{Provider, default_profile};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub model: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Copied into a new private service profile, never used as its write target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_profile: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            command: None,
            model: String::new(),
            profile: default_profile(),
            seed_profile: None,
        }
    }
}

fn is_default_provider(value: &ProviderConfig) -> bool {
    value.command.is_none()
        && value.model.is_empty()
        && value.profile == "default"
        && value.seed_profile.is_none()
}

macro_rules! define_providers {
    ($($variant:ident $field:ident [$($default:tt)*] [$($skip:tt)*] $metadata:tt;)*) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct Providers {
            $(#[serde(default)] $($skip)* pub $field: ProviderConfig,)*
        }

        impl Providers {
            pub fn get(&self, provider: Provider) -> &ProviderConfig {
                match provider { $(Provider::$variant => &self.$field,)* }
            }
        }
    };
}
se_types::with_harness_registry!(define_providers);
