//! Built-in harness identity and declarative defaults shared by every ingress.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub struct HarnessRegistration {
    pub provider: Provider,
    pub id: &'static str,
    pub title: &'static str,
    pub selection_title: &'static str,
    pub driver: &'static str,
    pub default_command: &'static str,
    /// Built-in selections are distinct from named protocol descriptors.
    pub selectable: bool,
    pub seed_profile: bool,
    pub detached_no_approval: bool,
}

macro_rules! define_registry {
    ($($variant:ident $field:ident [$($default:tt)*] [$($skip:tt)*] {
        id: $id:literal, title: $title:literal, selection_title: $selection_title:literal, driver: $driver:literal, command: $command:literal,
        selectable: $selectable:literal, seed_profile: $seed:literal,
        detached_no_approval: $detached:literal
    };)*) => {
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "lowercase")]
        pub enum Provider {
            $($($default)* #[serde(rename = $id)] $variant,)*
        }

        pub const HARNESS_REGISTRY: &[HarnessRegistration] = &[$(HarnessRegistration {
            provider: Provider::$variant,
            id: $id, title: $title, selection_title: $selection_title, driver: $driver, default_command: $command,
            selectable: $selectable, seed_profile: $seed, detached_no_approval: $detached,
        },)*];
    };
}
with_harness_registry!(define_registry);

impl Provider {
    pub const fn registration(self) -> &'static HarnessRegistration {
        // The enum and table are emitted in the same registry order.
        &HARNESS_REGISTRY[self as usize]
    }

    pub const fn id(self) -> &'static str {
        self.registration().id
    }

    pub fn from_id(id: &str) -> Option<Self> {
        HARNESS_REGISTRY
            .iter()
            .find(|row| row.id == id)
            .map(|row| row.provider)
    }
}
