use schemars::JsonSchema;
use se_types::Read;
use serde::{Deserialize, Serialize};

/// Public configuration readback. A present JSON value retains its setting type;
/// absence and a failed read must not become a successful null value.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfigValueOutput {
    pub key: String,
    pub value: Read<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}
impl ConfigValueOutput {
    pub fn into_envelope(self) -> super::super::Envelope<Self> {
        super::super::Envelope::new(
            crate::registry::Family {
                name: "se.config-value",
                major: 1,
            },
            self,
        )
    }
}
