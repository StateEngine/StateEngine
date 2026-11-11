//! Owner diagnostic export receipt. Collection and private publication are native CLI work.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBundle {}
impl Validate for DiagnosticBundle {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// A receipt is returned only after reopening and digest-checking the private file.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticBundleOutput {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    /// All requested observations were collected within their explicit bounds.
    /// A complete collection may still describe an unhealthy installation.
    pub complete: bool,
}
