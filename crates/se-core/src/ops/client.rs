//! The native human viewer uses the same bounded records as a remote client.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::{Result, SeError, remote::RemoteWatch};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientWatchCall {
    pub request: RemoteWatch,
    #[serde(default)]
    pub wait_ms: u32,
    #[serde(skip)]
    #[schemars(skip)]
    pub follow: bool,
}
impl Validate for ClientWatchCall {
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        if self.request.targets.is_empty() || self.wait_ms > 30_000 {
            return Err(SeError::invalid(
                "local watch",
                "exact selected targets and 0..30000 milliseconds",
            ));
        }
        Ok(())
    }
}
