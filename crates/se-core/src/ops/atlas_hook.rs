//! Private provider augmentation, separate from the five public Atlas queries.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::{
    NativePath, Result, SeError,
    code::{AtlasText, QueryText, RootId},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
/// The whole provider hook: process start, configuration, one local IPC round
/// trip and the host's answer. Windows process creation and named pipes are
/// slower than Unix sockets.
pub const HOOK_DEADLINE: Duration = if cfg!(windows) {
    Duration::from_millis(100)
} else {
    Duration::from_millis(75)
};
/// The host's share of [`HOOK_DEADLINE`] after admitting the request, leaving
/// the rest for the hook process around it.
pub const HOOK_HOST_BUDGET: Duration = if cfg!(windows) {
    Duration::from_millis(70)
} else {
    Duration::from_millis(50)
};
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum AtlasHookTarget {
    Symbol(QueryText),
    File(NativePath),
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasAugment {
    pub target: AtlasHookTarget,
    #[serde(default)]
    pub root: Option<RootId>,
    /// Set only by native ingress after reading the frame, before admission.
    #[serde(skip)]
    #[schemars(skip)]
    pub deadline: Option<Instant>,
}
impl Validate for AtlasAugment {
    fn validate(&self) -> Result<()> {
        match &self.target {
            AtlasHookTarget::Symbol(name) => {
                if name.as_str().len() > 128
                    || !name.as_str().bytes().enumerate().all(|(i, b)| {
                        b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit())
                    })
                {
                    return Err(SeError::invalid(
                        "Atlas hook symbol",
                        "one ASCII identifier, at most 128 bytes",
                    ));
                }
            }
            AtlasHookTarget::File(path) => {
                if !path.to_local()?.is_absolute() {
                    return Err(SeError::invalid(
                        "Atlas hook file",
                        "an absolute native path",
                    ));
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtlasHookOutput {
    /// At most 600 bytes of provider JSON; empty means no confident augmentation.
    pub stdout: String,
}
