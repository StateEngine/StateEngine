use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Application session material travels only through protected local custody or
/// an authenticated SSH channel. It is never a user-facing result or argument.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct LinkSecret([u8; 32]);
impl LinkSecret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkSecret([redacted])")
    }
}
impl Drop for LinkSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
