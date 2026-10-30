use crate::{Result, SeError, Sha256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Hasher};
use std::fmt;
use zeroize::Zeroize;

/// Protected transport material. No Display, Clone, Serialize or Deserialize.
pub struct Secret(Vec<u8>);
impl Secret {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let mut secret = Self(bytes);
        if secret.0.is_empty() || secret.0.len() > 65536 {
            secret.0.zeroize();
            return Err(SeError::invalid("secret", "1..65536 protected bytes"));
        }
        Ok(secret)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Body {
    text: String,
    digest: Sha256,
}
impl Body {
    pub const MAX_BYTES: usize = 1048576;
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        if text.len() > Self::MAX_BYTES {
            return Err(SeError::too_large("body", Self::MAX_BYTES, text.len()));
        }
        let digest = Sha256::from_bytes(Hasher::digest(text.as_bytes()).into());
        Ok(Self { text, digest })
    }
    pub fn as_str(&self) -> &str {
        &self.text
    }
    pub fn len(&self) -> usize {
        self.text.len()
    }
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
    pub const fn digest(&self) -> Sha256 {
        self.digest
    }
}
impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Body {{ bytes: {}, sha256: {}… }}",
            self.len(),
            &self.digest.hex()[..12]
        )
    }
}
impl TryFrom<String> for Body {
    type Error = SeError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}
impl From<Body> for String {
    fn from(value: Body) -> String {
        value.text
    }
}
