//! Closed, allocation-bounded opaque identifiers at the native/process boundary.
use serde::{Deserialize, Serialize};

macro_rules! identifier {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                Self::try_from(value.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                let tail = value.strip_prefix($prefix).ok_or("identifier prefix")?;
                if tail.len() != 32
                    || !tail
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("identifier requires 32 lowercase hexadecimal digits");
                }
                Ok(Self(value))
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
identifier!(ChannelId, "chn-");
identifier!(CredentialId, "ccr-");
identifier!(ReceiptId, "chr-");
identifier!(OutputId, "cho-");

identifier!(ActionId, "cha-");
