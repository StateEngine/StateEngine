use crate::{Result, SeError};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt, num::NonZeroU64, str::FromStr};
use uuid::{Builder, Uuid, Variant, Version};

macro_rules! ids {
    ($($name:ident => $prefix:literal),+ $(,)?) => {$ (
        #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub const PREFIX: &'static str = $prefix;
            /// No clock or RNG: uniqueness of the supplied inputs is caller-owned.
            pub fn from_parts(unix_millis: u64, random: [u8; 10]) -> Result<Self> {
                if unix_millis > 0xffff_ffff_ffff { return Err(SeError::invalid("unix_millis", "a 48-bit UUIDv7 timestamp")); }
                let id=Builder::from_unix_timestamp_millis(unix_millis,&random).into_uuid();
                Ok(Self(format!("{}{}", Self::PREFIX,id)))
            }
            pub fn from_bytes(bytes: [u8;16]) -> Result<Self> {
                let id=Uuid::from_bytes(bytes);
                if id.get_version()!=Some(Version::SortRand) || id.get_variant()!=Variant::RFC4122 {
                    return Err(SeError::invalid(stringify!($name), "UUIDv7 bytes with RFC variant"));
                }
                Ok(Self(format!("{}{}", Self::PREFIX,id)))
            }
            pub fn as_str(&self) -> &str { &self.0 }
            /// Explicit importer entrypoint: legacy text is data, never authority.
            /// A UUID-shaped suffix must be canonical new-format, not a legacy bypass.
            pub fn from_legacy(value: impl Into<String>) -> Result<Self> {
                let value=value.into();
                validate_opaque(&value,512,stringify!($name))?;
                if known_id_prefix(&value).is_some_and(|prefix|prefix!=Self::PREFIX){return Err(SeError::invalid(stringify!($name),Self::PREFIX));}
                if let Some(suffix)=value.strip_prefix(Self::PREFIX) {
                    if suffix.is_empty() { return Err(SeError::invalid(stringify!($name),"a nonempty legacy suffix")); }
                    if suffix.len()==36 && Uuid::parse_str(suffix).is_ok() { return value.parse(); }
                }
                // Imported legacy identifiers predate the new prefix grammar;
                // their existence/kind must be resolved in the authorized registry.
                Ok(Self(value))
            }
        }
        impl FromStr for $name {
            type Err=SeError;
            fn from_str(value:&str)->Result<Self> {
                let suffix=value.strip_prefix(Self::PREFIX).ok_or_else(||SeError::invalid(stringify!($name),Self::PREFIX))?;
                let uuid=Uuid::parse_str(suffix).map_err(|_|SeError::invalid(stringify!($name),"kind prefix plus canonical UUIDv7"))?;
                if uuid.get_version()!=Some(Version::SortRand) || uuid.get_variant()!=Variant::RFC4122 || uuid.to_string()!=suffix {
                    return Err(SeError::invalid(stringify!($name),"kind prefix plus lowercase canonical UUIDv7"));
                }
                Ok(Self(value.into()))
            }
        }
        impl TryFrom<String> for $name { type Error=SeError; fn try_from(value:String)->Result<Self> {
            // Wire readers preserve explicitly kind-prefixed imported IDs as data.
            Self::from_legacy(value)
        } }
        impl From<$name> for String { fn from(value:$name)->String {value.0} }
        impl fmt::Display for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(&self.0)}}
        impl fmt::Debug for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(&self.0)}}
        impl JsonSchema for $name {
            fn schema_name()->Cow<'static,str>{stringify!($name).into()}
            fn json_schema(_: &mut SchemaGenerator)->Schema {json_schema!({"type":"string","minLength":1,"maxLength":512,"pattern":"^[!-~]+$"})}
        }
    )+
        fn known_id_prefix(value:&str)->Option<&'static str>{[$($prefix),+].into_iter().find(|prefix|value.starts_with(prefix))}
    };
}
ids!(ProjectId=>"prj_",AgentId=>"ag_",HumanId=>"hu_",SessionId=>"ses_",MessageId=>"msg_",DecisionId=>"dec_",EventId=>"ev_",LaunchId=>"launch_",ObservationId=>"obs_",StoreId=>"store_",LifecycleId=>"life_",AtlasRootId=>"aroot_",IndexEpochId=>"aidx_");

pub(crate) fn validate_opaque(value: &str, max: usize, field: &str) -> Result<()> {
    if value.len() > max {
        return Err(SeError::too_large(field, max, value.len()));
    }
    if value.is_empty() || value.len() > max || value.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err(SeError::invalid(
            field,
            "bounded nonempty ASCII without whitespace or controls",
        ));
    }
    Ok(())
}
macro_rules! opaque {
    ($($name:ident => $max:literal),+ $(,)?) => {$ (
        #[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash,Serialize,Deserialize,JsonSchema)]
        #[serde(try_from="String",into="String")]
        #[schemars(with="String")]
        pub struct $name(String);
        impl $name {
            pub fn new(value:impl Into<String>)->Result<Self>{let value=value.into();validate_opaque(&value,$max,stringify!($name))?;Ok(Self(value))}
            pub fn as_str(&self)->&str{&self.0}
        }
        impl FromStr for $name {type Err=SeError;fn from_str(value:&str)->Result<Self>{Self::new(value)}}
        impl TryFrom<String> for $name {type Error=SeError;fn try_from(value:String)->Result<Self>{Self::new(value)}}
        impl From<$name> for String {fn from(value:$name)->String{value.0}}
        impl fmt::Display for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str(&self.0)}}
    )+};
}
opaque!(Cursor=>4096,MachineId=>256,BootId=>256,HostSessionId=>512,HostEventId=>512,HostPendingId=>512,ProviderSessionId=>512,IdempotencyKey=>128,NoticeId=>256);

macro_rules! counter {
    ($name:ident,$zero:expr) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            Serialize,
            Deserialize,
            JsonSchema,
        )]
        #[serde(try_from = "u64", into = "u64")]
        #[schemars(with = "u64")]
        pub struct $name(u64);
        impl $name {
            pub fn new(value: u64) -> Result<Self> {
                if value > i64::MAX as u64 || (!$zero && value == 0) {
                    return Err(SeError::invalid(
                        stringify!($name),
                        "a supported nonnegative/nonzero signed-store integer",
                    ));
                }
                Ok(Self(value))
            }
            pub const fn get(self) -> u64 {
                self.0
            }
        }
        impl TryFrom<u64> for $name {
            type Error = SeError;
            fn try_from(value: u64) -> Result<Self> {
                Self::new(value)
            }
        }
        impl From<$name> for u64 {
            fn from(value: $name) -> u64 {
                value.0
            }
        }
    };
}
counter!(Sequence, true);
counter!(UnixMillis, true);
counter!(UnixMicros, true);
impl Sequence {
    pub const ZERO: Self = Self(0);
}
macro_rules! generation {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            Serialize,
            Deserialize,
            JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);
        impl $name {
            pub fn new(value: u64) -> Result<Self> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or_else(|| SeError::invalid(stringify!($name), "a nonzero generation"))
            }
            pub const fn get(self) -> u64 {
                self.0.get()
            }
            pub fn successor(self) -> Result<Self> {
                self.get()
                    .checked_add(1)
                    .ok_or_else(|| SeError::invalid(stringify!($name), "an unexhausted generation"))
                    .and_then(Self::new)
            }
        }
    };
}
generation!(Generation);
generation!(HostGeneration);
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Sha256([u8; 32]);
impl Sha256 {
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }
    pub fn parse_hex(value: &str) -> Result<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SeError::invalid(
                "sha256",
                "64 lowercase hexadecimal digits",
            ));
        }
        let mut bytes = [0; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            };
            bytes[index] = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        Ok(Self(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}
impl TryFrom<String> for Sha256 {
    type Error = SeError;
    fn try_from(value: String) -> Result<Self> {
        Self::parse_hex(&value)
    }
}
impl From<Sha256> for String {
    fn from(value: Sha256) -> String {
        value.hex()
    }
}
impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}
