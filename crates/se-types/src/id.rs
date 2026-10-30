use crate::{Result, SeError};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt, num::NonZeroU64, str::FromStr};
use uuid::{Builder, Uuid, Variant, Version};

macro_rules! ids {
    ($($name:ident => $prefix:literal),+ $(,)?) => {
        #[derive(Clone,Copy,Debug,Eq,PartialEq,Hash)]
        pub enum IdKind { $($name,)+ }
        $ (
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
                if value.starts_with("selp-") { return Err(SeError::invalid(stringify!($name),"a public ID, never a bearer credential")); }
                if known_id_prefix(&value).is_some() { return value.parse(); }
                if !legacy_matches(IdKind::$name,&value) {
                    return Err(SeError::invalid(stringify!($name),"this kind's documented legacy grammar"));
                }
                Ok(Self(value))
            }
            /// Only a contextual, source/project-scoped registry may accept a
            /// historical custom spelling. No ambient registry is used by serde.
            pub fn from_registered_legacy(value:impl Into<String>,registry:&dyn LegacyIdRegistry)->Result<Self> {
                let value=value.into();
                validate_opaque(&value,512,stringify!($name))?;
                if value.starts_with("selp-") { return Err(SeError::invalid(stringify!($name),"a public ID, never a bearer credential")); }
                if known_id_prefix(&value).is_some() { return value.parse(); }
                if !registry.contains(IdKind::$name,&value)? {
                    return Err(SeError::invalid(stringify!($name),"an exact kind/project/source registration"));
                }
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
            // Only the own-kind historical producer grammar supplements strict UUIDv7.
            Self::from_legacy(value)
        } }
        impl From<$name> for String { fn from(value:$name)->String {value.0} }
        impl fmt::Display for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(&self.0)}}
        impl fmt::Debug for $name {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(&self.0)}}
        impl JsonSchema for $name {
            fn schema_name()->Cow<'static,str>{stringify!($name).into()}
            fn json_schema(_: &mut SchemaGenerator)->Schema {json_schema!({"type":"string","minLength":1,"maxLength":512,"anyOf":[{"pattern":format!("^{}[0-9a-f]{{8}}-[0-9a-f]{{4}}-7[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$",Self::PREFIX)},{"pattern":legacy_pattern(IdKind::$name)}]})}
        }
    )+
        fn known_id_prefix(value:&str)->Option<&'static str>{["cred_",$($prefix),+].into_iter().find(|prefix|value.starts_with(prefix))}
    };
}
ids!(ProjectId=>"prj_",AgentId=>"ag_",HumanId=>"hu_",SessionId=>"ses_",MessageId=>"msg_",DecisionId=>"dec_",EventId=>"ev_",LaunchId=>"lch_",ObservationId=>"obs_",StoreId=>"store_",LifecycleId=>"life_",AtlasRootId=>"aroot_",IndexEpochId=>"aidx_");

/// An already-authorized registry snapshot scoped to the import project/source.
/// Implemented by the store/import boundary, never a global or a name heuristic.
/// The result permits representing history, not launching or authenticating it.
pub trait LegacyIdRegistry {
    fn contains(&self, kind: IdKind, text: &str) -> Result<bool>;
}
fn hex(value: &str, count: Option<usize>) -> bool {
    count.is_none_or(|count| value.len() == count)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn serial(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    let groups: Vec<_> = suffix.split('-').collect();
    groups.len() == 3
        && groups.iter().all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|b| b"0123456789abcdefghjkmnpqrstvwxyz".contains(&b))
        })
}
fn uuid_v4(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| {
        id.get_version() == Some(Version::Random)
            && id.get_variant() == Variant::RFC4122
            && id.to_string() == value
    })
}
fn known_legacy_kind(value: &str) -> Option<IdKind> {
    [
        ("agt-", IdKind::AgentId),
        ("hum-", IdKind::HumanId),
        ("msg-", IdKind::MessageId),
        ("evt-", IdKind::EventId),
        ("se-", IdKind::SessionId),
        ("semantic-observation:", IdKind::ObservationId),
        ("observation-", IdKind::ObservationId),
        ("health-terminal-lineage-", IdKind::ObservationId),
    ]
    .into_iter()
    .find_map(|(prefix, kind)| value.starts_with(prefix).then_some(kind))
}
fn legacy_project(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || known_id_prefix(value).is_some()
        || known_legacy_kind(value).is_some()
        || (value.len() == 36 && Uuid::parse_str(value).is_ok())
    {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || value.ends_with('.')
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
    {
        return false;
    }
    let stem = value.split('.').next().unwrap_or("").to_ascii_lowercase();
    !matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        && !((stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.len() == 4
            && (b'1'..=b'9').contains(&stem.as_bytes()[3]))
}
fn legacy_matches(kind: IdKind, value: &str) -> bool {
    match kind {
        IdKind::ProjectId => legacy_project(value),
        IdKind::AgentId => serial(value, "agt-"),
        IdKind::HumanId => serial(value, "hum-"),
        IdKind::SessionId => {
            value
                .strip_prefix("se-session-sha256-")
                .is_some_and(|s| hex(s, Some(64)))
                || value.strip_prefix("se-").is_some_and(uuid_v4)
                || uuid_v4(value)
        }
        IdKind::MessageId => value
            .strip_prefix("msg-")
            .is_some_and(|s| s.len() >= 8 && hex(s, None)),
        IdKind::EventId => value.strip_prefix("evt-").is_some_and(|s| hex(s, Some(64))),
        IdKind::DecisionId | IdKind::LaunchId | IdKind::LifecycleId => uuid_v4(value),
        IdKind::ObservationId => value
            .strip_prefix("semantic-observation:")
            .is_some_and(|s| hex(s, Some(64))),
        IdKind::StoreId | IdKind::AtlasRootId | IdKind::IndexEpochId => false,
    }
}
fn legacy_pattern(kind: IdKind) -> &'static str {
    match kind {
        IdKind::ProjectId => {
            r"^(?!(?:prj_|ag_|hu_|ses_|msg_|dec_|ev_|lch_|obs_|store_|life_|aroot_|aidx_|agt-|hum-|msg-|evt-|se-|semantic-observation:|observation-|health-terminal-lineage-|selp-|cred_))(?!(?:[cC][oO][nN]|[pP][rR][nN]|[aA][uU][xX]|[nN][uU][lL]|[cC][oO][mM][1-9]|[lL][pP][tT][1-9])(?:\..*)?$)(?![0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9_-])?$"
        }
        IdKind::AgentId => {
            r"^agt-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}$"
        }
        IdKind::HumanId => {
            r"^hum-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}-[0-9a-hjkmnp-tv-z]{4}$"
        }
        IdKind::SessionId => {
            r"^(?:se-session-sha256-[0-9a-f]{64}|(?:se-)?[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
        }
        IdKind::MessageId => r"^msg-[0-9a-f]{8,}$",
        IdKind::EventId => r"^evt-[0-9a-f]{64}$",
        IdKind::DecisionId | IdKind::LaunchId | IdKind::LifecycleId => {
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        }
        IdKind::ObservationId => r"^semantic-observation:[0-9a-f]{64}$",
        IdKind::StoreId | IdKind::AtlasRootId | IdKind::IndexEpochId => r"^$",
    }
}

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

/// UTC calendar text for human messages; serde remains exact Unix microseconds.
impl fmt::Display for UnixMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.get() / 1_000_000;
        let days = (seconds / 86_400) as i64;
        // Gregorian 400-year eras, with March as month zero to handle leap days.
        let z = days + 719_468;
        let era = z / 146_097;
        let day_of_era = z - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let march_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * march_month + 2) / 5 + 1;
        let month = march_month + if march_month < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        let hour = seconds % 86_400 / 3_600;
        let minute = seconds % 3_600 / 60;
        let second = seconds % 60;
        write!(
            f,
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{:06} UTC",
            self.get() % 1_000_000
        )
    }
}
