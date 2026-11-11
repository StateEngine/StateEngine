//! Provider coordinates are bounded opaque values, never ordered by the core.
use serde::{Deserialize, Deserializer, Serialize, de};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct Opaque<const MAX: usize>(String);
pub type ExternalId = Opaque<256>;
pub type ReceiveCursor = Opaque<4096>;

impl<const MAX: usize> Opaque<MAX> {
    pub fn new(value: String) -> Result<Self, &'static str> {
        if value.is_empty() || value.len() > MAX || value.chars().any(char::is_control) {
            return Err("provider coordinate is empty, oversized or contains control characters");
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<const MAX: usize> fmt::Display for Opaque<MAX> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl From<i64> for ExternalId {
    fn from(value: i64) -> Self {
        Self(value.to_string())
    }
}
impl<'de, const MAX: usize> Deserialize<'de> for Opaque<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Coordinate {
            Text(String),
            LegacySigned(i64),
            LegacyUnsigned(u64),
        }
        let value = match Coordinate::deserialize(deserializer)? {
            Coordinate::Text(value) => value,
            Coordinate::LegacySigned(value) => value.to_string(),
            Coordinate::LegacyUnsigned(value) => value.to_string(),
        };
        Self::new(value).map_err(de::Error::custom)
    }
}
impl<const MAX: usize> rusqlite::ToSql for Opaque<MAX> {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.0.as_str().into())
    }
}
impl<const MAX: usize> rusqlite::types::FromSql for Opaque<MAX> {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let value = match value {
            rusqlite::types::ValueRef::Integer(value) => value.to_string(),
            value => value.as_str()?.to_owned(),
        };
        Self::new(value).map_err(|reason| {
            rusqlite::types::FromSqlError::Other(std::io::Error::other(reason).into())
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connector {
    #[default]
    Telegram,
    Discord,
}
impl Connector {
    pub fn is_telegram(&self) -> bool {
        *self == Self::Telegram
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Telegram => "telegram",
            Self::Discord => "discord",
        }
    }
}

impl<const MAX: usize> crate::sql_value::Param for Opaque<MAX> {
    fn sql_value(&self) -> crate::StoreResult<rusqlite::types::Value> {
        Ok(rusqlite::types::Value::Text(self.0.clone()))
    }
}
