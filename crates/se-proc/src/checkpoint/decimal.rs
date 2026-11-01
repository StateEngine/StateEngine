//! Native integers that must survive JSON readers without floating-point loss.
use serde::{Deserialize, Deserializer, Serializer};
fn canonical(value: &str) -> bool {
    value == "0"
        || (value
            .as_bytes()
            .first()
            .is_some_and(|b| (b'1'..=b'9').contains(b))
            && value.bytes().all(|b| b.is_ascii_digit()))
}
macro_rules! decimal {
    ($name:ident, $integer:ty, $limit:expr) => {
        pub(crate) mod $name {
            use super::*;
            pub fn serialize<S: Serializer>(
                value: &$integer,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&value.to_string())
            }
            pub fn deserialize<'de, D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$integer, D::Error> {
                let value = String::deserialize(deserializer)?;
                if value.len() > $limit || !canonical(&value) {
                    return Err(serde::de::Error::custom(
                        "canonical unsigned decimal string required",
                    ));
                }
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}
decimal!(u64, u64, 20);
decimal!(u128, u128, 39);
