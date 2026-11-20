//! Bounded, duplicate-free JSON decoding shared by native and MCP transports.
use se_types::{Result, SeError};
use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_JSON_DEPTH: u8 = 64;
fn invalid(expected: &str) -> SeError {
    SeError::invalid("IPC frame", expected)
}

/// Validate duplicate fields/depth before typed decoding, including arguments.
/// The first pass retains keys only, without copying credentials/bodies into a
/// generic Value tree or normalizing numbers before the core DTO sees them.
pub fn decode_json<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit || limit > MAX_FRAME_BYTES {
        return Err(invalid("nonempty JSON within the negotiated byte budget"));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    JsonSeed { depth: 0 }
        .deserialize(&mut decoder)
        .map_err(|_| invalid("UTF-8 JSON, unique fields and depth at most 64"))?;
    decoder
        .end()
        .map_err(|_| invalid("one complete JSON value"))?;
    let mut ignored = false;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let decoded = serde_ignored::deserialize(&mut decoder, |_| ignored = true)
        .map_err(|_| invalid("the closed versioned IPC envelope"))?;
    if ignored {
        return Err(invalid("only declared IPC fields"));
    }
    Ok(decoded)
}

struct JsonSeed {
    depth: u8,
}
impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> std::result::Result<(), D::Error> {
        decoder.deserialize_any(JsonVisitor { depth: self.depth })
    }
}
struct JsonVisitor {
    depth: u8,
}
impl JsonVisitor {
    fn child<E: de::Error>(&self) -> std::result::Result<JsonSeed, E> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(E::custom("IPC JSON depth exceeded"));
        }
        Ok(JsonSeed {
            depth: self.depth + 1,
        })
    }
}
impl<'de> Visitor<'de> for JsonVisitor {
    type Value = ();
    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_string<E: de::Error>(self, _: String) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<(), A::Error> {
        self.child::<A::Error>()?;
        while sequence.next_element_seed(self.child()?)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> std::result::Result<(), A::Error> {
        self.child::<A::Error>()?;
        let mut keys = BTreeSet::new();
        while let Some(key) = fields.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate IPC JSON field"));
            }
            fields.next_value_seed(self.child()?)?;
        }
        Ok(())
    }
}
