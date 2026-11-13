use crate::{error::*, *};
use uuid::{Builder, Uuid, Variant, Version};
impl RecordIdentity for RecordId {
    fn from_parts(time: u64, random: [u8; 10]) -> StoreResult<Self> {
        if time > 0xffff_ffff_ffff {
            return Err(invalid("record timestamp exceeds UUIDv7 range"));
        }
        Self::from_bytes(
            *Builder::from_unix_timestamp_millis(time, &random)
                .into_uuid()
                .as_bytes(),
        )
    }
    fn from_bytes(bytes: [u8; 16]) -> StoreResult<Self> {
        let id = Uuid::from_bytes(bytes);
        if id.get_version() != Some(Version::SortRand) || id.get_variant() != Variant::RFC4122 {
            return Err(invalid("record identity requires RFC UUIDv7"));
        }
        Ok(Self::new_internal(bytes))
    }
    fn as_bytes(&self) -> &[u8; 16] {
        self.bytes_internal()
    }
}
impl Actor {
    #[doc(hidden)]
    pub fn wire(&self) -> &str {
        match self {
            Self::Human(x) => x.as_str(),
            Self::Agent(x) => x.as_str(),
            Self::Remote(x) => x.as_str(),
        }
    }
    #[doc(hidden)]
    pub fn kind(&self) -> &str {
        match self {
            Self::Human(_) => "human",
            Self::Agent(_) => "agent",
            Self::Remote(_) => "remote",
        }
    }
}
