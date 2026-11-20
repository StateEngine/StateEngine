//! Presentation-only compacting of the Atlas byte-array IDs to hex strings.
//!
//! Native IPC, cursors and persisted rows keep the byte-array wire form;
//! only the JSON presented through the MCP server and the CLI takes the
//! compact form, so a reply stays byte-for-byte compatible with the host.

use se_core::ops::AnyOutput;
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Sorted field names that carry one of this crate's byte-array IDs.
const ID_FIELDS: &[&str] = &[
    "content_hash",
    "enclosing",
    "file",
    "from",
    "id",
    "job",
    "observed_hash",
    "offer",
    "parent",
    "previous_hash",
    "resolved_target",
    "symbol",
    "to",
];

/// Replaces every mapped byte-array ID with its lowercase hex string.
///
/// The walk is idempotent: a value already in the hex form passes through
/// unchanged, and byte arrays of any other length stay put.
pub fn compact_ids(value: &mut Value) {
    match value {
        Value::Object(members) => {
            for (name, field) in members.iter_mut() {
                if ID_FIELDS.binary_search(&name.as_str()).is_ok()
                    && let Value::Array(bytes) = field
                {
                    let bytes = bytes.clone();
                    if let Some(hex) = hex_if_id_bytes(&bytes) {
                        *field = Value::String(hex);
                        continue;
                    }
                }
                compact_ids(field);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                compact_ids(item);
            }
        }
        Value::Null | Value::String(_) | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn hex_if_id_bytes(bytes: &[Value]) -> Option<String> {
    let len = bytes.len();
    if len != 16 && len != 32 {
        return None;
    }
    let mut raw = [0u8; 32];
    for (slot, byte) in raw.iter_mut().take(len).zip(bytes) {
        *slot = byte.as_u64().and_then(|value| u8::try_from(value).ok())?;
    }
    Some(se_types::hex_lower(&raw[..len]))
}

/// One presented output: either verbatim, or with its Atlas byte-array IDs
/// compacted to hex. Only the presentation changes; the wire form behind it
/// is untouched.
pub enum Presented<'a> {
    Direct(&'a AnyOutput),
    Compacted(&'a AnyOutput),
}
/// Chooses the presentation for an output. The Atlas read families and the
/// resume reply carry byte-array IDs, so their presented JSON takes the
/// compact form; every other family is presented verbatim.
pub fn presented(value: &AnyOutput) -> Presented<'_> {
    if matches!(
        value,
        AnyOutput::AtlasFind(_)
            | AnyOutput::AtlasRefs(_)
            | AnyOutput::AtlasImpact(_)
            | AnyOutput::AtlasChanges(_)
            | AnyOutput::AtlasOutline(_)
            | AnyOutput::Resume(_)
    ) {
        Presented::Compacted(value)
    } else {
        Presented::Direct(value)
    }
}
impl Serialize for Presented<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Direct(value) => value.serialize(serializer),
            Self::Compacted(value) => {
                let mut presented =
                    serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
                compact_ids(&mut presented);
                presented.serialize(serializer)
            }
        }
    }
}
