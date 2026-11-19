//! Atlas byte-array IDs used to serialize as JSON number arrays, so the
//! outline reply spent most of its byte budget on IDs and returned only a
//! few symbols. Their wire form is now a lowercase hex string, and persisted
//! caches written before the change keep decoding.
use se_types::code::{AtlasJobId, ContentHash, FileId, ResumeOfferId, SymbolId};
use serde_json::{Value, json};
use std::error::Error;

type Check = Result<(), Box<dyn Error>>;

/// Protects: C1 — every wire ID serializes as a lowercase hex string and
/// round-trips through exactly that spelling.
#[test]
fn atlas_ids_serialize_as_lowercase_hex_strings() -> Check {
    for (value, expected) in [
        (
            serde_json::to_value(&AtlasJobId([0x01; 16]))?,
            "01".repeat(16),
        ),
        (serde_json::to_value(&FileId([0xab; 16]))?, "ab".repeat(16)),
        (
            serde_json::to_value(&SymbolId([0xcd; 32]))?,
            "cd".repeat(32),
        ),
        (
            serde_json::to_value(&ContentHash([0xef; 32]))?,
            "ef".repeat(32),
        ),
        (
            serde_json::to_value(&ResumeOfferId([0x7f; 16]))?,
            "7f".repeat(16),
        ),
    ] {
        assert_eq!(value, expected);
    }
    let decoded: FileId = serde_json::from_value(json!("ab".repeat(16)))?;
    assert_eq!(decoded, FileId([0xab; 16]));
    Ok(())
}

/// Protects: C1 — legacy byte arrays from persisted caches still decode, and
/// either hex letter case names the same bytes.
#[test]
fn legacy_byte_arrays_still_deserialize() -> Check {
    let bytes: [u8; 16] = std::array::from_fn(|index| index as u8);
    let legacy = Value::Array(bytes.iter().map(|byte| json!(*byte)).collect());
    assert_eq!(
        serde_json::from_value::<FileId>(legacy.clone())?,
        FileId(bytes)
    );
    let hash_bytes: [u8; 32] = std::array::from_fn(|index| index as u8);
    let legacy_hash = Value::Array(hash_bytes.iter().map(|byte| json!(*byte)).collect());
    assert_eq!(
        serde_json::from_value::<ContentHash>(legacy_hash)?,
        ContentHash(hash_bytes)
    );
    assert_eq!(
        serde_json::from_value::<ContentHash>(json!("AB".repeat(32)))?,
        ContentHash([0xab; 32])
    );
    Ok(())
}

/// Protects: C1 — wrong lengths, non-hex text and non-byte numbers refuse.
#[test]
fn malformed_id_wire_values_refuse() -> Check {
    assert!(serde_json::from_value::<FileId>(json!("ab".repeat(15))).is_err());
    assert!(serde_json::from_value::<FileId>(json!("ab".repeat(17))).is_err());
    assert!(serde_json::from_value::<FileId>(json!("")).is_err());
    assert!(serde_json::from_value::<FileId>(json!("zz".repeat(16))).is_err());
    assert!(serde_json::from_value::<FileId>(json!(1.5)).is_err());
    assert!(serde_json::from_value::<SymbolId>(json!("ab".repeat(16))).is_err());
    let short = Value::Array((0u8..15).map(|byte| json!(byte)).collect());
    assert!(serde_json::from_value::<FileId>(short).is_err());
    let long = Value::Array((0u8..17).map(|byte| json!(byte)).collect());
    assert!(serde_json::from_value::<FileId>(long).is_err());
    Ok(())
}

/// Protects: C1 — the published schemas document the hex wire form.
#[test]
fn id_schemas_document_the_hex_wire_form() -> Check {
    for (schema, pattern) in [
        (
            serde_json::to_value(schemars::schema_for!(FileId))?,
            "^[0-9a-f]{32}$",
        ),
        (
            serde_json::to_value(schemars::schema_for!(SymbolId))?,
            "^[0-9a-f]{64}$",
        ),
    ] {
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["pattern"], pattern);
    }
    Ok(())
}
