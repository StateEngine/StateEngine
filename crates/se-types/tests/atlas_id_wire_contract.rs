//! Atlas byte-array IDs keep the byte-array native wire form, so host IPC,
//! cursor digests and persisted rows stay byte-for-byte compatible with the
//! base. Only the JSON presented through the MCP server and the CLI takes
//! the compact hex form, and the decoder also accepts the hex string so an
//! ID from a presented reply round-trips into a request.
use se_types::code::{AtlasJobId, ContentHash, FileId, ResumeOfferId, SymbolId};
use serde_json::{Value, json};
use std::error::Error;

type Check = Result<(), Box<dyn Error>>;

fn byte_array(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().map(|b| Value::from(*b)).collect())
}

/// Protects: C1 - every ID serializes as the bare byte array exactly as on
/// the base, so host IPC, cursor digests and cache rows stay byte-identical.
#[test]
fn ids_serialize_as_bare_byte_arrays() -> Check {
    assert_eq!(
        serde_json::to_value(AtlasJobId([0x01; 16]))?,
        byte_array(&[0x01; 16])
    );
    assert_eq!(
        serde_json::to_value(FileId([0xab; 16]))?,
        byte_array(&[0xab; 16])
    );
    assert_eq!(
        serde_json::to_value(SymbolId([0xcd; 32]))?,
        byte_array(&[0xcd; 32])
    );
    assert_eq!(
        serde_json::to_value(ContentHash([0xef; 32]))?,
        byte_array(&[0xef; 32])
    );
    assert_eq!(
        serde_json::to_value(ResumeOfferId([0x7f; 16]))?,
        byte_array(&[0x7f; 16])
    );
    Ok(())
}

/// Protects: C1 - byte arrays and hex strings decode to the same ID, so
/// persisted rows and presented replies both round-trip.
#[test]
fn arrays_and_hex_strings_deserialize_to_the_same_id() -> Check {
    assert_eq!(
        serde_json::from_value::<FileId>(byte_array(&[0xab; 16]))?,
        FileId([0xab; 16])
    );
    assert_eq!(
        serde_json::from_value::<FileId>(json!("ab".repeat(16)))?,
        FileId([0xab; 16])
    );
    assert_eq!(
        serde_json::from_value::<ContentHash>(json!("AB".repeat(32)))?,
        ContentHash([0xab; 32])
    );
    Ok(())
}

/// Protects: C1 - wrong lengths, non-hex text and non-byte numbers refuse.
#[test]
fn malformed_id_values_refuse() -> Check {
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

/// Protects: C1 - the published schemas advertise both supported input
/// forms: the compact hex string the presentation layer produces and the
/// native byte array.
#[test]
fn id_schemas_advertise_both_supported_input_forms() -> Check {
    for (schema, pattern, len) in [
        (
            serde_json::to_value(schemars::schema_for!(FileId))?,
            "^[0-9a-f]{32}$",
            16,
        ),
        (
            serde_json::to_value(schemars::schema_for!(SymbolId))?,
            "^[0-9a-f]{64}$",
            32,
        ),
    ] {
        assert_eq!(schema["anyOf"][0]["type"], "string");
        assert_eq!(schema["anyOf"][0]["pattern"], pattern);
        assert_eq!(schema["anyOf"][1]["type"], "array");
        assert_eq!(schema["anyOf"][1]["items"]["type"], "integer");
        assert_eq!(schema["anyOf"][1]["items"]["minimum"], 0);
        assert_eq!(schema["anyOf"][1]["items"]["maximum"], 255);
        assert_eq!(schema["anyOf"][1]["minItems"], len);
        assert_eq!(schema["anyOf"][1]["maxItems"], len);
    }
    Ok(())
}

/// Protects: C1 - a selector carrying IDs serializes to the same bytes as
/// the hand-written base JSON with bare arrays; because cursor digests hash
/// exactly those bytes, old page links and the text-search ordering suffix
/// digest identically on the base.
#[test]
fn selector_serialization_stays_byte_identical_with_the_base() -> Check {
    let selector = json!({
        "kind": "file",
        "file": serde_json::to_value(FileId([0x5a; 16]))?,
        "symbol": serde_json::to_value(SymbolId([0x3c; 32]))?
    });
    let base = json!({
        "kind": "file",
        "file": vec![0x5au8; 16],
        "symbol": vec![0x3cu8; 32]
    });
    assert_eq!(serde_json::to_vec(&selector)?, serde_json::to_vec(&base)?);
    Ok(())
}
