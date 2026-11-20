//! Atlas byte-array IDs keep the byte-array native wire form, so host IPC,
//! cursor digests and persisted rows stay byte-for-byte compatible with the
//! base. Only the JSON presented through the MCP server and the CLI takes
//! the compact hex form, and the decoder also accepts the hex string so an
//! ID from a presented reply round-trips into a request.
use se_types::code::{AtlasJobId, ContentHash, FileId, ResumeOfferId, SymbolId, compact_ids};
use serde_json::{Value, json};
use std::error::Error;

type Check = Result<(), Box<dyn Error>>;

fn byte_array(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().map(Value::from).collect())
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

/// Protects: C1 - the published schemas document the compact hex form the
/// presentation layer produces.
#[test]
fn id_schemas_document_the_hex_form() -> Check {
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

/// Protects: C1 - the compacting walk rewrites only mapped ID fields,
/// recurses into containers, leaves everything else untouched and is
/// idempotent on the compact form.
#[test]
fn compact_ids_rewrites_mapped_id_fields_only() -> Check {
    let mut presented = json!({
        "schema": "atlas.find",
        "file": byte_array(&[0xab; 16]),
        "symbol": byte_array(&[0xcd; 32]),
        "from": byte_array(&[0x01; 16]),
        "to": byte_array(&[0x02; 32]),
        "offer": byte_array(&[0x7f; 16]),
        "job": byte_array(&[0x55; 16]),
        "content_hash": byte_array(&[0xef; 32]),
        "observed_hash": Value::Null,
        "parent": Value::Null,
        "enclosing": Value::Null,
        "resolved_target": Value::Null,
        "id": byte_array(&[0x11; 32]),
        "previous_hash": byte_array(&[0x22; 32]),
        "hops": [
            { "from": byte_array(&[0x33; 32]), "to": byte_array(&[0x44; 32]) }
        ],
        "unmapped": byte_array(&[0xab; 16]),
        "count": 16
    });
    compact_ids(&mut presented);
    assert_eq!(presented["file"], "ab".repeat(16));
    assert_eq!(presented["symbol"], "cd".repeat(32));
    assert_eq!(presented["from"], "01".repeat(16));
    assert_eq!(presented["to"], "02".repeat(32));
    assert_eq!(presented["offer"], "7f".repeat(16));
    assert_eq!(presented["job"], "55".repeat(16));
    assert_eq!(presented["content_hash"], "ef".repeat(32));
    assert_eq!(presented["id"], "11".repeat(32));
    assert_eq!(presented["previous_hash"], "22".repeat(32));
    assert_eq!(presented["hops"][0]["from"], "33".repeat(32));
    assert_eq!(presented["hops"][0]["to"], "44".repeat(32));
    assert_eq!(presented["unmapped"], byte_array(&[0xab; 16]));
    assert_eq!(presented["count"], 16);
    let compact = presented.clone();
    compact_ids(&mut presented);
    assert_eq!(presented, compact);
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
