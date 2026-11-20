//! The presentation-only compacting of Atlas byte-array IDs to hex strings
//! rewrites only mapped ID fields, recurses into containers, leaves
//! everything else untouched and is idempotent on the compact form.
use se_mcp::presentation::compact_ids;
use serde_json::{Value, json};
use std::error::Error;

type Check = Result<(), Box<dyn Error>>;

fn byte_array(bytes: &[u8]) -> Value {
    Value::Array(bytes.iter().map(|b| Value::from(*b)).collect())
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
