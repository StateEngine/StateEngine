//! The storage boundary consumes materialized bytes, not queued handles.
#[test]
fn borrowed_materialized_text_preserves_bytes_and_enforces_byte_limits()
-> Result<(), Box<dyn std::error::Error>> {
    // These calls also enforce the boundary's input type. The previous queued
    // InputText signature cannot compile them; no synthetic staged handle is
    // manufactured or sent around the materialization step.
    let value = "a\0🦀";
    assert_eq!(super::text(value, 6)?, value);
    assert_eq!(super::text("", 0)?, "");
    let error = super::text(value, 5)
        .err()
        .ok_or("UTF-8 bytes were counted as characters at the storage boundary")?;
    assert_eq!(error.code, crate::StoreErrorCode::BodyTooLarge);
    Ok(())
}
