#![cfg(feature = "listener")]

use se_host::client::wire;

#[test]
fn exact_json_byte_limits_include_escaping_and_exclude_frame_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let text = "é\n\"".repeat(512);
    let expected = serde_json::to_vec(&text)?;
    assert!(wire::encode_json(&text, 0).is_err());
    assert!(wire::encode_json(&text, wire::MAX_FRAME_BYTES + 1).is_err());
    assert_eq!(
        wire::encode_json(&text, expected.len())?.as_bytes(),
        expected
    );
    assert!(wire::encode_json(&text, expected.len() - 1).is_err());
    assert!(wire::encode_frame(&text, expected.len() - 1).is_err());
    let frame = wire::encode_frame(&text, expected.len())?;
    assert_eq!(&frame.as_bytes()[4..], expected);
    assert_eq!(
        wire::frame_length(frame.as_bytes()[..4].try_into()?, expected.len())?,
        expected.len()
    );

    let maximum = "x".repeat(wire::MAX_FRAME_BYTES - 2);
    assert_eq!(
        wire::encode_json(&maximum, wire::MAX_FRAME_BYTES)?
            .as_bytes()
            .len(),
        wire::MAX_FRAME_BYTES
    );
    assert_eq!(
        wire::encode_frame(&maximum, wire::MAX_FRAME_BYTES)?
            .as_bytes()
            .len(),
        wire::MAX_FRAME_BYTES + 4
    );
    let excessive = "x".repeat(wire::MAX_FRAME_BYTES - 1);
    assert!(wire::encode_json(&excessive, wire::MAX_FRAME_BYTES).is_err());
    assert!(wire::encode_frame(&excessive, wire::MAX_FRAME_BYTES).is_err());
    Ok(())
}
