use se_types::{NativePath, PathEncoding};

/// Bug: 893e06c — incomplete UNC names are accepted as absolute native paths.
#[test]
fn native_path_ingress_requires_a_complete_absolute_path_and_preserves_units()
-> Result<(), Box<dyn std::error::Error>> {
    for text in [
        r"C:\agent.exe",
        r"\\server\share\agent.exe",
        r"\\?\C:\agent.exe",
        r"\\?\UNC\server\share\agent.exe",
        r"\\.\pipe\otto",
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}\agent.exe",
    ] {
        let encoding = PathEncoding::WindowsUtf16(text.encode_utf16().collect());
        let path = NativePath::from_encoded(encoding.clone())?;
        assert_eq!(path.encoded(), &encoding);
        let wire = serde_json::to_value(&path)?;
        let decoded: NativePath = serde_json::from_value(wire)?;
        assert_eq!(decoded, path);
    }
    // Native representation must not replace an unpaired surrogate or non-UTF-8 byte.
    for encoding in [
        PathEncoding::WindowsUtf16(vec![67, 58, 92, 0xd800]),
        PathEncoding::UnixBytes(vec![47, 255]),
    ] {
        let path = NativePath::from_encoded(encoding.clone())?;
        let decoded: NativePath = serde_json::from_slice(&serde_json::to_vec(&path)?)?;
        assert_eq!(decoded.encoded(), &encoding);
    }
    let mut accepted = Vec::new();
    for text in [
        r"relative",
        r"C:relative",
        r"\root-relative",
        r"\\",
        r"\\server",
        r"\\server\",
        r"\\?\UNC\server",
        r"\\?\UNC\server\",
        r"\\?\C:relative",
    ] {
        let encoding = PathEncoding::WindowsUtf16(text.encode_utf16().collect());
        let wire = serde_json::to_value(&encoding)?;
        let constructor_accepts = NativePath::from_encoded(encoding).is_ok();
        let serde_accepts = serde_json::from_value::<NativePath>(wire).is_ok();
        if constructor_accepts || serde_accepts {
            accepted.push((text, constructor_accepts, serde_accepts));
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted incomplete/relative paths: {accepted:?}"
    );
    Ok(())
}
