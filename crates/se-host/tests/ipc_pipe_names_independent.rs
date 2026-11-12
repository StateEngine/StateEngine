#![cfg(feature = "listener")]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{IpcEndpoint, client::endpoint};

fn names() -> Vec<String> {
    ["", ".", "..", "nested/name", r"nested\name", "a\0b"]
        .into_iter()
        .map(|tail| format!(r"\\.\pipe\{tail}"))
        .chain([
            format!(r"\\.\pipe\{}", "量".repeat(1016)),
            format!(r"\\.\pipe\{}", "😀".repeat(509)),
        ])
        .collect()
}

/// Protects: G1/G6 — both endpoint codec directions reject nested/dot/NUL/overlong Windows pipe names.
#[test]
fn portable_endpoint_codec_refuses_unsafe_windows_names_both_directions() -> Check {
    let home = Home::new()?;
    let mut record = home.record()?;
    record.address = IpcEndpoint::WindowsPipe(r"\\.\pipe\review-valid".into());
    let valid = endpoint::encode_endpoint(&record)?;
    for name in names() {
        let mut wire: serde_json::Value = serde_json::from_slice(valid.as_bytes())?;
        wire["address"]["name"] = serde_json::Value::String(name.clone());
        assert!(
            endpoint::decode_endpoint(&serde_json::to_vec(&wire)?).is_err(),
            "decoder accepted {name:?}"
        );
        record.address = IpcEndpoint::WindowsPipe(name.clone());
        assert!(
            endpoint::encode_endpoint(&record).is_err(),
            "encoder accepted {name:?}"
        );
    }
    for tail in [
        "a..b".to_owned(),
        ".hidden".to_owned(),
        "review-量".to_owned(),
        "😀".repeat(400),
    ] {
        record.address = IpcEndpoint::WindowsPipe(format!(r"\\.\pipe\{tail}"));
        let bytes = endpoint::encode_endpoint(&record)?;
        assert_eq!(
            endpoint::decode_endpoint(bytes.as_bytes())?.address,
            record.address
        );
    }
    Ok(())
}

#[cfg(windows)]
/// Protects: G1/G6 — the real native reservation and connection doors reject unsafe names before OS use.
#[test]
fn native_pipe_doors_refuse_the_same_unsafe_names() -> Check {
    use se_proc::native_ipc::{IpcNativeErrorCode, NativePipeReservation, NativePipeStream};
    for name in names() {
        assert_eq!(
            NativePipeReservation::create(std::ffi::OsStr::new(&name))
                .err()
                .ok_or("unsafe name reserved")?
                .code,
            IpcNativeErrorCode::UnsafeEndpoint
        );
        assert_eq!(
            NativePipeStream::connect(
                std::ffi::OsStr::new(&name),
                bound(std::time::Duration::from_millis(100))
            )
            .err()
            .ok_or("unsafe name connected")?
            .code,
            IpcNativeErrorCode::UnsafeEndpoint
        );
    }
    let name = format!(r"\\.\pipe\review-safe-{}", std::process::id());
    drop(NativePipeReservation::create(std::ffi::OsStr::new(&name))?);
    Ok(())
}
