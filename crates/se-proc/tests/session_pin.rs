//! Protects: 70 §2.2 / G1/G8 — a public handle resolves only its exact protected
//! session pin; drift, foreign bytes and unsafe files never become owner authority.
use se_proc::{
    NativeStateFiles, publish_session_pin, read_session_pin, remove_session_pin, session_launch_id,
};
use se_types::{Secret, SessionId};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};
type Check = Result<(), Box<dyn std::error::Error>>;

/// Protects: pin publication is consumed in another process, with no secret argv/environment.
#[test]
#[ignore = "spawned by the protected-pin consumer judge"]
fn session_pin_reader_child() -> Check {
    let root = PathBuf::from(std::env::var_os("PIN_JUDGE_ROOT").ok_or("fixture root absent")?);
    let handle = std::env::var("PIN_JUDGE_HANDLE")?;
    let expected = std::env::var("PIN_JUDGE_DIGEST")?;
    let files = NativeStateFiles::open(&root)?;
    let token = read_session_pin(&files, &handle)?;
    assert_eq!(
        se_types::hex_lower(&Sha256::digest(token.expose())),
        expected
    );
    Ok(())
}

/// Protects: real pin producer/reader/remover, absent versus unsafe, and digest-checked foreign preservation.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn protected_session_pin_custody_refuses_drift_and_never_overwrites() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let session = SessionId::from_parts(1_700_000_000_001, [17; 10])?;
    let other = SessionId::from_parts(1_700_000_000_002, [18; 10])?;
    let suffix = se_types::hex_lower(&se_proc::random_secret()?.expose()[..16]);
    let root = std::env::temp_dir().join(format!("se-session-pin-{suffix}"));
    println!("pin fixture (retained on failure): {}", root.display());
    let files = NativeStateFiles::create(&root)?;
    // Unissued synthetic tokens test custody, not provider authentication.
    let token = Secret::new(format!("sec1.{}.{}", session.as_str(), "A".repeat(43)).into_bytes())?;
    let foreign = Secret::new(format!("sec1.{}.{}", other.as_str(), "B".repeat(43)).into_bytes())?;
    let expected: [u8; 32] = Sha256::digest(token.expose()).into();
    publish_session_pin(&files, &session, &token)?;
    let pin = root
        .join("launch")
        .join(session_launch_id(&session)?.as_str())
        .join("pin");
    assert_eq!(fs::read(&pin)?, token.expose());
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "session_pin_reader_child",
            "--ignored",
            "--nocapture",
        ])
        .env("PIN_JUDGE_ROOT", &root)
        .env("PIN_JUDGE_HANDLE", session.as_str())
        .env("PIN_JUDGE_DIGEST", se_types::hex_lower(&expected))
        .output()?;
    assert!(
        child.status.success(),
        "outside pin reader failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );

    assert!(
        publish_session_pin(&files, &session, &token).is_err(),
        "pin publication overwrote an existing pin"
    );
    assert!(
        publish_session_pin(&files, &session, &foreign).is_err(),
        "producer accepted another session's token"
    );
    assert_eq!(fs::read(&pin)?, token.expose());
    for handle in [
        token.expose(),
        b"../credential",
        b"ses_../../credential",
        other.as_str().as_bytes(),
    ] {
        assert!(
            read_session_pin(&files, std::str::from_utf8(handle)?).is_err(),
            "invalid or absent handle resolved to a credential"
        );
    }
    fs::write(&pin, foreign.expose())?;
    assert!(
        read_session_pin(&files, session.as_str()).is_err(),
        "reader accepted foreign session bytes"
    );
    assert!(
        remove_session_pin(&files, &session, expected).is_err(),
        "remove consumed an edited foreign pin"
    );
    assert_eq!(
        fs::read(&pin)?,
        foreign.expose(),
        "foreign replacement bytes were lost"
    );
    fs::write(&pin, token.expose())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o644))?;
        assert!(
            read_session_pin(&files, session.as_str()).is_err(),
            "reader accepted an exposed pin"
        );
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o600))?;
        let target = root.join("foreign-target");
        fs::write(&target, token.expose())?;
        fs::remove_file(&pin)?;
        symlink(&target, &pin)?;
        assert!(
            read_session_pin(&files, session.as_str()).is_err(),
            "reader followed a replacement symlink"
        );
        assert!(
            remove_session_pin(&files, &session, expected).is_err(),
            "remover followed a replacement symlink"
        );
        assert_eq!(
            fs::read(&target)?,
            token.expose(),
            "symlink target was changed"
        );
        fs::remove_file(&pin)?;
        publish_session_pin(&files, &session, &token)?;
    }
    remove_session_pin(&files, &session, expected)?;
    assert!(
        !pin.try_exists()?,
        "successful removal did not witness absence"
    );
    assert!(
        read_session_pin(&files, session.as_str()).is_err(),
        "absent pin became a credential"
    );
    remove_session_pin(&files, &session, expected)?;
    drop(files);
    fs::remove_dir_all(&root)?;
    Ok(())
}
