//! Real native file locks exercise the shared installer/uninstaller error mapping.
#![allow(dead_code, reason = "Shared native store fixture")]
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "../src/installation_error.rs"]
mod installation_error;
use fixture::*;
use se_proc::OwnedFile;
use se_types::{Class, Code, Retry};

#[test]
fn native_lock_contention_is_retryable_and_releases_without_removing_the_lock() -> Check {
    let f = Fixture::new()?;
    let path = f.home.join("installation-test-record");
    std::fs::write(&path, b"original record")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut held = OwnedFile::open(&path)?.ok_or("record missing")?;
    held.claim_installation_record()?;
    let error = match OwnedFile::open(&path) {
        Err(error) => error,
        Ok(Some(mut other)) => match other.claim_installation_record() {
            Err(error) => error,
            Ok(()) => return Err("second claim acquired a held lock".into()),
        },
        Ok(None) => return Err("held record disappeared".into()),
    };
    assert!(error.is_contended());
    let error = installation_error::map(error, |error| {
        se_core::scope::unreadable("native installation custody", &error.to_string())
    });
    assert_eq!(error.code(), Code::StateConflict);
    assert_eq!(error.class(), Class::Conflict);
    assert_eq!(error.class().exit_code(), 1);
    assert!(matches!(error.body.retry(), Retry::AfterReread));
    assert!(error.body.message().contains("contended"));
    assert_eq!(std::fs::read(&path)?, b"original record");
    drop(held);
    let mut retry = OwnedFile::open(&path)?.ok_or("record absent after release")?;
    retry.claim_installation_record()?;
    assert_eq!(std::fs::read(&path)?, b"original record");
    Ok(())
}

#[test]
#[cfg(unix)]
fn native_access_failure_stays_unreadable_and_is_not_reported_as_contention() -> Check {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new()?;
    let path = f.home.join("inaccessible-record");
    std::fs::write(&path, b"retained")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0))?;
    let error = OwnedFile::open(&path)
        .err()
        .ok_or("unreadable file opened")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    assert!(!error.is_contended());
    let error = installation_error::map(error, |error| {
        se_core::scope::unreadable("native installation custody", &error.to_string())
    });
    assert_eq!(error.class(), Class::Unreadable);
    assert_eq!(error.class().exit_code(), 3);
    Ok(())
}
