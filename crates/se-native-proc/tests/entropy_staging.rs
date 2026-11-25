//! Linux syscall-bound regression for the real staging consumer, not a mock port.
#![cfg(target_os = "linux")]
#[path = "support/entropy_fill_fixture.rs"]
mod fixture;
use fixture::Check;
#[test]
fn native_staging_refuses_partial_entropy_failure_without_fallback() -> Check {
    fixture::run_child("staging_failure_child")
}
#[test]
#[ignore = "Executed only by the parent with its process-bound native fault interposer"]
fn staging_failure_child() -> Check {
    let home = fixture::Home::new()?;
    let files = se_proc::NativeStateFiles::open(&home.0)?;
    fixture::arm(16)?;
    let error = files
        .create_staging(&home.0)
        .err()
        .ok_or("native staging allocated a file despite entropy failure")?;
    assert_eq!(error.code, se_proc::StateFileErrorCode::Unreadable);
    fixture::assert_partial_then_eio()?;
    assert_eq!(
        std::fs::read_dir(&home.0)?.count(),
        0,
        "failed entropy left a staging file"
    );
    Ok(())
}
