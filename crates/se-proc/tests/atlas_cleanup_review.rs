//! Expired starts cannot acquire native child custody.
#![cfg(any(target_os = "linux", windows, target_os = "macos"))]
use se_proc::atlas_worker::AtlasWorker;
use std::time::{Duration, Instant};
#[test]
fn consecutive_expired_starts_leave_the_custody_slot_available()
-> Result<(), Box<dyn std::error::Error>> {
    let image = std::env::current_exe()?.canonicalize()?;
    let mut first = None;
    for attempt in 0..3 {
        let deadline = Instant::now() - Duration::from_millis(1);
        let error = match AtlasWorker::spawn_bounded(&image, b"{}", deadline) {
            Ok(mut worker) => {
                worker.cancel_until(Instant::now() + Duration::from_secs(5))?;
                return Err("expired start created a child".into());
            }
            Err(error) => error,
        };
        println!("attempt={attempt} kind={:?} error={error}", error.kind());
        let observed = (error.kind(), error.to_string());
        if let Some(expected) = &first {
            assert_eq!(
                &observed, expected,
                "an expired start changed the available custody slot at attempt {attempt}"
            );
        } else {
            first = Some(observed);
        }
    }
    Ok(())
}
