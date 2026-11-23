#![cfg(target_os = "linux")]
//! A blocked native watch wait ends promptly on a wake or a source event, and
//! a consumed wake does not end the next wait.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::{NativeSourceRoot, NativeSourceWatch};
use std::{
    fs,
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;

const PROMPT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(300);

/// Run `wait` on a scoped thread and report when it returns.
fn blocked_wait<'s>(
    scope: &'s thread::Scope<'s, '_>,
    watch: &'s NativeSourceWatch,
) -> mpsc::Receiver<std::io::Result<()>> {
    let (done, finished) = mpsc::channel();
    scope.spawn(move || {
        let _ = done.send(watch.wait());
    });
    finished
}

#[test]
fn wake_ends_a_blocked_wait_and_is_consumed() -> Check {
    let watch = NativeSourceWatch::new()?;
    let wake = watch.wake_handle()?;
    // A wake that arrives first is pending, not lost.
    wake.wake()?;
    let started = Instant::now();
    watch.wait()?;
    assert!(started.elapsed() < PROMPT);
    thread::scope(|scope| -> Check {
        let finished = blocked_wait(scope, &watch);
        // The earlier wake was consumed, so this wait stays blocked.
        assert!(
            matches!(
                finished.recv_timeout(QUIET),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "a consumed wake ended the next wait"
        );
        let woke_at = Instant::now();
        // A clone from another thread reaches the same eventfd.
        let other = wake.clone();
        thread::spawn(move || other.wake())
            .join()
            .map_err(|_| "wake panicked")??;
        finished.recv_timeout(PROMPT)??;
        assert!(woke_at.elapsed() < PROMPT);
        Ok(())
    })?;
    // Repeated handles share one eventfd, and a burst of wakes ends one wait.
    let again = watch.wake_handle()?;
    for _ in 0..3 {
        again.wake()?;
    }
    watch.wait()?;
    Ok(())
}

#[test]
fn source_event_ends_a_blocked_wait_with_a_wake_registered() -> Check {
    let path = std::env::temp_dir().join(format!(
        "se-watch-wake-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&path)?;
    let _owner = cleanup_directory::PrivateDirectory::for_case(path.clone());
    let root = NativeSourceRoot::open(&path)?;
    let watch = NativeSourceWatch::new()?;
    let _wake = watch.wake_handle()?;
    watch
        .subscribe(&root, "")?
        .ok_or("registered root absent")?;
    thread::scope(|scope| -> Check {
        let finished = blocked_wait(scope, &watch);
        assert!(matches!(
            finished.recv_timeout(QUIET),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        fs::write(path.join("edited.rs"), "fn edited() {}")?;
        finished.recv_timeout(PROMPT)??;
        Ok(())
    })?;
    // The event is left queued for the reader.
    let mut buffer = [0; 4096];
    assert!(watch.read(&mut buffer)? > 0);
    Ok(())
}
