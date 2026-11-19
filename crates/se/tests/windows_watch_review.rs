//! Independent Win32 watcher controls through the normal status command.
#![cfg(windows)]

#[test]
fn windows_watcher_freshness_and_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = root.join("../../target/judge-diagnostics/windows-watch-review");
    let result = std::process::Command::new("python")
        .args(["-I", "-B"])
        .arg(root.join("tests/judges/windows_watch_review.py"))
        .arg(env!("CARGO_BIN_EXE_se"))
        .arg(output)
        .output()?;
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[test]
fn windows_notification_loss_is_observed_and_can_rearm() -> Result<(), Box<dyn std::error::Error>> {
    use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
    use std::{
        fs,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    let temp = std::env::temp_dir().join(format!(
        "native-notification-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    ));
    fs::create_dir(&temp)?;
    let result = (|| {
        let folder = NativeSourceRoot::open(&temp)?;
        let mut watch = NativeSourceWatch::new()?;
        assert!(watch.subscribe_tree(&folder)?.is_some());
        // Use unique names, and leave the production event queue undrained for
        // the whole burst. Either kernel or queue loss is an explicit event.
        for n in 0..512 {
            fs::write(
                temp.join(format!("burst-{n:03}-{}.txt", "x".repeat(80))),
                b"x",
            )?;
        }
        let until = Instant::now() + Duration::from_secs(4);
        let mut found_overflow = false;
        let mut buffer = [0; 16384];
        while Instant::now() < until && !found_overflow {
            watch.synchronize(Duration::from_millis(350))?;
            let bytes = watch.read(&mut buffer)?;
            for event in NativeWatchEvents::new(&buffer[..bytes]) {
                found_overflow |= event?.action == NativeWatchAction::Overflow;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(found_overflow, "no native queue-loss event after the burst");
        watch.shutdown(Duration::from_secs(2))?;

        let mut rearmed = NativeSourceWatch::new()?;
        let registration = rearmed
            .subscribe_tree(&folder)?
            .ok_or("watch did not rearm")?;
        fs::write(temp.join("marker.txt"), b"write after rearm")?;
        let until = Instant::now() + Duration::from_secs(4);
        let mut saw_edit = false;
        while Instant::now() < until && !saw_edit {
            rearmed.synchronize(Duration::from_millis(350))?;
            let bytes = rearmed.read(&mut buffer)?;
            for event in NativeWatchEvents::new(&buffer[..bytes]) {
                let event = event?;
                saw_edit |=
                    event.descriptor == Some(registration.descriptor) && event.name == "marker.txt";
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(saw_edit, "rearmed watch did not observe a new write");
        rearmed.shutdown(Duration::from_secs(2))?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })();
    if result.is_ok() {
        fs::remove_dir_all(&temp)?;
    }
    result
}
