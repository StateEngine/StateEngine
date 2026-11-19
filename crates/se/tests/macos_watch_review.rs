//! Native FSEvents and public status controls.
#![cfg(target_os = "macos")]

use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
use std::{
    error::Error,
    fs,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn public_status_reports_watched_facts_and_fresh_fallback() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = root.join("../../target/judge-diagnostics/macos-watch-review");
    let result = std::process::Command::new("python3")
        .args(["-I", "-B"])
        .arg(root.join("tests/judges/macos_watch_review.py"))
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

fn await_event(
    watch: &NativeSourceWatch,
    action: NativeWatchAction,
    name: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let until = Instant::now() + Duration::from_secs(8);
    let mut buffer = [0; 16384];
    while Instant::now() < until {
        watch.synchronize(Duration::from_millis(500))?;
        let bytes = watch.read(&mut buffer)?;
        for event in NativeWatchEvents::new(&buffer[..bytes]) {
            let event = event?;
            if event.action == action && name.is_none_or(|name| event.name == name) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!("native event {action:?} {name:?} was not delivered").into())
}

#[test]
fn native_loss_and_root_invalidation_reach_the_watcher() -> Result<(), Box<dyn Error>> {
    let root = std::env::temp_dir().canonicalize()?.join(format!(
        "fsevents-review-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    ));
    fs::create_dir(&root)?;
    let source = root.join("source");
    fs::create_dir(&source)?;
    let retained = NativeSourceRoot::open(&source)?;
    {
        let watch = NativeSourceWatch::new()?;
        assert!(watch.subscribe_tree(&retained)?.is_some());
        fs::write(source.join("armed.txt"), b"witness delivery")?;
        await_event(&watch, NativeWatchAction::Changed, Some("armed.txt"))?;
        // A retained, undrained consumer must see one explicit loss notification.
        for n in 0..640 {
            fs::write(
                source.join(format!("burst-{n:03}-{}", "a".repeat(90))),
                b"x",
            )?;
        }
        std::thread::sleep(Duration::from_millis(700));
        await_event(&watch, NativeWatchAction::Overflow, None)?;
    }
    {
        let watch = NativeSourceWatch::new()?;
        assert!(watch.subscribe_tree(&retained)?.is_some());
        fs::write(source.join("rearmed.txt"), b"new stream")?;
        await_event(&watch, NativeWatchAction::Changed, Some("rearmed.txt"))?;
        fs::rename(&source, root.join("moved"))?;
        await_event(&watch, NativeWatchAction::Invalidated, None)?;
        assert!(retained.check().is_err());
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
