#![cfg(target_os = "linux")]
use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
use std::{
    fs,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;

#[test]
fn retained_directory_events_do_not_wake_for_source_reads() -> Check {
    let path = std::env::temp_dir().join(format!(
        "se-watch-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&path)?;
    let root = NativeSourceRoot::open(&path)?;
    let watch = NativeSourceWatch::new()?;
    let registration = watch
        .subscribe(&root, "")?
        .ok_or("registered root absent")?;
    fs::write(path.join("source.rs"), "fn initial() {}")?;
    let mut buffer = [0; 4096];
    let count = watch.read(&mut buffer)?;
    assert!(count > 0);
    let mut seen = false;
    for event in NativeWatchEvents::new(&buffer[..count]) {
        let event = event?;
        assert_eq!(event.descriptor, Some(registration.descriptor));
        if event.name == "source.rs" {
            seen = true;
            assert_eq!(event.action, NativeWatchAction::Changed);
        }
    }
    assert!(seen);
    let mut text = String::new();
    fs::File::open(path.join("source.rs"))?.read_to_string(&mut text)?;
    assert_eq!(text, "fn initial() {}");
    assert_eq!(
        watch.read(&mut buffer)?,
        0,
        "source reads must not arm indexing"
    );
    assert!(watch.remove(registration.descriptor)?);
    drop(watch);
    drop(root);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn watch_subscription_refuses_source_links_and_replaced_roots() -> Check {
    use std::os::unix::fs::symlink;
    let path = std::env::temp_dir().join(format!(
        "se-watch-custody-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&path)?;
    fs::create_dir(path.join("outside"))?;
    fs::create_dir(path.join("source"))?;
    symlink(path.join("outside"), path.join("source/escape"))?;
    let root = NativeSourceRoot::open(&path.join("source"))?;
    let watch = NativeSourceWatch::new()?;
    assert!(watch.subscribe(&root, "escape").is_err());
    assert!(watch.subscribe(&root, "absent")?.is_none());
    fs::rename(path.join("source"), path.join("retired"))?;
    fs::create_dir(path.join("source"))?;
    assert!(watch.subscribe(&root, "").is_err());
    drop(watch);
    drop(root);
    fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn overflow_is_explicit_and_malformed_events_never_look_empty() -> Check {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(-1i32).to_ne_bytes());
    bytes.extend_from_slice(&0x4000u32.to_ne_bytes());
    bytes.extend_from_slice(&[0; 8]);
    let event = NativeWatchEvents::new(&bytes)
        .next()
        .ok_or("overflow discarded")??;
    assert_eq!(event.action, NativeWatchAction::Overflow);
    assert!(event.descriptor.is_none());
    assert!(
        NativeWatchEvents::new(&bytes[..8])
            .next()
            .ok_or("short event discarded")?
            .is_err()
    );
    Ok(())
}

#[test]
fn directory_cursor_survives_its_callers_root_borrow() -> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("vera-owned-watch-cursor-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    std::fs::write(directory.join("a.rs"), "fn a() {}")?;
    let mut cursor = {
        let root = se_proc::NativeSourceRoot::open(&directory)?;
        se_proc::NativeWatchDirectory::open(&root, "")?.ok_or("absent directory")?
    };
    assert_eq!(cursor.next_entry()?.ok_or("missing entry")?.name, "a.rs");
    assert!(cursor.next_entry()?.is_none());
    drop(cursor);
    std::fs::remove_file(directory.join("a.rs"))?;
    std::fs::remove_dir(directory)?;
    Ok(())
}
