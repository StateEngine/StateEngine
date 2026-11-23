//! Open-time metadata and cached scan directories never stand in for a fresh check
//! once the named object, its directory, or its bytes may have changed.
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
use se_proc::NativeSourceRoot;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn case(
    name: &str,
) -> Result<(PathBuf, cleanup_directory::PrivateDirectory), Box<dyn std::error::Error>> {
    let base = std::env::temp_dir().join(format!(
        "source-root-reuse-{name}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&base)?;
    let owner = cleanup_directory::PrivateDirectory::for_case(base.clone());
    fs::create_dir(base.join("root"))?;
    Ok((base, owner))
}
/// Backdate a file so a rewrite always moves its timestamps, whatever the clock tick.
fn backdate(path: &Path) -> Check {
    fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_modified(UNIX_EPOCH + Duration::from_secs(946_684_800))?;
    Ok(())
}

#[test]
fn scan_refuses_a_cached_directory_replaced_by_name() -> Check {
    let (base, owner) = case("swap")?;
    let root = base.join("root");
    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;
    fs::write(root.join("a/x.rs"), "fn x() {}")?;
    fs::write(root.join("b/y.rs"), "fn y() {}")?;
    let source = NativeSourceRoot::open(&root)?;
    let mut scan = source.begin_scan()?;
    let first = scan.open_relative("a/x.rs")?.ok_or("a/x.rs absent")?;
    assert!(first.validate_name()?);
    drop(first);
    fs::rename(root.join("a"), base.join("a-moved"))?;
    fs::create_dir(root.join("a"))?;
    fs::write(root.join("a/x.rs"), "fn x() {}")?;
    let refused = match scan.open_relative("b/y.rs") {
        Ok(_) => return Err("leaving a replaced cached directory was accepted".into()),
        Err(error) => error,
    };
    assert!(
        refused
            .to_string()
            .contains("source directory changed during scan"),
        "unexpected refusal: {refused}"
    );
    drop(scan);
    drop(source);
    owner.finish(Ok(()))
}

#[test]
fn same_size_write_after_open_never_matches_the_open_baseline() -> Check {
    let (base, owner) = case("baseline")?;
    let root = base.join("root");
    let path = root.join("same.rs");
    fs::write(&path, "fn before() {}\n")?;
    backdate(&path)?;
    let source = NativeSourceRoot::open(&root)?;
    let mut file = source.open_relative("same.rs")?.ok_or("same.rs absent")?;
    let opened = file.opened_revision();
    assert_eq!(
        opened,
        file.revision()?,
        "open baseline differs before any write"
    );
    fs::write(&path, "fn changed() {}")?;
    let mut bytes = String::new();
    file.read_to_string(&mut bytes)?;
    assert_eq!(bytes, "fn changed() {}");
    let fresh = file.revision()?;
    assert_eq!(fresh.size, opened.size, "fixture must keep the size");
    assert_ne!(
        fresh, opened,
        "a same-size write after open matched the open-time baseline"
    );
    assert!(
        file.validate_name()?,
        "an in-place write is the same named object"
    );
    drop(file);
    drop(source);
    owner.finish(Ok(()))
}

#[cfg(windows)]
#[test]
fn retained_directory_refuses_a_junction_under_its_name() -> Check {
    let (base, owner) = case("junction")?;
    let root = base.join("root");
    fs::create_dir(root.join("held"))?;
    fs::write(root.join("held/kept.rs"), "kept")?;
    fs::create_dir(base.join("elsewhere"))?;
    let source = NativeSourceRoot::open(&root)?;
    let directory = source.open_directory("held")?.ok_or("held absent")?;
    assert!(directory.validate_name()?);
    fs::rename(root.join("held"), base.join("held-moved"))?;
    let status = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(root.join("held"))
        .arg(base.join("held-moved"))
        .stdout(std::process::Stdio::null())
        .status()?;
    assert!(status.success(), "junction fixture was not created");
    let validated = directory.validate_name();
    assert!(
        !matches!(validated, Ok(true)),
        "a junction to the moved directory validated as the retained name"
    );
    // Removing a junction removes the link, never its target's entries.
    fs::remove_dir(root.join("held"))?;
    let status = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(root.join("held"))
        .arg(base.join("elsewhere"))
        .stdout(std::process::Stdio::null())
        .status()?;
    assert!(status.success(), "second junction fixture was not created");
    assert!(
        !matches!(directory.validate_name(), Ok(true)),
        "a junction to another directory validated as the retained name"
    );
    fs::remove_dir(root.join("held"))?;
    assert_eq!(fs::read(base.join("held-moved/kept.rs"))?, b"kept");
    drop(directory);
    drop(source);
    owner.finish(Ok(()))
}
