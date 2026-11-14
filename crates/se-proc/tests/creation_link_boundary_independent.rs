//! Directory creation resolves trusted ancestors without adopting linked roots.
#![cfg(unix)]
use se_proc::{NativeDirectoryCreation, NativeStateFiles, StateFileErrorCode};
use std::{error::Error, fs, io::Write, os::unix::fs::MetadataExt, path::Path};
#[path = "../../test-support/directory.rs"]
mod directory;
type Check = Result<(), Box<dyn Error>>;

fn symlink(target: &Path, path: &Path) -> Check {
    std::os::unix::fs::symlink(target, path)?;
    Ok(())
}
fn unchanged(path: &Path, before: &fs::Metadata) -> Check {
    let after = fs::symlink_metadata(path)?;
    assert_eq!(
        (after.dev(), after.ino(), after.uid(), after.mode()),
        (before.dev(), before.ino(), before.uid(), before.mode())
    );
    Ok(())
}

#[test]
fn trusted_ancestor_creation_publishes_into_the_real_directory() -> Check {
    let fixture = directory::private_directory()?;
    let canonical = fixture.canonicalize()?;
    let real = canonical.join("real");
    fs::create_dir(&real)?;
    let alias = canonical.join("alias");
    symlink(&real, &alias)?;
    let before = fs::symlink_metadata(&alias)?;
    let root = alias.join("new-state");
    let mut creation = NativeDirectoryCreation::begin();
    let files = creation.create(&root)?;
    assert!(!creation.paths().contains(&alias));
    let mut staging = files.create_staging(&root)?;
    staging
        .file
        .write_all(b"independent directory creation readback")?;
    drop(staging.file);
    files.publish_no_replace(&staging.path, &root.join("observation"))?;
    assert_eq!(
        fs::read(real.join("new-state/observation"))?,
        b"independent directory creation readback"
    );
    unchanged(&alias, &before)
}

#[test]
fn a_link_at_the_final_root_is_refused_without_touching_its_target() -> Check {
    let fixture = directory::private_directory()?;
    let canonical = fixture.canonicalize()?;
    let real = canonical.join("real");
    fs::create_dir(&real)?;
    fs::write(real.join("marker"), b"preserve target")?;
    let alias = canonical.join("final-root");
    symlink(&real, &alias)?;
    let before = fs::symlink_metadata(&alias)?;
    let mut creation = NativeDirectoryCreation::begin();
    assert_eq!(
        creation
            .prepare(&alias)
            .err()
            .ok_or("linked root admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    assert!(creation.paths().is_empty());
    assert_eq!(
        NativeStateFiles::open(&alias)
            .err()
            .ok_or("linked store root admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    assert_eq!(fs::read(real.join("marker"))?, b"preserve target");
    unchanged(&alias, &before)
}

#[test]
fn a_foreign_owned_ancestor_link_is_refused_before_creating_a_child() -> Check {
    let fixture = directory::private_directory()?;
    let canonical = fixture.canonicalize()?;
    let real = canonical.join("real");
    fs::create_dir(&real)?;
    fs::write(real.join("marker"), b"preserve target")?;
    let alias = canonical.join("foreign-alias");
    symlink(&real, &alias)?;
    let owner = fs::symlink_metadata(&alias)?.uid();
    let foreign = if owner == 65534 { 65533 } else { 65534 };
    // Provision only this disposable link; no account or profile is changed.
    let status = std::process::Command::new("sudo")
        .args(["-n", "chown", "-h", &foreign.to_string()])
        .arg(&alias)
        .status()?;
    assert!(
        status.success(),
        "fixture could not provision a foreign-owned symlink"
    );
    let before = fs::symlink_metadata(&alias)?;
    assert_eq!(before.uid(), foreign);
    let mut creation = NativeDirectoryCreation::begin();
    assert_eq!(
        creation
            .prepare(&alias.join("new-state"))
            .err()
            .ok_or("foreign ancestor link admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    assert!(creation.paths().is_empty());
    assert!(!real.join("new-state").try_exists()?);
    assert_eq!(fs::read(real.join("marker"))?, b"preserve target");
    unchanged(&alias, &before)
}
