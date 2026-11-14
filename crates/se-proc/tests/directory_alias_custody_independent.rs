//! Native directory creation must resolve only trusted ancestor aliases.
#![cfg(unix)]

use se_proc::{NativeDirectoryCreation, NativeStateFiles, StateFileErrorCode};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Check<Self> {
        let secret = se_proc::random_secret().map_err(|e| format!("entropy: {e:?}"))?;
        let parent = if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let path = Path::new(parent).join(format!(
            "dc-{}",
            se_types::hex_lower(&secret.expose()[..12])
        ));
        assert!(!path.try_exists()?);
        drop(NativeStateFiles::create(&path)?);
        eprintln!("owned directory-control fixture: {}", path.display());
        Ok(Self(path))
    }

    fn target(&self) -> Check<PathBuf> {
        let target = self.0.join("target");
        drop(NativeStateFiles::create(&target)?);
        fs::write(target.join("marker"), b"preserve existing bytes")?;
        Ok(target)
    }

    fn finish(self) -> Check {
        fs::remove_dir_all(&self.0)?;
        Ok(())
    }
}

fn refused_without_mutation(alias: &Path, target: &Path) -> Check {
    let original_link = fs::read_link(alias)?;
    let mut creation = NativeDirectoryCreation::begin();
    let result = creation.create(&alias.join("state"));
    assert_eq!(
        result.err().ok_or("untrusted ancestor admitted")?.code,
        StateFileErrorCode::LocationUnsafe
    );
    assert!(
        creation.paths().is_empty(),
        "created paths: {:?}",
        creation.paths()
    );
    assert!(!target.join("state").try_exists()?);
    assert_eq!(fs::read_link(alias)?, original_link);
    assert_eq!(fs::read(target.join("marker"))?, b"preserve existing bytes");
    Ok(())
}

#[test]
fn trusted_alias_publishes_state_but_final_root_link_refuses() -> Check {
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    let alias = fixture.0.join("alias");
    symlink(&target, &alias)?;
    assert_eq!(
        NativeDirectoryCreation::begin()
            .prepare(&alias)
            .err()
            .ok_or("final root link admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    let root = alias.join("state");
    let mut creation = NativeDirectoryCreation::begin();
    let files = creation.create(&root)?;
    let mut stage = files.create_staging(&root)?;
    stage.file.write_all(b"protected publication")?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &root.join("payload"))?;
    assert_eq!(
        fs::read(target.join("state/payload"))?,
        b"protected publication"
    );
    assert_eq!(fs::metadata(target.join("state"))?.mode() & 0o777, 0o700);
    assert_eq!(fs::read_link(&alias)?, target);
    drop(files);
    drop(creation);
    fixture.finish()
}

#[test]
fn trusted_link_does_not_admit_writable_target() -> Check {
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o777))?;
    let alias = fixture.0.join("alias");
    symlink(&target, &alias)?;
    refused_without_mutation(&alias, &target)?;
    assert_eq!(fs::metadata(&target)?.mode() & 0o777, 0o777);
    fixture.finish()
}

#[test]
fn foreign_link_to_owned_target_is_refused_without_mutation() -> Check {
    let fixture = Fixture::new()?;
    let target = fixture.target()?;
    let alias = fixture.0.join("alias");
    symlink(&target, &alias)?;
    let owner = fs::symlink_metadata(&alias)?.uid();
    let foreign = if owner == 65534 { 65533 } else { 65534 };
    // Hosted runners provide passwordless sudo to provision this exact fixture
    // entry. Refuse a missing provisioning capability rather than skip the test.
    let changed = Command::new("sudo")
        .args(["-n", "chown", "-h", &foreign.to_string()])
        .arg(&alias)
        .output()?;
    assert!(
        changed.status.success(),
        "foreign-link fixture: {}",
        String::from_utf8_lossy(&changed.stderr)
    );
    assert_eq!(fs::symlink_metadata(&alias)?.uid(), foreign);
    refused_without_mutation(&alias, &target)?;
    assert_eq!(fs::symlink_metadata(&alias)?.uid(), foreign);
    fixture.finish()
}
