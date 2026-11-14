//! An external pathname replacement must not let init write another file.
#![cfg(unix)]
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_proc::NativeStateFiles;
use se_store::*;
use se_types::{Read, Retry};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
#[path = "../../test-support/directory.rs"]
mod directory;

fn refusal(error: impl std::fmt::Display) -> Box<StoreError> {
    Box::new(StoreError {
        code: StoreErrorCode::Unreadable,
        cause: error.to_string(),
        detail: StoreDetail::None,
        remedy: se_types::Remedy {
            text: "Preserve the fixture".into(),
            command: None,
        },
        retry: Retry::Never,
    })
}
struct SubstitutedFiles {
    inner: Arc<Lease>,
    victim: PathBuf,
}
impl StateFiles for SubstitutedFiles {
    fn create_staging(&self, directory: &Path) -> StoreResult<ProtectedStaging> {
        let stage = self.inner.files.create_staging(directory)?;
        // The native adapter returns a real reserved file. A separate process
        // changes its pathname while the retained handle still names that file.
        let status = Command::new("python3").arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2]); os.symlink(sys.argv[3],sys.argv[1])")
            .arg(&stage.path).arg(stage.path.with_extension("held")).arg(&self.victim)
            .status().map_err(refusal)?;
        if !status.success() {
            return Err(refusal("external substitution failed"));
        }
        Ok(stage)
    }
    fn inspect_metadata(&self, path: &Path) -> StoreResult<Read<fs::Metadata>> {
        self.inner.files.inspect_metadata(path)
    }
    fn readback(&self, path: &Path) -> StoreResult<Read<fs::File>> {
        self.inner.files.readback(path)
    }
    fn publish_no_replace(&self, stage: &Path, target: &Path) -> StoreResult<()> {
        self.inner.files.publish_no_replace(stage, target)
    }
    fn retire_empty_staging(&self, stage: ProtectedStaging) -> StoreResult<fs::File> {
        self.inner.files.retire_empty_staging(stage)
    }
}
struct SubstitutedLease(SubstitutedFiles);
impl RuntimeLease for SubstitutedLease {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        self.0.inner.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        &self.0
    }
}
fn case(linked: bool) -> Check {
    let root = directory::private_case_directory()?;
    let real = root.join("real");
    drop(NativeStateFiles::create(&real.join("state"))?);
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&real, &alias)?;
    let state = if linked {
        alias.join("state")
    } else {
        real.join("state")
    };
    let f = Fixture::at(root.to_path_buf(), state.clone())?;
    let inner = Lease::acquire(&state, LeaseMode::DirectClient, None)?;
    let victim = root.join("outside.db");
    fs::write(&victim, [])?;
    let lease = SubstitutedLease(SubstitutedFiles {
        inner,
        victim: victim.clone(),
    });
    let result = SqliteFactory::create_direct(&f.options, &lease, f.store.clone());
    assert!(result.is_err(), "substituted staging name was accepted");
    let bytes = fs::read(&victim)?;
    assert!(
        bytes.is_empty(),
        "SQLite changed the substituted file: {} bytes, prefix {:?}",
        bytes.len(),
        &bytes[..bytes.len().min(16)]
    );
    drop(lease);
    root.finish(Ok(()))
}
#[test]
fn plain_staging_substitution_refuses_without_touching_target() -> Check {
    case(false)
}
#[test]
fn trusted_ancestor_staging_substitution_refuses_without_touching_target() -> Check {
    case(true)
}

fn established() -> Result<
    (
        directory::PrivateDirectory,
        Fixture,
        Arc<Lease>,
        PathBuf,
        PathBuf,
    ),
    Box<dyn std::error::Error>,
> {
    let root = directory::private_case_directory()?;
    let real = root.join("real");
    drop(NativeStateFiles::create(&real.join("state"))?);
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&real, &alias)?;
    // Bootstrap through the physical spelling on both revisions; only the
    // subsequent open is meant to encounter the selected ancestor shape.
    let mut f = Fixture::at(root.to_path_buf(), real.join("state"))?;
    let (db, lease) = f.direct()?;
    db.close()?;
    drop(lease);
    f.options.state_directory = alias.join("state");
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::DirectClient,
        Some(f.store.clone()),
    )?;
    Ok((root, f, lease, real, alias))
}
#[test]
fn foreign_ancestor_link_refuses_at_existing_store_open() -> Check {
    use std::os::unix::fs::MetadataExt;
    let (root, f, lease, real, alias) = established()?;
    let owner = fs::symlink_metadata(&alias)?.uid();
    let foreign = if owner == 65534 { 65533 } else { 65534 };
    let status = Command::new("sudo")
        .args(["-n", "chown", "-h", &foreign.to_string()])
        .arg(&alias)
        .status()?;
    assert!(
        status.success(),
        "foreign link fixture could not be provisioned"
    );
    assert_eq!(fs::symlink_metadata(&alias)?.uid(), foreign);
    let before = fs::read(real.join("state/state.db"))?;
    let result = SqliteFactory::open_direct(&f.options, &*lease);
    assert!(
        result.is_err(),
        "foreign-owned ancestor admitted at store open"
    );
    assert_eq!(fs::read(real.join("state/state.db"))?, before);
    drop(result);
    drop(lease);
    fs::remove_file(alias)?;
    root.finish(Ok(()))
}
#[test]
fn writable_target_behind_owned_ancestor_refuses_at_existing_store_open() -> Check {
    use std::os::unix::fs::PermissionsExt;
    let (root, f, lease, real, _alias) = established()?;
    fs::set_permissions(&real, fs::Permissions::from_mode(0o777))?;
    let before = fs::read(real.join("state/state.db"))?;
    let result = SqliteFactory::open_direct(&f.options, &*lease);
    assert!(
        result.is_err(),
        "writable ancestor target admitted at store open"
    );
    assert_eq!(fs::read(real.join("state/state.db"))?, before);
    drop(result);
    drop(lease);
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700))?;
    root.finish(Ok(()))
}
#[test]
fn substituted_state_root_refuses_without_touching_outside_database() -> Check {
    let (root, f, lease, real, _alias) = established()?;
    let held = real.join("held-state");
    fs::rename(real.join("state"), &held)?;
    let outside = root.join("outside-state");
    fs::create_dir(&outside)?;
    fs::write(outside.join("state.db"), b"preserve outside bytes")?;
    std::os::unix::fs::symlink(&outside, real.join("state"))?;
    let result = SqliteFactory::open_direct(&f.options, &*lease);
    let error = result.err().ok_or("substituted root admitted")?;
    assert!(
        matches!(
            error.code,
            StoreErrorCode::LocationUnsafe | StoreErrorCode::SourceChanged
        ),
        "wrong refusal: {error:?}"
    );
    assert_eq!(
        fs::read(outside.join("state.db"))?,
        b"preserve outside bytes"
    );
    drop(lease);
    fs::remove_file(real.join("state"))?;
    fs::rename(held, real.join("state"))?;
    root.finish(Ok(()))
}
