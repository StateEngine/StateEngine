//! Native Linux mirror checks through the host's real Atlas reader.
#![cfg(unix)]
use se_atlas::{
    lifecycle::{AtlasSource, CaseMode, RevisionTrust, SourceRead, SourceVerification},
    model::{CacheLocation, ParseBudget, RelativePath, RootId, RootRegistration},
};
use se_host::atlas_source::NativeAtlasSource;
use se_types::{Detail, ProjectId};
use std::{
    error::Error,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::set_permissions(
            self.0.join("source/denied.rs"),
            fs::Permissions::from_mode(0o600),
        );
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let p = std::env::temp_dir().join(format!(
        "se-atlas-source-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&p)?;
    fs::create_dir(p.join("source"))?;
    fs::create_dir(p.join("cache"))?;
    Ok(Fixture(p))
}
fn registration(f: &Fixture) -> Result<RootRegistration, Box<dyn Error>> {
    Ok(RootRegistration {
        project: ProjectId::from_parts(1, [1; 10])?,
        root: RootId::from_parts(1, [2; 10])?,
        canonical_source_root: f.0.join("source"),
        cache: CacheLocation {
            directory: f.0.join("cache"),
        },
        git_metadata: None,
    })
}
fn budget() -> ParseBudget {
    ParseBudget {
        max_source_bytes: 524288,
        max_rows: 100,
        max_work: Duration::from_millis(200),
        reserved_bytes: 524288,
    }
}
#[test]
fn host_reader_observes_absence_chunks_and_same_size_restored_mtime_edits() -> Check {
    let f = fixture()?;
    let source = NativeAtlasSource::open(registration(&f)?, CaseMode::Sensitive)?;
    let p = RelativePath::new("main.rs")?;
    assert!(matches!(source.read(&p, budget())?, SourceRead::Removed));
    assert!(source.read_chunk(&p, 0, 16)?.is_none());
    fs::write(f.0.join("source/main.rs"), b"fn alpha() {}")?;
    let SourceRead::Bytes(old) = source.read(&p, budget())? else {
        return Err("missing source".into());
    };
    assert_eq!(old.identity.revision_trust, RevisionTrust::Unverified);
    assert_eq!(source.verify(&old)?, SourceVerification::Unchanged);
    let chunk = source.read_chunk(&p, 0, 16)?.ok_or("missing chunk")?;
    assert_eq!(chunk.bytes, old.bytes);
    assert_eq!(chunk.content_revision, Some(old.content_hash));
    let before = fs::metadata(f.0.join("source/main.rs"))?.modified()?;
    fs::write(f.0.join("source/main.rs"), b"fn bravo() {}")?;
    fs::File::options()
        .write(true)
        .open(f.0.join("source/main.rs"))?
        .set_times(fs::FileTimes::new().set_modified(before))?;
    assert_eq!(source.verify(&old)?, SourceVerification::Changed);
    Ok(())
}
#[test]
fn host_reader_refuses_leaf_and_directory_links_and_special_files() -> Check {
    let f = fixture()?;
    fs::write(f.0.join("outside.rs"), b"never read outside")?;
    symlink(f.0.join("outside.rs"), f.0.join("source/link.rs"))?;
    symlink(&f.0, f.0.join("source/linked"))?;
    let source = NativeAtlasSource::open(registration(&f)?, CaseMode::Sensitive)?;
    for name in ["link.rs", "linked/outside.rs"] {
        let p = RelativePath::new(name)?;
        assert!(source.read(&p, budget()).is_err());
        assert!(source.read_chunk(&p, 0, 16).is_err());
    }
    let result = std::process::Command::new("mkfifo")
        .arg(f.0.join("source/pipe"))
        .status()?;
    assert!(result.success());
    assert!(source.read(&RelativePath::new("pipe")?, budget()).is_err());
    assert_eq!(fs::read(f.0.join("outside.rs"))?, b"never read outside");
    Ok(())
}
#[test]
fn host_reader_keeps_permission_failure_distinct_from_absence() -> Check {
    let f = fixture()?;
    let p = f.0.join("source/denied.rs");
    fs::write(&p, b"denied")?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o0))?;
    let source = NativeAtlasSource::open(registration(&f)?, CaseMode::Sensitive)?;
    for result in [
        source
            .read(&RelativePath::new("denied.rs")?, budget())
            .map(|_| ()),
        source
            .read_chunk(&RelativePath::new("denied.rs")?, 0, 16)
            .map(|_| ()),
    ] {
        let e = result.err().ok_or("permission was not refused")?;
        assert!(matches!(e.body.detail(), Detail::AtlasSourceUnreadable(_)));
    }
    Ok(())
}
#[test]
fn host_reader_refuses_replaced_root_even_when_requested_file_is_absent() -> Check {
    let f = fixture()?;
    let source = NativeAtlasSource::open(registration(&f)?, CaseMode::Sensitive)?;
    fs::rename(f.0.join("source"), f.0.join("retired"))?;
    fs::create_dir(f.0.join("source"))?;
    assert!(
        source
            .read(&RelativePath::new("absent.rs")?, budget())
            .is_err()
    );
    assert!(
        source
            .read_chunk(&RelativePath::new("absent.rs")?, 0, 16)
            .is_err()
    );
    Ok(())
}
#[test]
fn source_pin_detects_same_name_replacement_and_root_link_at_open() -> Check {
    let f = fixture()?;
    fs::write(f.0.join("source/a.rs"), b"old")?;
    let root = se_proc::NativeSourceRoot::open(&f.0.join("source"))?;
    let pin = root.open_relative("a.rs")?.ok_or("absent")?;
    fs::rename(f.0.join("source/a.rs"), f.0.join("source/old.rs"))?;
    fs::write(f.0.join("source/a.rs"), b"new")?;
    assert!(!pin.validate_name()?);
    fs::rename(f.0.join("source"), f.0.join("retired"))?;
    symlink(f.0.join("retired"), f.0.join("source"))?;
    assert!(NativeAtlasSource::open(registration(&f)?, CaseMode::Sensitive).is_err());
    Ok(())
}
