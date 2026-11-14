//! A cache database reached through a trusted symlinked ancestor directory
//! still opens.
//!
//! SQLite's own NOFOLLOW flag refuses a symlinked ancestor outright (extended
//! code 1550, SQLITE_CANTOPEN_SYMLINK), which breaks the ordinary macOS temp
//! directory under /var (issue 273's foundation_judge refusals). The open
//! seam now resolves the same link rule the state-files walk admits: a
//! symlinked ancestor owned by root or by the current user. The native test
//! adapter below is not a production custody implementation; only the
//! SQLite open seam is under test.
#![cfg(unix)]
use se_atlas::{
    cache::{connection::*, *},
    errors::AtlasResult,
    model::*,
    scope::Scope,
};
use se_types::ProjectId;
use std::{
    error::Error,
    fs,
    fs::OpenOptions,
    os::unix::fs::symlink,
    path::PathBuf,
    time::{Duration, Instant},
};
// A std-only fixture root: se-atlas deliberately has no se-proc
// dependency, so the custody-backed shared helper is out of reach;
// the plain temp root follows the foundation_judge pattern.
struct TempRoot(std::path::PathBuf);
impl std::ops::Deref for TempRoot {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl TempRoot {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "se-atlas-tp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir(&dir)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        // Keep the plain control free of ambient temporary-directory aliases;
        // the linked cases below add their own explicit ancestor alias.
        Ok(Self(std::fs::canonicalize(dir)?))
    }
    fn finish(
        self,
        result: Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _ = std::fs::remove_dir_all(&self.0);
        result
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn cache_error(reason: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("judge IO", &reason.to_string())
}
type Check = Result<(), Box<dyn Error>>;
struct Native {
    dir: PathBuf,
}
struct Metadata(std::fs::Metadata);
impl DatabaseFile for Metadata {
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        Ok(self.0.clone())
    }
    fn identity(&self) -> std::io::Result<DatabaseFileIdentity> {
        use std::os::unix::fs::MetadataExt;
        let mut volume = [0; 16];
        let mut file = [0; 16];
        volume[..8].copy_from_slice(&self.0.dev().to_be_bytes());
        file[..8].copy_from_slice(&self.0.ino().to_be_bytes());
        Ok((volume, file))
    }
}
struct Reservation;
impl GrowthReservation for Reservation {}
impl CacheFiles for Native {
    fn read_pointer(&self) -> AtlasResult<Option<Vec<u8>>> {
        match fs::read(self.dir.join("current.json")) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(cache_error(e)),
        }
    }
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> AtlasResult<()> {
        if self.read_pointer()?.as_deref() != expected {
            return Err(cache_error("pointer CAS"));
        }
        fs::write(self.dir.join("current.json"), bytes).map_err(cache_error)
    }
    fn pin_database(&self, epoch: &CacheEpoch) -> AtlasResult<Option<DatabasePin>> {
        let path = self.dir.join(epoch.as_str());
        match fs::symlink_metadata(&path) {
            Ok(file) => Ok(Some(DatabasePin {
                file: Box::new(Metadata(file)),
                path,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(cache_error(e)),
        }
    }
    fn reserve_database(&self, epoch: &CacheEpoch) -> AtlasResult<DatabasePin> {
        let path = self.dir.join(epoch.as_str());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(cache_error)?;
        let metadata = file.metadata().map_err(cache_error)?;
        drop(file);
        Ok(DatabasePin {
            file: Box::new(Metadata(metadata)),
            path,
        })
    }
    fn discard_unpublished(&self, pin: &DatabasePin) -> AtlasResult<()> {
        self.validate_database(pin)?;
        for suffix in ["-wal", "-shm", ""] {
            match fs::remove_file(format!("{}{}", pin.path.display(), suffix)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(cache_error(e)),
            }
        }
        Ok(())
    }
    fn validate_database(&self, pin: &DatabasePin) -> AtlasResult<()> {
        use std::os::unix::fs::MetadataExt;
        let path = fs::symlink_metadata(&pin.path).map_err(cache_error)?;
        let held = pin.file.metadata().map_err(cache_error)?;
        if !path.is_file() || path.ino() != held.ino() || path.dev() != held.dev() {
            return Err(cache_error("pin changed"));
        }
        Ok(())
    }
    fn wal_bytes(&self, pin: &DatabasePin) -> AtlasResult<u64> {
        match fs::metadata(format!("{}-wal", pin.path.display())) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(cache_error(e)),
        }
    }
    fn reserve_growth(&self, _: u64) -> AtlasResult<Box<dyn GrowthReservation + '_>> {
        Ok(Box::new(Reservation))
    }
}
fn setup_linked() -> Result<(TempRoot, Native, CacheSeed, SqlProfile), Box<dyn Error>> {
    let root = TempRoot::new()?;
    let real = root.join("real-cache");
    fs::create_dir(&real)?;
    let dir = root.join("linked-cache");
    symlink(&real, &dir)?;
    let native = Native { dir };
    let scope = Scope::new(
        RootRegistration {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: real.clone(),
            cache: CacheLocation {
                directory: native.dir.clone(),
            },
            git_metadata: None,
        },
        [3; 32],
    )?;
    let coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope,
            epoch: CacheEpoch::from_parts(1, [4; 10])?,
        },
        extractor_version: "judge".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::Current,
    };
    let profile = SqlProfile::from_qualified_overhead(1)?;
    Ok((root, native, seed, profile))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
/// Protects: a cache under a trusted link ancestor accepts a write and reads
/// it back, with the database at the real location. An open that did not
/// resolve the link fails at the SQLite seam (extended code 1550).
#[test]
fn cache_opens_through_a_trusted_ancestor_link() -> Check {
    let (root, files, seed, profile) = setup_linked()?;
    let real = root.join("real-cache");
    let mut db = CacheConnection::create(
        &files,
        &seed,
        ConnectionRole::HostWriter,
        &profile,
        deadline(),
    )?;
    db.write(0, deadline(), |v| {
        v.prepare("INSERT INTO names(text) VALUES('linked')")?
            .execute([])
            .map_err(cache_error)?;
        Ok(())
    })?;
    let n: i64 = db.read(deadline(), |v| {
        v.prepare("SELECT count(*) FROM names")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)
    })?;
    assert_eq!(n, 1);
    let epoch_file = real.join(seed.identity.epoch.as_str());
    assert!(
        epoch_file.is_file(),
        "cache database absent at the real location behind the link"
    );
    root.finish(Ok(()))
}

// This adapter keeps every native check, then permits an outside process to
// replace the name between the last check and SQLite's open.
struct SubstitutedNative {
    inner: Native,
    victim: PathBuf,
    armed: std::cell::Cell<bool>,
}
impl CacheFiles for SubstitutedNative {
    fn read_pointer(&self) -> AtlasResult<Option<Vec<u8>>> {
        self.inner.read_pointer()
    }
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> AtlasResult<()> {
        self.inner.replace_pointer(expected, bytes)
    }
    fn pin_database(&self, epoch: &CacheEpoch) -> AtlasResult<Option<DatabasePin>> {
        self.inner.pin_database(epoch)
    }
    fn reserve_database(&self, epoch: &CacheEpoch) -> AtlasResult<DatabasePin> {
        self.inner.reserve_database(epoch)
    }
    fn discard_unpublished(&self, pin: &DatabasePin) -> AtlasResult<()> {
        self.inner.discard_unpublished(pin)
    }
    fn validate_database(&self, pin: &DatabasePin) -> AtlasResult<()> {
        self.inner.validate_database(pin)?;
        if self.armed.replace(false) {
            let status = std::process::Command::new("python3").arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2]); os.symlink(sys.argv[3],sys.argv[1])")
                .arg(&pin.path).arg(pin.path.with_extension("held")).arg(&self.victim)
                .status().map_err(cache_error)?;
            if !status.success() {
                return Err(cache_error("external substitution failed"));
            }
        }
        Ok(())
    }
    fn wal_bytes(&self, pin: &DatabasePin) -> AtlasResult<u64> {
        self.inner.wal_bytes(pin)
    }
    fn reserve_growth(&self, bytes: u64) -> AtlasResult<Box<dyn GrowthReservation + '_>> {
        self.inner.reserve_growth(bytes)
    }
}
fn substitution(linked: bool) -> Check {
    let (root, mut files, mut seed, profile) = setup_linked()?;
    if !linked {
        files.dir = root.join("real-cache");
        // Scope identity is independent of the selected pathname spelling.
        let registration = RootRegistration {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: files.dir.clone(),
            cache: CacheLocation {
                directory: files.dir.clone(),
            },
            git_metadata: None,
        };
        seed.identity.scope = Scope::new(registration, [3; 32])?;
    }
    let victim = root.join("outside.db");
    fs::write(&victim, [])?;
    let files = SubstitutedNative {
        inner: files,
        victim: victim.clone(),
        armed: std::cell::Cell::new(true),
    };
    let result = CacheConnection::create(
        &files,
        &seed,
        ConnectionRole::HostWriter,
        &profile,
        deadline(),
    );
    assert!(result.is_err(), "substituted epoch name was accepted");
    let bytes = fs::read(&victim)?;
    assert!(
        bytes.is_empty(),
        "SQLite changed the substituted file: {} bytes, prefix {:?}",
        bytes.len(),
        &bytes[..bytes.len().min(16)]
    );
    drop(result);
    root.finish(Ok(()))
}
#[test]
fn plain_epoch_substitution_refuses_without_touching_target() -> Check {
    substitution(false)
}
#[test]
fn trusted_ancestor_epoch_substitution_refuses_without_touching_target() -> Check {
    substitution(true)
}
