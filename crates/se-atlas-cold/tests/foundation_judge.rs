//! Independent foundation consumer checks. The native test adapter is not a production
//! custody implementation or a qualification of the proposed SQL overhead profile.
#![cfg(unix)]
#[path = "../../test-support/atlas_clock.rs"]
mod test_clock;
use se_atlas::{
    cache::{connection::*, prune, *},
    errors::AtlasResult,
    model::*,
    scope::Scope,
};
use se_types::ProjectId;
use std::{
    error::Error,
    fs::{self, OpenOptions},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
fn cache_error(reason: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("judge IO", &reason.to_string())
}
type Check = Result<(), Box<dyn Error>>;
static SERIAL: Mutex<()> = Mutex::new(());
struct Native {
    dir: PathBuf,
}
impl Drop for Native {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
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
fn setup() -> Result<(Native, CacheSeed, SqlProfile), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!(
        "se-atlas-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&dir)?;
    let native = Native { dir };
    let scope = Scope::new(
        RootRegistration {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: native.dir.clone(),
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
    Ok((native, seed, SqlProfile::from_qualified_overhead(1)?))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[path = "foundation_judge/history.rs"]
mod history;
