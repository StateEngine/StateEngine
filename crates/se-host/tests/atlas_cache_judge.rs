//! Native cache ownership and file cleanup through the host's production adapter.
//! SqlProfile(1) exercises the plumbing; this does not qualify SQL RSS overhead.
use se_atlas::{
    cache::{connection::*, pointer, *},
    model::*,
    scope::Scope,
};
use se_host::atlas_cache::NativeAtlasCache;
use se_types::ProjectId;
use std::{
    error::Error,
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;
static SERIAL: Mutex<()> = Mutex::new(());
struct Fixture {
    dir: PathBuf,
    home: PathBuf,
    scope: Scope,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn fixture() -> Result<Fixture, Box<dyn Error>> {
    se_proc::initialize_file_creation_owner()?;
    let dir = std::env::temp_dir().join(format!(
        "5c-native-cache-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let home = dir.join("atlas");
    let project = ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [2; 10])?;
    let scope = Scope::new(
        RootRegistration {
            project: project.clone(),
            root: root.clone(),
            canonical_source_root: dir.clone(),
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        [3; 32],
    )?;
    Ok(Fixture { dir, home, scope })
}
fn epoch(n: u8) -> Result<CacheEpoch, Box<dyn Error>> {
    Ok(CacheEpoch::from_parts(1, [n; 10])?)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn seed(f: &Fixture) -> Result<CacheSeed, Box<dyn Error>> {
    Ok(CacheSeed {
        identity: CacheIdentity {
            scope: f.scope.clone(),
            epoch: epoch(4)?,
        },
        extractor_version: "judge".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage: serde_json::from_value(
            serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
        )?,
        state: IndexState::Current,
    })
}
#[test]
fn absent_reader_has_no_creation_and_read_only_adapter_cannot_write() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    assert!(NativeAtlasCache::open(&f.home, f.scope.clone())?.is_none());
    assert!(!f.home.exists());
    {
        let _writer = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    }
    let reader = NativeAtlasCache::open(&f.home, f.scope.clone())?.ok_or("reader absent")?;
    assert!(reader.reserve_database(&epoch(4)?).is_err());
    assert!(reader.reserve_growth(1).is_err());
    Ok(())
}
#[test]
fn failed_real_create_discards_the_reserved_epoch_with_outside_absence() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let mut seed = seed(&f)?;
    seed.extractor_version.clear();
    let error = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        deadline(),
    )
    .err()
    .ok_or("bad seed accepted")?;
    assert!(error.to_string().contains("seed"), "{error}");
    assert!(cache.pin_database(&seed.identity.epoch)?.is_none());
    assert!(
        !f.scope
            .registration
            .cache
            .directory
            .join("epochs")
            .join(seed.identity.epoch.as_str())
            .exists()
    );
    assert!(cache.read_pointer()?.is_none());
    Ok(())
}
#[test]
fn discard_refuses_unknown_files_before_deleting_any_owned_bytes() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let pin = cache.reserve_database(&epoch(4)?)?;
    let unknown = pin.path.parent().ok_or("parent")?.join("keep.txt");
    fs::write(&unknown, b"stranger work")?;
    assert!(cache.discard_unpublished(&pin).is_err());
    assert!(pin.path.exists());
    assert_eq!(fs::read(&unknown)?, b"stranger work");
    fs::remove_file(unknown)?;
    cache.discard_unpublished(&pin)?;
    assert!(!pin.path.exists());
    Ok(())
}
#[test]
fn discard_refuses_replaced_database_and_preserves_both_files() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let pin = cache.reserve_database(&epoch(4)?)?;
    let old = pin.path.with_file_name("old.db");
    fs::rename(&pin.path, &old)?;
    let parent = se_proc::NativeStateFiles::open(pin.path.parent().ok_or("parent")?)?;
    let mut stage = parent.create_staging(parent.root())?;
    {
        use std::io::Write;
        stage.file.write_all(b"other replacement")?;
    }
    drop(stage.file);
    parent.publish_no_replace(&stage.path, &pin.path)?;
    assert!(cache.discard_unpublished(&pin).is_err());
    assert_eq!(fs::read(&pin.path)?, b"other replacement");
    assert!(old.exists());
    Ok(())
}
#[test]
fn published_epoch_cannot_be_discarded_and_readers_do_no_inventory() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let s = seed(&f)?;
    let profile = SqlProfile::from_qualified_overhead(1)?;
    let db = CacheConnection::create(&cache, &s, ConnectionRole::HostWriter, &profile, deadline())?;
    pointer::publish(&cache, &db, None, deadline())?;
    let pin = cache.pin_database(&s.identity.epoch)?.ok_or("pin absent")?;
    assert!(cache.discard_unpublished(&pin).is_err());
    assert!(pin.path.exists());
    let unknown = f.scope.registration.cache.directory.join("keep.txt");
    fs::write(&unknown, b"preserve")?;
    let files = NativeAtlasCache::open(&f.home, f.scope.clone())?.ok_or("reader absent")?;
    let reader = pointer::open_current(
        &files,
        &f.scope,
        ConnectionRole::ExternalReader,
        &profile,
        deadline(),
    )?
    .ok_or("epoch absent")?;
    let count: i64 = reader.connection.read(deadline(), |v| {
        v.prepare("SELECT count(*) FROM names")?
            .query_row([], |r| r.get(0))
            .map_err(|e| se_types::SeError::invalid("judge SQL", &e.to_string()))
    })?;
    assert_eq!(count, 0);
    assert_eq!(fs::read(unknown)?, b"preserve");
    Ok(())
}
#[test]
fn writer_lease_releases_on_drop_and_sparse_growth_obeys_disk_budget() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let first = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    assert!(NativeAtlasCache::create(&f.home, f.scope.clone()).is_err());
    drop(first);
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let pin = cache.reserve_database(&epoch(4)?)?;
    let growth_file = fs::OpenOptions::new().write(true).open(&pin.path)?;
    growth_file.set_len(512_000_001)?;
    let error = cache
        .reserve_growth(1)
        .err()
        .ok_or("disk budget accepted")?;
    assert!(matches!(
        error.body.detail(),
        se_types::Detail::AtlasResourceBudget(_)
    ));
    growth_file.set_len(0)?;
    drop(growth_file);
    let reservation = cache.reserve_growth(1)?;
    drop(reservation);
    cache.discard_unpublished(&pin)?;
    Ok(())
}

#[test]
fn atlas_cache_writer_child() -> Check {
    let Some(directory) = std::env::var_os("ATLAS_JUDGE_CHILD_DIRECTORY") else {
        return Ok(());
    };
    se_proc::initialize_file_creation_owner()?;
    let dir = PathBuf::from(directory);
    let project = ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [2; 10])?;
    let home = dir.join("atlas");
    let scope = Scope::new(
        RootRegistration {
            project: project.clone(),
            root: root.clone(),
            canonical_source_root: dir.clone(),
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        [3; 32],
    )?;
    let _cache = NativeAtlasCache::create(&home, scope)?;
    use std::io::{Read, Write};
    println!("ATLAS_WRITER_READY");
    std::io::stdout().flush()?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    // Skip Rust destructors: only process exit releases the kernel-owned lease.
    std::process::exit(0)
}

#[test]
fn native_writer_lease_is_process_owned_and_released_after_child_exit() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "atlas_cache_writer_child", "--nocapture"])
        .env("ATLAS_JUDGE_CHILD_DIRECTORY", &f.dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    use std::io::BufRead;
    let mut stdout = std::io::BufReader::new(child.stdout.take().ok_or("child stdout")?);
    let mut line = String::new();
    loop {
        line.clear();
        if stdout.read_line(&mut line)? == 0 {
            return Err("child exited before acquiring the native writer lease".into());
        }
        if line.trim() == "ATLAS_WRITER_READY" {
            break;
        }
    }
    assert!(NativeAtlasCache::create(&f.home, f.scope.clone()).is_err());
    drop(child.stdin.take()); // normal input EOF, never a name/pattern process kill
    assert!(child.wait()?.success());
    let _writer = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    Ok(())
}

#[test]
fn new_reservation_cannot_claim_or_erase_preexisting_epoch_sidecars() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    {
        let _cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    }
    let epoch = epoch(4)?;
    let epochs = f.scope.registration.cache.directory.join("epochs");
    let parent = se_proc::NativeStateFiles::open(&epochs)?;
    let directory = epochs.join(epoch.as_str());
    parent.prepare_directory(&directory)?;
    let files = se_proc::NativeStateFiles::open(&directory)?;
    let mut stage = files.create_staging(&directory)?;
    {
        use std::io::Write;
        stage
            .file
            .write_all(b"retained WAL from an earlier reservation")?;
    }
    drop(stage.file);
    let wal = directory.join("atlas.db-wal");
    files.publish_no_replace(&stage.path, &wal)?;
    let before = fs::read(&wal)?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    match cache.reserve_database(&epoch) {
        Err(_) => assert_eq!(fs::read(&wal)?, before),
        Ok(pin) => {
            let cleanup = cache.discard_unpublished(&pin);
            drop(_serial); // report the custody failure without poisoning other native cases
            assert!(
                wal.exists(),
                "a new reservation erased a preexisting sidecar; cleanup={cleanup:?}"
            );
            assert_eq!(fs::read(&wal)?, before);
            panic!("a new epoch reservation claimed a nonfresh directory with prior sidecars");
        }
    }
    Ok(())
}
