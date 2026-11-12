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
        "se-native-cache-{}-{}",
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
// Epoch construction includes durable filesystem setup, outside read/work slices.
fn setup_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
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
        setup_deadline(),
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
    let mut db = CacheConnection::create(
        &cache,
        &s,
        ConnectionRole::HostWriter,
        &profile,
        setup_deadline(),
    )?;
    pointer::publish(&cache, &mut db, None, deadline())?;
    let pin = cache.pin_database(&s.identity.epoch)?.ok_or("pin absent")?;
    assert!(cache.discard_unpublished(&pin).is_err());
    assert!(pin.path.exists());
    let unknown = f.scope.registration.cache.directory.join("keep.txt");
    fs::write(&unknown, b"preserve")?;
    let files = NativeAtlasCache::open(&f.home, f.scope.clone())?.ok_or("reader absent")?;
    let mut reader = pointer::open_current(
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
/// A second lease on the same home must be refused on every platform.
///
/// This is deterministic, not timing-based: one cache holds the writer lease
/// while a second acquisition is attempted. On Windows the readback handle
/// shares READ|WRITE|DELETE, so the open grants nothing and the byte-range lock
/// is the only exclusion; if that lock were dropped, this check would pass two
/// holders and fail here.
#[test]
fn a_second_writer_lease_on_one_home_is_refused() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let held = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let second = NativeAtlasCache::create(&f.home, f.scope.clone());
    let refused = match second {
        Ok(_) => false,
        Err(error) => matches!(
            error.body.detail(),
            se_types::Detail::AtlasResourceBudget(detail)
                if detail.resource == "Atlas home writer lease"
        ),
    };
    assert!(refused, "a second lease was granted on a held Atlas home");
    drop(held);
    NativeAtlasCache::create(&f.home, f.scope.clone())?;
    Ok(())
}

/// The Atlas writer lease must end explicitly, not by close.
///
/// `flock` belongs to the open file description, and a child forked on another
/// thread inherits a duplicate of it until it execs. A lease that releases only
/// by closing this process's duplicate therefore stays held by that child's
/// copy, and the same process's next step is refused with a spurious
/// "Atlas home writer lease" busy. This takes and drops the real cache writer
/// through the production adapter while a spawner thread runs, then reacquires:
/// with the explicit release it never refuses, and on the close-only release it
/// refused often (five base runs in five, about ten percent of lease cycles).
#[test]
#[cfg(unix)]
fn writer_lease_ends_explicitly_while_another_thread_spawns() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spawns = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let spawner = {
        let (stop, spawns) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&spawns));
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = std::process::Command::new("/bin/true").status();
                spawns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        })
    };
    // Take the home once so the writer lock exists, then cycle the lease.
    drop(NativeAtlasCache::create(&f.home, f.scope.clone())?);
    let mut refusals = 0;
    let mut leases = 0;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        match NativeAtlasCache::create(&f.home, f.scope.clone()) {
            Ok(cache) => {
                leases += 1;
                drop(cache);
            }
            Err(error) => {
                let writer_busy = matches!(
                    error.body.detail(),
                    se_types::Detail::AtlasResourceBudget(detail)
                        if detail.resource == "Atlas home writer lease"
                );
                if !writer_busy {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    spawner.join().ok();
                    return Err(format!("unexpected cache failure: {error}").into());
                }
                refusals += 1;
            }
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    spawner.join().ok();
    let spawned = spawns.load(std::sync::atomic::Ordering::Relaxed);
    println!("leases={leases} refusals={refusals} spawns={spawned}");
    assert!(spawned > 0, "the spawner ran");
    assert_eq!(
        refusals, 0,
        "the released writer lease was refused {refusals} times in {leases} leases while {spawned} children were spawned"
    );
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
    let cache = NativeAtlasCache::create(&home, scope)?;
    let _reservation = std::env::var("ATLAS_JUDGE_RESERVED_EPOCH")
        .ok()
        .map(|value| -> Result<_, Box<dyn Error>> {
            Ok(cache.reserve_database(&epoch(value.parse()?)?)?)
        })
        .transpose()?;
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

#[cfg(any(target_os = "linux", windows))]
fn kill_reserved_writer(f: &Fixture, number: u8) -> Check {
    use std::{
        io::BufRead,
        process::{Child, Command, Stdio},
    };
    // Reap our exact child on every error path; EOF makes the helper exit even
    // when identity observation refuses the requested hard kill.
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    let executable = std::env::current_exe()?;
    let mut child = OwnedChild(
        Command::new(&executable)
            .args(["--exact", "atlas_cache_writer_child", "--nocapture"])
            .env("ATLAS_JUDGE_CHILD_DIRECTORY", &f.dir)
            .env("ATLAS_JUDGE_RESERVED_EPOCH", number.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("child stdout")?;
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(line) if line.trim() == "ATLAS_WRITER_READY" => {
                    let _ = send.send(true);
                    return;
                }
                Ok(_) => (),
                Err(_) => break,
            }
        }
        let _ = send.send(false);
    });
    let ready = receive.recv_timeout(Duration::from_secs(10));
    if !matches!(ready, Ok(true)) {
        drop(child);
        let _ = reader.join();
        return Err(format!("reservation helper did not become ready: {ready:?}").into());
    }
    reader.join().map_err(|_| "child output reader panicked")?;
    let database = f
        .scope
        .registration
        .cache
        .directory
        .join("epochs")
        .join(epoch(number)?.as_str())
        .join("atlas.db");
    assert!(
        database.is_file(),
        "kill point precedes durable reservation"
    );
    let pid = child.0.id();
    // Read the complete native command line before acting on this exact owned
    // process. No executable-name scan or pattern-based termination is used.
    #[cfg(target_os = "linux")]
    let command = String::from_utf8(fs::read(format!("/proc/{pid}/cmdline"))?)?;
    #[cfg(windows)]
    let command = {
        let output = Command::new("powershell.exe")
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!("$ErrorActionPreference='Stop'; (Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine"))
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "cannot observe owned child command line: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        String::from_utf8(output.stdout)?
    };
    assert!(command.contains("atlas_cache_writer_child") && command.contains("--exact"));
    assert!(
        command
            .to_lowercase()
            .contains(&executable.to_string_lossy().to_lowercase())
    );
    eprintln!("kill owned reservation helper pid={pid} command={command:?}");
    child.0.kill()?;
    assert!(
        !child.0.wait()?.success(),
        "helper exited normally before the crash point"
    );
    assert!(
        database.is_file(),
        "process teardown unexpectedly removed the reservation"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn three_killed_unpublished_writers_do_not_exhaust_epoch_slots() -> Check {
    let serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    for number in [5, 6, 7] {
        kill_reserved_writer(&f, number)?;
    }
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let seed = seed(&f)?;
    let result = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        setup_deadline(),
    );
    drop(serial); // a real recovery failure must not poison unrelated judges
    let mut database = result.map_err(|error| {
        format!("three killed reservations permanently exhausted epoch slots: {error}")
    })?;
    pointer::publish(&cache, &mut database, None, deadline())?;
    assert!(cache.read_pointer()?.is_some());
    for number in [5, 6, 7] {
        assert!(
            !f.scope
                .registration
                .cache
                .directory
                .join("epochs")
                .join(epoch(number)?.as_str())
                .exists(),
            "crashed unpublished epoch was not reclaimed"
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn crash_recovery_preserves_published_epoch_and_unowned_sidecars() -> Check {
    let serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let profile = SqlProfile::from_qualified_overhead(1)?;
    let published;
    {
        let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
        let mut database = CacheConnection::create(
            &cache,
            &seed(&f)?,
            ConnectionRole::HostWriter,
            &profile,
            setup_deadline(),
        )?;
        pointer::publish(&cache, &mut database, None, deadline())?;
        published = cache.read_pointer()?.ok_or("published pointer absent")?;
    }
    let epochs = f.scope.registration.cache.directory.join("epochs");
    let unknown = epochs.join(epoch(8)?.as_str());
    se_proc::NativeStateFiles::open(&epochs)?.prepare_directory(&unknown)?;
    let files = se_proc::NativeStateFiles::open(&unknown)?;
    let mut stage = files.create_staging(&unknown)?;
    {
        use std::io::Write;
        stage
            .file
            .write_all(b"unowned WAL must survive crash recovery")?;
    }
    drop(stage.file);
    let wal = unknown.join("atlas.db-wal");
    files.publish_no_replace(&stage.path, &wal)?;
    drop(files);
    kill_reserved_writer(&f, 5)?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    assert_eq!(cache.read_pointer()?, Some(published));
    assert_eq!(fs::read(&wal)?, b"unowned WAL must survive crash recovery");
    let mut reader = pointer::open_current(
        &cache,
        &f.scope,
        ConnectionRole::ExternalReader,
        &profile,
        deadline(),
    )?
    .ok_or("published cache lost after recovery")?;
    let count: i64 = reader.connection.read(deadline(), |view| {
        view.prepare("SELECT count(*) FROM names")?
            .query_row([], |row| row.get(0))
            .map_err(|error| se_types::SeError::invalid("judge SQL", &error.to_string()))
    })?;
    assert_eq!(count, 0);
    let reserved = cache.reserve_database(&epoch(9)?);
    drop(serial);
    let pin = reserved
        .map_err(|error| format!("crashed reservation still occupies an epoch slot: {error}"))?;
    cache.discard_unpublished(&pin)?;
    assert_eq!(fs::read(wal)?, b"unowned WAL must survive crash recovery");
    Ok(())
}
