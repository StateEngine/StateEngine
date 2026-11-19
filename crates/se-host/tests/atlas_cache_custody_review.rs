//! Native Windows controls use only independently owned temporary cache paths.
use super::*;
use std::{io::Write, path::Path, process::Command};

type ResultOf<T> = Result<T, Box<dyn Error>>;

fn location(seed: &CacheSeed) -> PathBuf {
    seed.identity
        .scope
        .registration
        .cache
        .directory
        .join("epochs")
        .join(seed.identity.epoch.as_str())
}

fn database<'a>(cache: &'a NativeAtlasCache, seed: &CacheSeed) -> ResultOf<CacheConnection<'a>> {
    Ok(CacheConnection::create(
        cache,
        seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        setup_deadline(),
    )?)
}

fn rename_blocked(source: &Path, moved: &Path) -> ResultOf<bool> {
    match fs::rename(source, moved) {
        Ok(()) => Ok(false),
        Err(error) if matches!(error.raw_os_error(), Some(5 | 32 | 33)) => {
            assert!(source.try_exists()? && !moved.try_exists()?, "{error}");
            Ok(true)
        }
        Err(error) => Err(error.into()),
    }
}

fn junction(name: &Path, target: &Path) -> Check {
    let child = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(name)
        .arg(target)
        .output()?;
    assert!(child.status.success(), "fixture junction: {child:?}");
    use std::os::windows::fs::MetadataExt;
    assert_ne!(fs::symlink_metadata(name)?.file_attributes() & 0x400, 0);
    Ok(())
}

fn acl(path: &Path, args: &[&str]) -> Check {
    let result = Command::new("icacls.exe").arg(path).args(args).output()?;
    assert!(result.status.success(), "fixture junction ACL: {result:?}");
    Ok(())
}

#[test]
fn ancestor_rename_or_junction_replacement_does_not_change_live_connection_custody() -> Check {
    let serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let seed = seed(&f)?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let mut db = database(&cache, &seed)?;
    let directory = location(&seed);
    let moved = directory.with_file_name("moved-epoch");
    let target = f.dir.join("empty-target");
    fs::create_dir(&target)?;
    fs::write(target.join("sentinel.txt"), b"separate synthetic directory")?;
    let live_rename_blocked = rename_blocked(&directory, &moved)?;
    let live_validate = if live_rename_blocked {
        db.validate(deadline())?;
        true
    } else {
        junction(&directory, &target)?;
        let refused = db.validate(deadline()).is_err();
        fs::remove_dir(&directory)?;
        fs::rename(&moved, &directory)?;
        refused
    };
    assert_eq!(
        fs::read(target.join("sentinel.txt"))?,
        b"separate synthetic directory"
    );
    drop(db);

    // A metadata-only pin isolates directory custody from SQLite sharing.
    let pin = cache
        .pin_database(&seed.identity.epoch)?
        .ok_or("database pin absent")?;
    let metadata_rename_blocked = rename_blocked(&directory, &moved)?;
    if !metadata_rename_blocked {
        fs::rename(&moved, &directory)?;
    }
    cache.validate_database(&pin)?;
    drop(pin);
    fs::rename(&directory, &moved)?;
    fs::rename(&moved, &directory)?;
    println!(
        "live_rename_blocked={live_rename_blocked}, metadata_rename_blocked={metadata_rename_blocked}, released_rename=true"
    );
    drop(serial);
    assert!(
        live_validate,
        "a replacement ancestor was accepted by the live connection"
    );
    assert!(
        metadata_rename_blocked,
        "the metadata pin did not retain the epoch directory"
    );
    f._root_owner.finish(Ok(()))
}

#[test]
fn replacement_database_never_validates_and_original_remains_readable() -> Check {
    let serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let seed = seed(&f)?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let mut db = database(&cache, &seed)?;
    let path = location(&seed).join("atlas.db");
    let old = path.with_file_name("original.db");
    let live_rename_blocked = rename_blocked(&path, &old)?;
    if live_rename_blocked {
        db.validate(deadline())?;
    } else {
        fs::rename(&old, &path)?;
    }
    drop(db);
    let pin = cache
        .pin_database(&seed.identity.epoch)?
        .ok_or("database pin absent")?;
    let original = pin.file.identity()?;
    let original_bytes = fs::read(&path)?;
    fs::rename(&path, &old)?;
    let directory =
        se_proc::NativeStateFiles::open(path.parent().ok_or("epoch directory absent")?)?;
    let mut stage = directory.create_staging(directory.root())?;
    stage.file.write_all(b"unrelated synthetic file")?;
    drop(stage.file);
    directory.publish_no_replace(&stage.path, &path)?;
    let new_pin = cache
        .pin_database(&seed.identity.epoch)?
        .ok_or("new database pin absent")?;
    assert_ne!(new_pin.file.identity()?, original);
    let refused = cache.validate_database(&pin).is_err();
    assert_eq!(fs::read(&path)?, b"unrelated synthetic file");
    assert_eq!(fs::read(&old)?, original_bytes);
    drop(new_pin);
    drop(directory);
    drop(pin);
    println!("live_database_rename_blocked={live_rename_blocked}, stale_pin_refused={refused}");
    drop(serial);
    assert!(
        refused,
        "a different named database was accepted under the original pin"
    );
    f._root_owner.finish(Ok(()))
}

#[test]
fn failed_creation_cleans_epoch_and_journal_and_allows_retry() -> Check {
    let serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let good = seed(&f)?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let mut bad = good.clone();
    bad.extractor_version.clear();
    let failure = database(&cache, &bad)
        .err()
        .ok_or("invalid seed accepted")?;
    let path = location(&good);
    let journal = good
        .identity
        .scope
        .registration
        .cache
        .directory
        .join("reservation.json");
    let absent_after_failure = !path.try_exists()? && !journal.try_exists()?;
    assert!(failure.to_string().contains("seed"));
    assert!(cache.read_pointer()?.is_none());
    let mut retry = database(&cache, &good)?;
    retry.validate(deadline())?;
    let owned_pin = cache
        .pin_database(&good.identity.epoch)?
        .ok_or("retry pin absent")?;
    assert!(path.try_exists()? && journal.try_exists()?);
    assert!(owned_pin.path.try_exists()?);
    drop(owned_pin);
    drop(retry);
    println!("failed_creation_cleaned={absent_after_failure}, retry_created=true");
    drop(serial);
    assert!(
        absent_after_failure,
        "failed creation left its epoch or journal"
    );
    f._root_owner.finish(Ok(()))
}

#[test]
fn above_root_junction_checks_owner_and_acl() -> Check {
    let serial = SERIAL.lock().map_err(|_| "lock")?;
    let f = fixture()?;
    let target = f.dir.join("redirected-parent");
    fs::create_dir(&target)?;
    fs::write(target.join("sentinel.txt"), b"redirected fixture");
    let alias = f.dir.join("ancestor-link");
    junction(&alias, &target)?;
    acl(&alias, &["/l", "/setowner", "*S-1-5-32-544", "/q"])?;
    acl(
        &alias,
        &[
            "/l",
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
            "/q",
        ],
    )?;
    let home = alias.join("atlas");
    let mut seed = seed(&f)?;
    let registration = &mut seed.identity.scope.registration;
    registration.cache.directory = home
        .join(registration.project.as_str())
        .join(registration.root.as_str());
    {
        let cache = NativeAtlasCache::create(&home, seed.identity.scope.clone())?;
        let mut db = database(&cache, &seed)?;
        db.validate(deadline())?;
    }
    // Keep the same administrator owner and change only the junction DACL.
    let sid = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()?;
    assert!(sid.status.success(), "fixture user SID unavailable");
    let sid = String::from_utf8(sid.stdout)?;
    let grant = format!("*{}:(M)", sid.trim());
    acl(&alias, &["/l", "/grant:r", &grant, "/q"])?;
    let refusal = match NativeAtlasCache::open(&home, seed.identity.scope.clone()) {
        Err(error) => Some(error),
        Ok(_) => None,
    };
    fs::remove_dir(&alias)?;
    assert_eq!(
        fs::read(target.join("sentinel.txt"))?,
        b"redirected fixture"
    );
    println!(
        "administrator_only_junction_validated=true, user_writable_junction_refused={}",
        refusal.is_some()
    );
    drop(serial);
    let error = refusal.ok_or("user-writable ancestor junction was accepted")?;
    let diagnostic = error.to_string().to_ascii_lowercase();
    assert!(
        diagnostic.contains("ancestor-link") && diagnostic.contains("reparse"),
        "{error}"
    );
    f._root_owner.finish(Ok(()))
}
