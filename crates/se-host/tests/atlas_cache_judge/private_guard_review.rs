//! Native Windows custody and publication through the production cache port.
use super::*;
use se_proc::NativeFileIdentity;
use std::{cell::Cell, io, path::Path, rc::Rc};

struct CountedFile {
    file: Box<dyn DatabaseFile>,
    checks: Rc<Cell<usize>>,
}
impl DatabaseFile for CountedFile {
    fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    fn identity(&self) -> io::Result<DatabaseFileIdentity> {
        self.checks.set(self.checks.get() + 1);
        self.file.identity()
    }
}

struct Witness<'a> {
    cache: &'a NativeAtlasCache,
    epoch: CacheEpoch,
    checks: Rc<Cell<usize>>,
    sqlite_matches: Cell<bool>,
    shortcut: Cell<bool>,
}
impl<'a> Witness<'a> {
    fn new(cache: &'a NativeAtlasCache, epoch: CacheEpoch) -> Self {
        Self {
            cache,
            epoch,
            checks: Rc::new(Cell::new(0)),
            sqlite_matches: Cell::new(false),
            shortcut: Cell::new(false),
        }
    }

    fn counted(&self, pin: DatabasePin) -> DatabasePin {
        DatabasePin {
            path: pin.path,
            file: Box::new(CountedFile {
                file: pin.file,
                checks: Rc::clone(&self.checks),
            }),
        }
    }
}
impl CacheFiles for Witness<'_> {
    fn configure_connection_role(
        &self,
        db: &mut NativeSqlConnection,
        role: ConnectionRole,
    ) -> se_types::Result<()> {
        self.cache.configure_connection_role(db, role)?;
        let pin = self.cache.pin_database(&self.epoch)?.ok_or_else(|| {
            se_types::SeError::invalid("native witness", "an existing reserved database")
        })?;
        let read_identity = |error: io::Error| {
            se_types::SeError::invalid("native database identity", &error.to_string())
        };
        let actual = NativeFileIdentity::observe_sqlite(db).map_err(read_identity)?;
        let named = NativeFileIdentity::observe(&pin.path).map_err(read_identity)?;
        self.sqlite_matches.set(actual == named);
        let probe = self.counted(pin);
        let before = self.checks.get();
        self.cache.validate_database(&probe)?;
        self.shortcut.set(before == self.checks.get());
        Ok(())
    }

    fn release_creation_guard(&self) {
        self.cache.release_creation_guard();
    }

    fn finish_creation_guard(&self) {
        self.cache.finish_creation_guard();
    }

    fn read_pointer(&self) -> se_types::Result<Option<Vec<u8>>> {
        self.cache.read_pointer()
    }

    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> se_types::Result<()> {
        self.cache.replace_pointer(expected, bytes)
    }

    fn pin_database(&self, epoch: &CacheEpoch) -> se_types::Result<Option<DatabasePin>> {
        self.cache.pin_database(epoch)
    }

    fn reserve_database(&self, epoch: &CacheEpoch) -> se_types::Result<DatabasePin> {
        self.cache
            .reserve_database(epoch)
            .map(|pin| self.counted(pin))
    }

    fn discard_unpublished(&self, pin: &DatabasePin) -> se_types::Result<()> {
        self.cache.discard_unpublished(pin)
    }

    fn validate_database(&self, pin: &DatabasePin) -> se_types::Result<()> {
        self.cache.validate_database(pin)
    }

    fn wal_bytes(&self, pin: &DatabasePin) -> se_types::Result<u64> {
        self.cache.wal_bytes(pin)
    }

    fn reserve_growth(&self, bytes: u64) -> se_types::Result<Box<dyn GrowthReservation + '_>> {
        self.cache.reserve_growth(bytes)
    }
}

fn ordinary(path: &Path) -> Result<bool, Box<dyn Error>> {
    Ok(
        se_proc::NativeStateFiles::open(path.parent().ok_or("database parent missing")?)?
            .pin_metadata(path)?
            .ok_or("database absent during qualification")?
            .is_ordinary_local(),
    )
}

#[test]
fn cold_guard_blocks_swap_and_delete_for_the_reserved_sqlite_file() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let key = epoch(4)?;
    let pin = cache.reserve_database(&key)?;
    assert!(ordinary(&pin.path)?, "requires ordinary local NTFS");
    let path = pin.path.clone();
    let identity = NativeFileIdentity::observe(&path)?;
    let other = f.dir.join("other.db");
    let mut wrong = NativeSqlConnection::open(&other)?;
    assert_ne!(NativeFileIdentity::observe_sqlite(&wrong)?, identity);
    let refused = cache
        .configure_connection_role(&mut wrong, ConnectionRole::ColdWriter)
        .err()
        .ok_or("SQLite open on a different fixture file was admitted")?;
    assert!(
        refused.to_string().contains("different cold database"),
        "{refused}"
    );
    drop(wrong);

    let mut sql = NativeSqlConnection::open(&path)?;
    cache.configure_connection_role(&mut sql, ConnectionRole::ColdWriter)?;
    assert_eq!(NativeFileIdentity::observe_sqlite(&sql)?, identity);
    drop(sql);
    drop(pin);

    // SQLite is closed. The native cache guard is the remaining delete barrier.
    let renamed = f.dir.join("renamed.db");
    let rename = fs::rename(&path, &renamed)
        .err()
        .ok_or("guard admitted a swap")?;
    let delete = fs::remove_file(&path)
        .err()
        .ok_or("guard admitted deletion")?;
    assert_eq!(rename.raw_os_error(), Some(32), "{rename}");
    assert_eq!(delete.raw_os_error(), Some(32), "{delete}");
    assert_eq!(NativeFileIdentity::observe(&path)?, identity);
    assert!(!renamed.exists());

    cache.release_creation_guard();
    fs::rename(&path, &renamed)?;
    fs::rename(&renamed, &path)?;
    let pin = cache
        .pin_database(&key)?
        .ok_or("guarded file disappeared")?;
    cache.discard_unpublished(&pin)?;
    assert!(!path.exists());
    drop(pin);
    drop(cache);
    f._root_owner.finish(Ok(()))
}

#[test]
fn cold_guard_restores_native_validation_before_publication() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let seed = seed(&f)?;
    let observed = Witness::new(&cache, seed.identity.epoch.clone());
    let mut db = CacheConnection::create(
        &observed,
        &seed,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        setup_deadline(),
    )?;
    assert!(observed.sqlite_matches.get() && observed.shortcut.get());
    assert!(cache.read_pointer()?.is_none());
    let initial = observed.checks.get();
    db.prepare_cold_publication()?;
    assert!(
        observed.checks.get() > initial,
        "publication preparation skipped native identity"
    );
    db.write(65_536, setup_deadline(), |sql| {
        sql.prepare("INSERT INTO names(text) VALUES('publication witness')")?
            .execute([])
            .map_err(|error| {
                se_types::SeError::invalid("publication witness", &error.to_string())
            })?;
        Ok(())
    })?;
    db.finish_cold_publication(setup_deadline())?;
    let before = observed.checks.get();
    let readback = pointer::publish(&observed, &mut db, None, setup_deadline())?;
    assert!(
        observed.checks.get() > before,
        "pointer publication skipped native identity"
    );
    assert_eq!(readback.epoch, seed.identity.epoch);
    assert!(cache.read_pointer()?.is_some());
    drop(db);
    drop(observed);
    drop(cache);
    f._root_owner.finish(Ok(()))
}

#[test]
fn cold_guard_releases_the_file_on_failed_creation() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let mut invalid = seed(&f)?;
    invalid.extractor_version.clear();
    let key = invalid.identity.epoch.clone();
    let observed = Witness::new(&cache, key.clone());
    let original = CacheConnection::create(
        &observed,
        &invalid,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        setup_deadline(),
    )
    .err()
    .ok_or("bad seed was accepted")?;
    assert!(original.to_string().contains("seed"), "{original}");
    assert!(
        observed.sqlite_matches.get() && observed.shortcut.get(),
        "failed before guard"
    );
    assert!(cache.pin_database(&key)?.is_none());
    assert!(
        !f.scope
            .registration
            .cache
            .directory
            .join("epochs")
            .join(key.as_str())
            .exists()
    );
    assert!(cache.read_pointer()?.is_none());
    let replacement = CacheConnection::create(
        &observed,
        &seed(&f)?,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        setup_deadline(),
    )?;
    drop(replacement);
    drop(observed);
    drop(cache);
    f._root_owner.finish(Ok(()))
}

fn local_junction(link: &Path, target: &Path) -> Check {
    use std::os::windows::process::CommandExt;
    fn cmd_path(path: &Path) -> Result<&str, Box<dyn Error>> {
        let text = path.to_str().ok_or("non-Unicode fixture path")?;
        let text = text.strip_prefix(r"\\?\").unwrap_or(text);
        if text.as_bytes().get(1) != Some(&b':')
            || text.as_bytes().get(2) != Some(&b'\\')
            || text.contains(['"', '%', '!', '\r', '\n', '&', '|', '<', '>', '^'])
        {
            return Err("fixture requires a plain absolute drive-letter path".into());
        }
        Ok(text)
    }
    let command = format!(
        "mklink /J \"{}\" \"{}\"",
        cmd_path(link)?,
        cmd_path(target)?
    );
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c"])
        .raw_arg(command)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn cold_guard_keeps_full_validation_below_a_junction() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let mut f = fixture()?;
    let real_entry = f.dir.join("real");
    fs::create_dir(&real_entry)?;
    // Native creation flushes the parent of a new directory. Establish the
    // protected home by its ordinary name before exercising alias traversal.
    drop(se_proc::NativeStateFiles::create(
        &real_entry.join("atlas"),
    )?);
    let alias = f.dir.join("alias");
    local_junction(&alias, &real_entry)?;
    f.home = alias.join("atlas");
    let registration = &mut f.scope.registration;
    registration.cache.directory = f
        .home
        .join(registration.project.as_str())
        .join(registration.root.as_str());
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let seed = seed(&f)?;
    let observed = Witness::new(&cache, seed.identity.epoch.clone());
    let db = CacheConnection::create(
        &observed,
        &seed,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        setup_deadline(),
    )?;
    let pin = cache
        .pin_database(&seed.identity.epoch)?
        .ok_or("database absent")?;
    assert!(
        !ordinary(&pin.path)?,
        "fixture did not supply unqualified ancestry"
    );
    assert!(observed.sqlite_matches.get());
    assert!(
        !observed.shortcut.get(),
        "unqualified ancestry used the shortcut"
    );
    let before = observed.checks.get();
    let probe = observed.counted(pin);
    cache.validate_database(&probe)?;
    assert!(observed.checks.get() > before);
    drop(probe);
    drop(db);
    drop(observed);
    drop(cache);
    fs::remove_dir(alias)?;
    f._root_owner.finish(Ok(()))
}

#[test]
fn cold_guard_keeps_full_validation_when_sqlite_identity_is_unavailable() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "fixture lock")?;
    let f = fixture()?;
    let cache = NativeAtlasCache::create(&f.home, f.scope.clone())?;
    let key = epoch(4)?;
    let reserved = cache.reserve_database(&key)?;
    assert!(ordinary(&reserved.path)?);
    let mut without_native_main = NativeSqlConnection::open_in_memory()?;
    assert!(NativeFileIdentity::observe_sqlite(&without_native_main).is_err());
    cache.configure_connection_role(&mut without_native_main, ConnectionRole::ColdWriter)?;
    let observed = Witness::new(&cache, key);
    let probe = observed.counted(reserved);
    assert_eq!(observed.checks.get(), 0);
    cache.validate_database(&probe)?;
    assert!(
        observed.checks.get() > 0,
        "unavailable native ID skipped full validation"
    );
    drop(without_native_main);
    cache.discard_unpublished(&probe)?;
    assert!(!probe.path.exists());
    drop(probe);
    drop(observed);
    drop(cache);
    f._root_owner.finish(Ok(()))
}
