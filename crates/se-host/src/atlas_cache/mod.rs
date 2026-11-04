//! Protected cache files shared by hosted and hostless readers. Only activation
//! creates directories or acquires the permanent kernel-owned writer lock.
mod inventory;
mod reservation;
use se_atlas::{cache::*, errors::AtlasResult, model::CacheEpoch, scope::Scope};
use se_proc::{NativeStateFiles, OwnedFile, observe_file_revision};
use se_types::{Detail, SeError, details};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct NativeAtlasCache {
    home: NativeStateFiles,
    root: NativeStateFiles,
    scope: Scope,
    // Permanent inode, never unlinked. Kernel releases ownership on process exit.
    writer: Option<File>,
    reserved: RefCell<Option<(CacheEpoch, se_proc::NativeFileRevision)>>,
    growth: Cell<u64>,
    other_roots_bytes: u64,
}
impl NativeAtlasCache {
    /// No creation, permissions repair, writer lock or schema action on reads.
    pub fn open(home: &Path, scope: Scope) -> AtlasResult<Option<Self>> {
        let home = match NativeStateFiles::open(home) {
            Ok(home) => home,
            Err(e) if missing(&e) => return Ok(None),
            Err(e) => return Err(fail(e)),
        };
        let path = cache_path(&home, &scope)?;
        let root = match NativeStateFiles::open(&path) {
            Ok(root) => root,
            Err(e) if missing(&e) => return Ok(None),
            Err(e) => return Err(fail(e)),
        };
        Ok(Some(Self {
            home,
            root,
            scope,
            writer: None,
            reserved: RefCell::new(None),
            growth: Cell::new(0),
            other_roots_bytes: 0,
        }))
    }
    /// Explicit after-ready activation only. All writers across this Atlas home,
    /// including cold children, share the same kernel lock and disk inventory.
    pub fn create(home: &Path, scope: Scope) -> AtlasResult<Self> {
        let home = NativeStateFiles::create(home).map_err(fail)?;
        let lock = home.root().join("writer.lock");
        if home.readback(&lock).map_err(fail)?.is_none() {
            let stage = home.create_staging(home.root()).map_err(fail)?;
            drop(stage.file);
            match home.publish_no_replace(&stage.path, &lock) {
                Ok(()) => (),
                Err(e) if e.code == se_proc::StateFileErrorCode::AlreadyExists => {
                    let mut orphan = OwnedFile::open(&stage.path)
                        .map_err(fail)?
                        .ok_or_else(|| fail("writer-lock staging disappeared"))?;
                    let digest = orphan.sha256().map_err(fail)?;
                    orphan.remove(digest).map_err(fail)?;
                }
                Err(e) => return Err(fail(e)),
            }
        }
        let writer = home
            .readback(&lock)
            .map_err(fail)?
            .ok_or_else(|| fail("writer lock absent"))?;
        writer.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => busy("Atlas home writer lease", 1, 0),
            std::fs::TryLockError::Error(e) => fail(e),
        })?;
        let named = home
            .readback(&lock)
            .map_err(fail)?
            .ok_or_else(|| fail("writer lock replaced"))?;
        if !same(&writer, &named)? {
            return Err(fail("writer lock identity changed"));
        }
        let path = cache_path(&home, &scope)?;
        let project = path
            .parent()
            .ok_or_else(|| fail("cache project directory missing"))?;
        home.prepare_directory(project).map_err(fail)?;
        let project_files = NativeStateFiles::open(project).map_err(fail)?;
        project_files.prepare_directory(&path).map_err(fail)?;
        let root = NativeStateFiles::open(&path).map_err(fail)?;
        root.prepare_directory(&path.join("epochs")).map_err(fail)?;
        let (total, root_bytes) = inventory::measure(&home, root.root())?;
        let cache = Self {
            home,
            root,
            scope,
            writer: Some(writer),
            reserved: RefCell::new(None),
            growth: Cell::new(0),
            other_roots_bytes: total - root_bytes,
        };
        cache.recover_reservation()?;
        Ok(cache)
    }
    fn require_writer(&self) -> AtlasResult<()> {
        let Some(writer) = &self.writer else {
            return Err(fail("read-only Atlas file adapter"));
        };
        let named = self
            .home
            .readback(&self.home.root().join("writer.lock"))
            .map_err(fail)?
            .ok_or_else(|| fail("retained writer lock is absent"))?;
        if !same(writer, &named)? {
            return Err(fail("retained writer lock replaced"));
        }
        Ok(())
    }
    fn path(&self, epoch: &CacheEpoch) -> PathBuf {
        self.root
            .root()
            .join("epochs")
            .join(epoch.as_str())
            .join("atlas.db")
    }
    fn epoch(&self, pin: &DatabasePin) -> AtlasResult<CacheEpoch> {
        let path = pin
            .path
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .ok_or_else(|| fail("epoch path is invalid"))?;
        let epoch: CacheEpoch = path.parse().map_err(fail)?;
        if self.path(&epoch) != pin.path {
            return Err(fail("database pin outside this cache"));
        }
        Ok(epoch)
    }
    fn pointer(&self) -> PathBuf {
        self.root.root().join("current.json")
    }
    fn check_unpublished(&self, epoch: &CacheEpoch) -> AtlasResult<()> {
        self.require_writer()?;
        if let Some(bytes) = self.read_pointer()? {
            let pointer = se_atlas::cache::pointer::decode(&bytes, &self.scope)?;
            if &pointer.epoch == epoch {
                return Err(fail("refuse removal of a published epoch"));
            }
        }
        Ok(())
    }
}
impl CacheFiles for NativeAtlasCache {
    fn read_pointer(&self) -> AtlasResult<Option<Vec<u8>>> {
        let Some(file) = self.root.readback(&self.pointer()).map_err(fail)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes).map_err(fail)?;
        if bytes.len() > 1024 {
            return Err(fail("Atlas pointer exceeds 1024 bytes"));
        }
        Ok(Some(bytes))
    }
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> AtlasResult<()> {
        self.require_writer()?;
        let pointer = se_atlas::cache::pointer::decode(bytes, &self.scope)?;
        self.pin_database(&pointer.epoch)?
            .ok_or_else(|| fail("candidate epoch absent"))?;
        if self.read_pointer()?.as_deref() != expected {
            return Err(fail("Atlas pointer changed; rediscover"));
        }
        match expected {
            Some(expected) => {
                let owned = OwnedFile::open(&self.pointer())
                    .map_err(fail)?
                    .ok_or_else(|| fail("pointer disappeared before replacement"))?;
                owned
                    .replace(Sha256::digest(expected).into(), bytes)
                    .map_err(fail)?;
            }
            None => {
                let mut stage = self.root.create_staging(self.root.root()).map_err(fail)?;
                stage.file.write_all(bytes).map_err(fail)?;
                drop(stage.file);
                self.root
                    .publish_no_replace(&stage.path, &self.pointer())
                    .map_err(fail)?;
            }
        }
        if self.read_pointer()?.as_deref() != Some(bytes) {
            return Err(fail("published pointer readback differs"));
        }
        if self
            .reserved
            .borrow()
            .as_ref()
            .is_some_and(|(e, _)| e == &pointer.epoch)
        {
            self.clear_reservation()?;
            self.reserved.borrow_mut().take();
        }
        Ok(())
    }
    fn pin_database(&self, epoch: &CacheEpoch) -> AtlasResult<Option<DatabasePin>> {
        let path = self.path(epoch);
        Ok(self
            .root
            .readback(&path)
            .map_err(fail)?
            .map(|file| DatabasePin { file, path }))
    }
    fn reserve_database(&self, epoch: &CacheEpoch) -> AtlasResult<DatabasePin> {
        self.require_writer()?;
        if self.reserved.borrow().is_some() {
            return Err(busy("Atlas unpublished epoch reservation", 1, 0));
        }
        let epochs = NativeStateFiles::open(&self.root.root().join("epochs")).map_err(fail)?;
        let mut count = 0;
        for entry in std::fs::read_dir(epochs.root()).map_err(fail)? {
            let entry = entry.map_err(fail)?;
            count += 1;
            if !entry.file_type().map_err(fail)?.is_dir()
                || entry
                    .file_name()
                    .to_str()
                    .is_none_or(|n| n.parse::<CacheEpoch>().is_err())
            {
                return Err(fail("unknown epoch entry preserved"));
            }
            if count >= 3 {
                return Err(busy("Atlas current/retired/staging epoch slots", 1, 0));
            }
        }
        let directory = self
            .path(epoch)
            .parent()
            .ok_or_else(|| fail("epoch parent missing"))?
            .to_path_buf();
        epochs.prepare_new_directory(&directory).map_err(fail)?;
        let files = NativeStateFiles::open(&directory).map_err(fail)?;
        let stage = files.create_staging(&directory).map_err(fail)?;
        drop(stage.file);
        files
            .publish_no_replace(&stage.path, &self.path(epoch))
            .map_err(fail)?;
        let pin = self
            .pin_database(epoch)?
            .ok_or_else(|| fail("reserved database absent on readback"))?;
        let identity = observe_file_revision(&pin.file).map_err(fail)?;
        self.remember_reservation(epoch, &pin)?;
        *self.reserved.borrow_mut() = Some((epoch.clone(), identity));
        Ok(pin)
    }
    fn discard_unpublished(&self, pin: &DatabasePin) -> AtlasResult<()> {
        let epoch = self.epoch(pin)?;
        self.check_unpublished(&epoch)?;
        let held = observe_file_revision(&pin.file).map_err(fail)?;
        if !self
            .reserved
            .borrow()
            .as_ref()
            .is_some_and(|(e, id)| e == &epoch && id.volume == held.volume && id.file == held.file)
        {
            return Err(fail(
                "no matching unpublished creation custody; preserve epoch",
            ));
        }
        self.validate_database(pin)?;
        let directory = pin
            .path
            .parent()
            .ok_or_else(|| fail("epoch parent absent"))?;
        // Refuse unknown entries before removing anything. Never recurse.
        let mut count = 0;
        for entry in std::fs::read_dir(directory).map_err(fail)? {
            let entry = entry.map_err(fail)?;
            count += 1;
            if count > 3
                || !matches!(
                    entry.file_name().to_str(),
                    Some("atlas.db" | "atlas.db-wal" | "atlas.db-shm")
                )
            {
                return Err(fail("unknown epoch entries preserved; cleanup pending"));
            }
        }
        for name in ["atlas.db-wal", "atlas.db-shm", "atlas.db"] {
            self.check_unpublished(&epoch)?;
            let path = directory.join(name);
            if self.root.readback(&path).map_err(fail)?.is_some() {
                let mut owned = OwnedFile::open(&path)
                    .map_err(fail)?
                    .ok_or_else(|| fail("epoch file disappeared during cleanup"))?;
                let digest = owned.sha256().map_err(fail)?;
                if name == "atlas.db" {
                    self.validate_database(pin)?;
                }
                owned.remove(digest).map_err(fail)?;
            }
            if self.root.readback(&path).map_err(fail)?.is_some() {
                return Err(fail("epoch cleanup absence was not witnessed"));
            }
        }
        if se_proc::remove_empty_directory(directory).map_err(fail)?
            == se_proc::DirectoryRemoval::NotEmpty
        {
            return Err(fail("epoch directory remains nonempty"));
        }
        self.clear_reservation()?;
        self.reserved.borrow_mut().take();
        Ok(())
    }
    fn validate_database(&self, pin: &DatabasePin) -> AtlasResult<()> {
        let epoch = self.epoch(pin)?;
        let named = self
            .pin_database(&epoch)?
            .ok_or_else(|| fail("retained database name absent"))?;
        if !same(&pin.file, &named.file)? {
            return Err(fail("retained database identity changed"));
        }
        Ok(())
    }
    fn wal_bytes(&self, pin: &DatabasePin) -> AtlasResult<u64> {
        self.validate_database(pin)?;
        let path = pin.path.with_file_name("atlas.db-wal");
        self.root
            .readback(&path)
            .map_err(fail)?
            .map(|f| f.metadata().map(|m| m.len()).map_err(fail))
            .transpose()
            .map(|n| n.unwrap_or(0))
    }
    fn reserve_growth(&self, bytes: u64) -> AtlasResult<Box<dyn GrowthReservation + '_>> {
        self.require_writer()?;
        let root = inventory::root(&self.root)?;
        let total = self
            .other_roots_bytes
            .checked_add(root)
            .ok_or_else(|| fail("Atlas home usage overflow"))?;
        let reserved = self.growth.get();
        let maximum = self.scope.registration.cache.directory.as_path();
        if maximum != self.root.root() {
            return Err(fail("cache registration differs from held root"));
        }
        for (resource, used, cap) in [
            ("Atlas root disk", root, 512_000_000u64),
            ("Atlas home disk", total, 2_000_000_000),
        ] {
            if used
                .checked_add(reserved)
                .and_then(|n| n.checked_add(bytes))
                .is_none_or(|n| n > cap)
            {
                return Err(busy(
                    resource,
                    bytes,
                    cap.saturating_sub(used.saturating_add(reserved)),
                ));
            }
        }
        self.growth.set(reserved + bytes);
        Ok(Box::new(Reservation {
            bytes,
            held: &self.growth,
        }))
    }
}
struct Reservation<'a> {
    bytes: u64,
    held: &'a Cell<u64>,
}
impl GrowthReservation for Reservation<'_> {}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.held.set(self.held.get().saturating_sub(self.bytes));
    }
}
fn cache_path(home: &NativeStateFiles, scope: &Scope) -> AtlasResult<PathBuf> {
    let path = home
        .root()
        .join(scope.registration.project.as_str())
        .join(scope.registration.root.as_str());
    if path != scope.registration.cache.directory {
        return Err(fail(
            "cache path must derive from the verified Atlas home/project/root",
        ));
    }
    Ok(path)
}
fn same(a: &File, b: &File) -> AtlasResult<bool> {
    let a = observe_file_revision(a).map_err(fail)?;
    let b = observe_file_revision(b).map_err(fail)?;
    Ok(a.volume == b.volume && a.file == b.file)
}
fn missing(error: &se_proc::StateFileError) -> bool {
    error
        .source
        .as_ref()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
trait CacheFailure {
    fn public_reason(&self) -> String;
}
impl CacheFailure for &str {
    fn public_reason(&self) -> String {
        (*self).into()
    }
}
impl CacheFailure for std::io::Error {
    fn public_reason(&self) -> String {
        self.to_string()
    }
}
impl CacheFailure for SeError {
    fn public_reason(&self) -> String {
        self.body.message()
    }
}
impl CacheFailure for se_proc::StateFileError {
    fn public_reason(&self) -> String {
        format!(
            "{}: {:?}{}",
            self.operation,
            self.code,
            self.source
                .as_ref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        )
    }
}
fn fail(reason: impl CacheFailure) -> SeError {
    let reason = reason.public_reason();
    let mut end = reason.len().min(900);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    SeError::new(Detail::AtlasUnreadable(details::AtlasUnreadable {
        path: "atlas cache".into(),
        reason: reason[..end].into(),
    }))
}
fn busy(resource: &str, requested: u64, available: u64) -> SeError {
    SeError::new(Detail::AtlasResourceBudget(details::AtlasResourceBudget {
        resource: resource.into(),
        requested,
        available,
    }))
}
