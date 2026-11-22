//! Where a store lives on disk, and the custody of every name it uses.
//!
//! A logical store path `dir/atlas.db` names a family of siblings: epoch
//! databases `atlas.v5.<n>.db` and the pointer `atlas.v5.current`, which holds
//! the current epoch's file name. A rebuild writes a new epoch and flips the
//! pointer by atomic rename, so it never replaces a file a reader may hold
//! open. Superseded epochs are reaped when nothing holds them any more.
//!
//! On Unix the directory is resolved through `se_trusted_path` (only owned
//! symlinked ancestors are admitted) before anything is created or removed,
//! and SQLite opens the database name with NOFOLLOW. On Windows SQLite needs
//! a verbatim path, which NOFOLLOW cannot accompany, so the directory and its
//! ancestors are checked for links and reparse points when the family is
//! located, and every database, sidecar and pointer name before it is used.
use crate::{IndexError, Result};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

/// A pointer holds one short file name.
const POINTER_LIMIT: u64 = 256;

/// The files of one logical store, in a directory that passed custody.
pub(crate) struct StoreFiles {
    dir: PathBuf,
    stem: String,
}

/// What the pointer file says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pointer {
    Missing,
    /// Present but not a well-formed epoch name: rebuild.
    Damaged,
    Epoch(u64),
}

impl StoreFiles {
    pub fn new(path: &Path) -> Result<Self> {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .filter(|stem| !stem.is_empty())
            .ok_or(IndexError::Invalid("store path needs a UTF-8 file name"))?
            .to_owned();
        #[cfg(not(windows))]
        let dir = parent_of(&se_trusted_path::resolve(path)?);
        #[cfg(windows)]
        let dir = {
            let dir = parent_of(path);
            check_directory(&dir)?;
            dir
        };
        Ok(Self { dir, stem })
    }

    pub fn epoch_path(&self, epoch: u64) -> PathBuf {
        self.dir.join(self.epoch_name(epoch))
    }

    fn epoch_name(&self, epoch: u64) -> String {
        format!("{}.v5.{epoch}.db", self.stem)
    }

    fn pointer_path(&self) -> PathBuf {
        self.dir.join(format!("{}.v5.current", self.stem))
    }

    fn parse_epoch(&self, name: &str) -> Option<u64> {
        let digits = name
            .strip_prefix(&self.stem)?
            .strip_prefix(".v5.")?
            .strip_suffix(".db")?;
        let canonical = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        canonical.then(|| digits.parse().ok()).flatten()
    }

    pub fn pointer(&self) -> Result<Pointer> {
        let path = self.pointer_path();
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Pointer::Missing),
            Err(error) => return Err(error.into()),
            Ok(meta) if is_link(&meta) || !meta.is_file() => return Err(refused().into()),
            Ok(_) => {}
        }
        let mut text = String::new();
        match fs::File::open(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Pointer::Missing),
            Err(error) => return Err(error.into()),
            Ok(file) => {
                if file.take(POINTER_LIMIT).read_to_string(&mut text).is_err() {
                    return Ok(Pointer::Damaged);
                }
            }
        }
        Ok(self
            .parse_epoch(text.trim_end())
            .map_or(Pointer::Damaged, Pointer::Epoch))
    }

    /// Epoch numbers present in the directory, in no particular order.
    fn epochs(&self) -> io::Result<Vec<u64>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if let Some(epoch) = entry.file_name().to_str().and_then(|n| self.parse_epoch(n)) {
                out.push(epoch);
            }
        }
        Ok(out)
    }

    /// An epoch number no file and no pointer has used.
    pub fn next_epoch(&self) -> Result<u64> {
        let pointed = match self.pointer()? {
            Pointer::Epoch(epoch) => epoch,
            _ => 0,
        };
        let highest = self.epochs()?.into_iter().max().unwrap_or(0);
        pointed
            .max(highest)
            .checked_add(1)
            .ok_or(IndexError::Corrupt("store epoch counter overflow"))
    }

    /// Point readers at `epoch` with one atomic rename.
    pub fn publish(&self, epoch: u64) -> Result<()> {
        let pointer = self.pointer_path();
        check_leaf(&pointer)?;
        let staged = self.dir.join(format!(
            "{}.v5.current.{}.tmp",
            self.stem,
            std::process::id()
        ));
        check_leaf(&staged)?;
        remove_files([staged.clone()])?;
        let written = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged)?;
            file.write_all(self.epoch_name(epoch).as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&staged, &pointer)
        })();
        if let Err(error) = written {
            let _ = fs::remove_file(&staged);
            return Err(error.into());
        }
        #[cfg(unix)]
        if let Ok(dir) = fs::File::open(&self.dir) {
            // Durability of the rename; a failure here loses nothing published.
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Remove every epoch except `keep`. A file still held open by a draining
    /// reader cannot be removed on Windows; it is left for the next reap.
    pub fn reap(&self, keep: u64) {
        let Ok(epochs) = self.epochs() else {
            return;
        };
        for epoch in epochs.into_iter().filter(|epoch| *epoch != keep) {
            let db = self.epoch_path(epoch);
            if check_leaves(&db).is_err() {
                continue;
            }
            let [wal, shm] = sidecars(&db);
            for file in [wal, shm, db] {
                let _ = fs::remove_file(file);
            }
        }
    }
}

fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

pub(crate) fn sidecars(path: &Path) -> [PathBuf; 2] {
    let with = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    [with("-wal"), with("-shm")]
}

pub(crate) fn remove_files(paths: impl IntoIterator<Item = PathBuf>) -> io::Result<()> {
    for file in paths {
        match fs::remove_file(&file) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

/// Refuse a database whose name or sidecars are links, reparse points or
/// anything but regular files. Absent names are fine: SQLite creates them.
pub(crate) fn check_leaves(db: &Path) -> io::Result<()> {
    let [wal, shm] = sidecars(db);
    for path in [db, wal.as_path(), shm.as_path()] {
        check_leaf(path)?;
    }
    Ok(())
}

fn check_leaf(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(meta) if is_link(&meta) || !meta.is_file() => Err(refused()),
        Ok(_) => Ok(()),
    }
}

/// The directory and every ancestor must be real directories, not links,
/// junctions or other reparse points.
#[cfg(windows)]
fn check_directory(dir: &Path) -> io::Result<()> {
    for ancestor in dir.ancestors().filter(|a| !a.as_os_str().is_empty()) {
        let meta = fs::symlink_metadata(ancestor)?;
        if is_link(&meta) || !meta.is_dir() {
            return Err(refused());
        }
    }
    Ok(())
}

fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "atlas store names must be regular files in real directories; links and reparse points are refused",
    )
}
