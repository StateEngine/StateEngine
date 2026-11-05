//! Read-only source custody. Every descendant opens relative to retained native
//! directory handles, without following links. No index, parser or Atlas types.
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
use windows as os;
#[cfg(unix)]
mod unix_entries;
#[cfg(windows)]
mod windows_entries;
#[cfg(unix)]
use unix_entries as entries;
#[cfg(windows)]
use windows_entries as entries;
#[cfg(target_os = "linux")]
mod watch_linux;
#[cfg(target_os = "linux")]
pub use watch_linux::{
    NativeSourceWatch, NativeWatchAction, NativeWatchDirectory, NativeWatchEvent,
    NativeWatchEvents, NativeWatchRegistration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSourceKind {
    File,
    Directory,
    Link,
    Other,
}
#[derive(Debug)]
pub struct NativeSourceEntry {
    pub name: std::ffi::OsString,
    pub kind: NativeSourceKind,
}
pub struct NativeRootDirectory<'a> {
    root: &'a NativeSourceRoot,
    path: String,
    directory: File,
    identity: NativeFileRevision,
    entries: entries::Cursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFileRevision {
    pub volume: [u8; 16],
    pub file: [u8; 16],
    pub size: u64,
    pub mtime_unix_nanos: i128,
    pub ctime_unix_nanos: Option<i128>,
}
/// Generic native facts for an already retained regular file. Ownership and
/// permission policy belong to the caller's file port.
pub fn observe_file_revision(file: &File) -> io::Result<NativeFileRevision> {
    os::revision(file, false)
}
impl NativeFileRevision {
    fn same_object(&self, other: &Self) -> bool {
        self.volume == other.volume && self.file == other.file
    }
    fn root_key(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.volume);
        hash.update(self.file);
        hash.finalize().into()
    }
}

pub struct NativeSourceRoot {
    path: PathBuf,
    directory: File,
    identity: NativeFileRevision,
}
pub struct NativeRootFile<'a> {
    root: &'a NativeSourceRoot,
    path: String,
    file: File,
}
impl NativeSourceRoot {
    /// Derive an independently retained root through this registered handle.
    pub(crate) fn subroot(&self, path: &str) -> io::Result<Self> {
        validate(path)?;
        let pin = self
            .open_directory(path)?
            .ok_or_else(|| changed("source subroot is absent"))?;
        let root = Self {
            path: self.path.join(path),
            directory: pin.directory,
            identity: pin.identity,
        };
        root.check()?;
        self.check()?;
        Ok(root)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn directory_handle(&self) -> &File {
        &self.directory
    }
    /// The authorized host supplies the physical root. Ancestors above this
    /// boundary may resolve normally; the root itself and descendants do not.
    pub fn open(physical_root: &Path) -> io::Result<Self> {
        if !physical_root.is_absolute() {
            return Err(invalid("source root must be absolute"));
        }
        let directory = os::open_root(physical_root)?;
        let identity = os::revision(&directory, true)?;
        let root = Self {
            path: physical_root.into(),
            directory,
            identity,
        };
        root.check()?;
        Ok(root)
    }
    pub fn physical_identity(&self) -> io::Result<[u8; 32]> {
        self.check()?;
        Ok(self.identity.root_key())
    }
    pub fn check(&self) -> io::Result<()> {
        let named = os::open_root(&self.path)?;
        if !self.identity.same_object(&os::revision(&named, true)?)
            || !self
                .identity
                .same_object(&os::revision(&self.directory, true)?)
        {
            return Err(changed("registered physical source root changed; rebind"));
        }
        Ok(())
    }
    pub fn open_relative(&self, path: &str) -> io::Result<Option<NativeRootFile<'_>>> {
        validate(path)?;
        self.check()?;
        let opened = os::open_relative(&self.directory, path);
        // Root replacement is not file absence, even if the lookup saw ENOENT.
        self.check()?;
        let file = match opened {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        os::revision(&file, false)?;
        let pin = NativeRootFile {
            root: self,
            path: path.into(),
            file,
        };
        if !pin.validate_name()? {
            return Err(changed("source name changed during open"));
        }
        Ok(Some(pin))
    }
    /// Empty denotes this registered root. Every other component is no-follow.
    /// The cursor streams entries and retains its directory identity; it never
    /// allocates an unbounded filesystem inventory.
    pub fn open_directory(&self, path: &str) -> io::Result<Option<NativeRootDirectory<'_>>> {
        if !path.is_empty() {
            validate(path)?;
        }
        self.check()?;
        let opened = if path.is_empty() {
            os::open_root(&self.path)
        } else {
            os::open_directory(&self.directory, path)
        };
        self.check()?;
        let directory = match opened {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let identity = os::revision(&directory, true)?;
        let entries = entries::Cursor::new(&directory)?;
        let cursor = NativeRootDirectory {
            root: self,
            path: path.into(),
            directory,
            identity,
            entries,
        };
        if !cursor.validate_name()? {
            return Err(changed("source directory changed during open"));
        }
        Ok(Some(cursor))
    }
}
impl NativeRootDirectory<'_> {
    /// Read at most 128 entries from the retained stream, validating its name on
    /// both sides of the batch. An empty batch means observed end of stream.
    pub fn next_batch(&mut self) -> io::Result<Vec<NativeSourceEntry>> {
        if !self.validate_name()? {
            return Err(changed("source directory was replaced before enumeration"));
        }
        let mut batch = Vec::new();
        for _ in 0..128 {
            let Some(entry) = self.entries.next()? else {
                break;
            };
            batch.push(entry);
        }
        if !self.validate_name()? {
            return Err(changed("source directory was replaced during enumeration"));
        }
        Ok(batch)
    }
    /// Native revision of this retained directory, including namespace timestamps.
    pub fn revision(&self) -> io::Result<NativeFileRevision> {
        if !self.validate_name()? {
            return Err(changed("source directory name changed"));
        }
        os::revision(&self.directory, true)
    }
    pub fn validate_name(&self) -> io::Result<bool> {
        self.root.check()?;
        let opened = if self.path.is_empty() {
            os::open_root(&self.root.path)
        } else {
            os::open_directory(&self.root.directory, &self.path)
        };
        let named = match opened {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let same = self.identity.same_object(&os::revision(&named, true)?)
            && self
                .identity
                .same_object(&os::revision(&self.directory, true)?);
        self.root.check()?;
        Ok(same)
    }
    pub fn next_entry(&mut self) -> io::Result<Option<NativeSourceEntry>> {
        if !self.validate_name()? {
            return Err(changed("source directory was replaced before enumeration"));
        }
        let entry = self.entries.next()?;
        if !self.validate_name()? {
            return Err(changed("source directory was replaced during enumeration"));
        }
        Ok(entry)
    }
}
impl NativeRootFile<'_> {
    pub fn revision(&self) -> io::Result<NativeFileRevision> {
        os::revision(&self.file, false)
    }
    pub fn validate_name(&self) -> io::Result<bool> {
        self.root.check()?;
        let named = match os::open_relative(&self.root.directory, &self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let same = os::revision(&named, false)?.same_object(&self.revision()?);
        self.root.check()?;
        Ok(same)
    }
}
impl Read for NativeRootFile<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}
impl Seek for NativeRootFile<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}
fn validate(path: &str) -> io::Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains(['\0', '\\', ':'])
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(invalid(
            "bounded slash-separated root-relative source path required",
        ));
    }
    Ok(())
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}
fn changed(reason: &'static str) -> io::Error {
    io::Error::other(reason)
}
