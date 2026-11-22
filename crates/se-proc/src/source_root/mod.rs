//! Read-only source custody. Every descendant opens relative to retained native
//! directory handles, without following links. No index, parser or Atlas types.
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
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod watch_shared;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use watch_shared::{NativeWatchAction, NativeWatchEvent, NativeWatchRegistration};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod watch_directory;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub use watch_directory::NativeWatchDirectory;
#[cfg(target_os = "linux")]
mod watch_linux;
#[cfg(target_os = "linux")]
pub use watch_linux::{NativeSourceWatch, NativeWatchEvents};
#[cfg(windows)]
#[path = "../source_watch/windows.rs"]
mod watch_windows;
#[cfg(windows)]
pub use watch_windows::{NativeSourceWatch, NativeWatchEvents};

#[cfg(target_os = "macos")]
#[path = "../source_watch/macos.rs"]
mod watch_macos;
#[cfg(target_os = "macos")]
pub use watch_macos::{NativeSourceWatch, NativeWatchEvents};

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

use se_state_files::NativeObjectKey;
pub use se_state_files::{NativeFileRevision, observe_file_revision};

pub struct NativeSourceRoot {
    path: PathBuf,
    directory: File,
    identity: NativeFileRevision,
}
pub struct NativeRootFile<'a> {
    root: &'a NativeSourceRoot,
    path: String,
    file: File,
    opened: NativeFileRevision,
}
/// Scoped directory-prefix handle cache for one bounded multi-file scan.
/// Reuses verified no-follow directory handles across sibling files in path
/// order, checks root custody on start, absence and finish, and drops all
/// handles as soon as the scan ends.
pub struct NativeSourceScan<'a> {
    root: &'a NativeSourceRoot,
    dirs: Vec<(String, File, NativeObjectKey)>,
}
impl<'a> NativeSourceScan<'a> {
    pub fn open_relative(&mut self, path: &str) -> io::Result<Option<NativeRootFile<'a>>> {
        validate(path)?;
        let (prefix, leaf) = match path.rsplit_once('/') {
            Some((prefix, leaf)) => (Some(prefix), leaf),
            None => (None, path),
        };
        let dir_parts = || prefix.into_iter().flat_map(|prefix| prefix.split('/'));
        let common = self
            .dirs
            .iter()
            .zip(dir_parts())
            .take_while(|((held, ..), want)| held == want)
            .count();
        if common < self.dirs.len() {
            self.verify_cached()?;
            self.dirs.truncate(common);
        }
        for part in dir_parts().skip(common) {
            let parent = self
                .dirs
                .last()
                .map_or(&self.root.directory, |(_, file, _)| file);
            match os::open_component(parent, part, true) {
                Ok((dir, facts)) => {
                    let key = os::object_key(&dir, &facts)?;
                    self.dirs.push((part.to_owned(), dir, key));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // Root replacement is not file absence, even on ENOENT.
                    self.root.check()?;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
        }
        let parent = self
            .dirs
            .last()
            .map_or(&self.root.directory, |(_, file, _)| file);
        let (file, facts) = match os::open_component(parent, leaf, false) {
            Ok(opened) => opened,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.root.check()?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let opened = os::opened_revision(&file, &facts, false)?;
        Ok(Some(NativeRootFile {
            root: self.root,
            path: path.into(),
            file,
            opened,
        }))
    }
    fn verify_cached(&self) -> io::Result<()> {
        if self.dirs.is_empty() {
            return Ok(());
        }
        let mut held: Option<File> = None;
        for (part, _, cached) in &self.dirs {
            let parent = held.as_ref().unwrap_or(&self.root.directory);
            let (fresh, facts) = match os::open_component(parent, part, true) {
                Ok(opened) => opened,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(changed("source directory changed during scan"));
                }
                Err(e) => return Err(e),
            };
            if os::object_key(&fresh, &facts)? != *cached {
                return Err(changed("source directory changed during scan"));
            }
            held = Some(fresh);
        }
        Ok(())
    }
    pub fn finish(self) -> io::Result<()> {
        let verified = self.verify_cached();
        drop(self.dirs);
        verified?;
        self.root.check()
    }
}
impl NativeSourceRoot {
    /// Derive an independently retained root through this registered handle.
    pub fn subroot(&self, path: &str) -> io::Result<Self> {
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
    pub fn directory_handle(&self) -> &File {
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
    /// Empty opens the registered root by name, which has no open-time facts.
    fn open_directory_handle(&self, path: &str) -> io::Result<(File, Option<os::Facts>)> {
        if path.is_empty() {
            os::open_root(&self.path).map(|f| (f, None))
        } else {
            os::open_directory(&self.directory, path).map(|(f, facts)| (f, Some(facts)))
        }
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
    pub fn begin_scan(&self) -> io::Result<NativeSourceScan<'_>> {
        self.check()?;
        Ok(NativeSourceScan {
            root: self,
            dirs: Vec::new(),
        })
    }
    pub fn open_relative(&self, path: &str) -> io::Result<Option<NativeRootFile<'_>>> {
        validate(path)?;
        let opened = os::open_relative(&self.directory, path);
        // Root replacement is not file absence, even if the lookup saw ENOENT.
        self.check()?;
        let (file, facts) = match opened {
            Ok(opened) => opened,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let opened = os::opened_revision(&file, &facts, false)?;
        Ok(Some(NativeRootFile {
            root: self,
            path: path.into(),
            file,
            opened,
        }))
    }
    /// Empty denotes this registered root. Every other component is no-follow.
    /// The cursor streams entries and retains its directory identity; it never
    /// allocates an unbounded filesystem inventory.
    pub fn open_directory(&self, path: &str) -> io::Result<Option<NativeRootDirectory<'_>>> {
        if !path.is_empty() {
            validate(path)?;
        }
        self.check()?;
        let opened = self.open_directory_handle(path);
        self.check()?;
        let (directory, facts) = match opened {
            Ok(opened) => opened,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let identity = match &facts {
            Some(facts) => os::opened_revision(&directory, facts, true)?,
            None => os::revision(&directory, true)?,
        };
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
    /// Identity of the directory retained by this cursor, after name validation.
    pub fn physical_identity(&self) -> io::Result<[u8; 32]> {
        self.revision().map(|revision| revision.root_key())
    }
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
    /// A retained handle keeps its object for life, so only the name is reread.
    pub fn validate_name(&self) -> io::Result<bool> {
        self.root.check()?;
        let (named, facts) = match self.root.open_directory_handle(&self.path) {
            Ok(opened) => opened,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let named = match &facts {
            Some(facts) => os::object_key(&named, facts)?,
            None => os::revision(&named, true)?.object_key(),
        };
        let same = named == self.identity.object_key();
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
    /// Fresh native revision of the retained file.
    pub fn revision(&self) -> io::Result<NativeFileRevision> {
        os::revision(&self.file, false)
    }
    /// Revision read by the no-follow open itself: a before-read baseline
    /// that costs no further query. Compare it with a fresh `revision()`.
    pub fn opened_revision(&self) -> &NativeFileRevision {
        &self.opened
    }
    /// A retained handle keeps its object for life, so only the name is reread.
    pub fn validate_name(&self) -> io::Result<bool> {
        let (named, facts) = match os::open_relative(&self.root.directory, &self.path) {
            Ok(opened) => opened,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.root.check()?;
                return Ok(false);
            }
            Err(e) => return Err(e),
        };
        let same = os::object_key(&named, &facts)? == self.opened.object_key();
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
