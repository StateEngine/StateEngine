//! The one custody boundary shared by every Atlas read path: the walker and
//! indexer, bounded live scans, and the dirty-file overlay.
//!
//! Each read applies [`crate::policy`] first, then opens the file relative to
//! retained no-follow directory handles (`O_NOFOLLOW` on Unix, reparse-point
//! opens on Windows), so a link anywhere below the registered root is refused
//! rather than followed. Nothing here opens a source file by an OS path.
use crate::policy;
use se_proc::{NativeFileRevision, NativeRootFile, NativeSourceRoot, NativeSourceScan};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
};

/// Files up to this size are read whole.
pub const FULL_READ_LIMIT: u64 = 1 << 20;
/// Larger files contribute only this many leading bytes.
pub const PREFIX_READ_LIMIT: usize = 64 * 1024;

/// A registered physical source root. Construct it once per index and share it
/// across worker threads; each thread opens its own [`GuardedReads`].
pub struct IndexSourceRoot {
    root: NativeSourceRoot,
    physical: PathBuf,
}

/// The outcome of one guarded read. Denied and absent are distinct facts, and
/// neither is an error.
#[derive(Debug)]
pub enum GuardedRead {
    /// The private-file policy refused the name; nothing was opened.
    Denied,
    /// No regular file exists at the name.
    Absent,
    /// The file's bytes as read through a retained handle.
    Source(SourceFile),
}

/// Bytes and native facts of one regular file.
#[derive(Debug)]
pub struct SourceFile {
    pub bytes: Vec<u8>,
    /// Size reported by the opened handle, which may exceed `bytes.len()`.
    pub size: u64,
    pub mtime_ns: i64,
    /// Volume and file id of the opened object.
    pub ident: [u8; 32],
    /// Only the first [`PREFIX_READ_LIMIT`] bytes were read.
    pub prefix_only: bool,
}

/// A bounded run of reads that reuses verified directory handles across
/// sibling files. Read paths in sorted order for the best reuse.
pub struct GuardedReads<'a> {
    scan: NativeSourceScan<'a>,
}

impl IndexSourceRoot {
    /// Pin an absolute physical root supplied by the authorized caller.
    pub fn open(physical_root: &Path) -> io::Result<Self> {
        Ok(Self {
            root: NativeSourceRoot::open(physical_root)?,
            physical: physical_root.to_path_buf(),
        })
    }

    pub fn native(&self) -> &NativeSourceRoot {
        &self.root
    }

    pub fn physical_root(&self) -> &Path {
        &self.physical
    }

    pub fn begin_reads(&self) -> io::Result<GuardedReads<'_>> {
        Ok(GuardedReads {
            scan: self.root.begin_scan()?,
        })
    }

    /// Read one file and confirm afterwards that the name still denotes the
    /// object that was read, for callers outside a scan.
    pub fn read_guarded_file(&self, path: &str) -> io::Result<GuardedRead> {
        if policy::file_denied(path) {
            return Ok(GuardedRead::Denied);
        }
        let Some(mut file) = self.root.open_relative(path)? else {
            return Ok(GuardedRead::Absent);
        };
        let source = read_retained(&mut file)?;
        if !file.validate_name()? {
            return Err(changed());
        }
        Ok(GuardedRead::Source(source))
    }
}

impl GuardedReads<'_> {
    pub fn read(&mut self, path: &str) -> io::Result<GuardedRead> {
        if policy::file_denied(path) {
            return Ok(GuardedRead::Denied);
        }
        match self.scan.open_relative(path)? {
            None => Ok(GuardedRead::Absent),
            Some(mut file) => read_retained(&mut file).map(GuardedRead::Source),
        }
    }

    /// Re-verify every retained directory and the root. A scan whose finish
    /// fails must not publish what it read.
    pub fn finish(self) -> io::Result<()> {
        self.scan.finish()
    }
}

fn read_retained(file: &mut NativeRootFile<'_>) -> io::Result<SourceFile> {
    let opened = file.opened_revision();
    let mut bytes = Vec::new();
    let prefix_only = if opened.size > FULL_READ_LIMIT {
        file.take(PREFIX_READ_LIMIT as u64)
            .read_to_end(&mut bytes)?;
        true
    } else {
        bytes.reserve_exact(opened.size as usize);
        file.take(FULL_READ_LIMIT + 1).read_to_end(&mut bytes)?;
        bytes.len() as u64 > FULL_READ_LIMIT
    };
    if prefix_only {
        bytes.truncate(PREFIX_READ_LIMIT);
    }
    let after = file.revision()?;
    if !same_content_facts(&opened, &after) {
        return Err(changed());
    }
    let mut ident = [0u8; 32];
    ident[..16].copy_from_slice(&opened.volume);
    ident[16..].copy_from_slice(&opened.file);
    Ok(SourceFile {
        bytes,
        size: opened.size,
        mtime_ns: i64::try_from(opened.mtime_unix_nanos).unwrap_or(i64::MAX),
        ident,
        prefix_only,
    })
}

fn same_content_facts(before: &NativeFileRevision, after: &NativeFileRevision) -> bool {
    before.same_object(after)
        && before.size == after.size
        && before.mtime_unix_nanos == after.mtime_unix_nanos
}

fn changed() -> io::Error {
    io::Error::other("source file changed during a guarded read; retry")
}
