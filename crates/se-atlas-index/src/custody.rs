//! The one custody boundary shared by every Atlas read path: the walker and
//! indexer, bounded live scans, and the dirty-file overlay.
//!
//! Each read applies [`crate::policy`] first, then opens the file relative to
//! retained no-follow directory handles (`O_NOFOLLOW` on Unix, reparse-point
//! opens on Windows), so a link anywhere below the registered root is refused
//! rather than followed. Nothing here opens a source file by an OS path, and
//! nothing outside this crate gets the raw root to try.
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

/// The outcome of one guarded read. Denied, refused and absent are distinct
/// facts, and none of them is an error.
#[derive(Debug)]
pub enum GuardedRead {
    /// The private-file policy refused the name; nothing was opened.
    Denied,
    /// No regular file exists at the name.
    Absent,
    /// Custody refused what the name denotes: a link or reparse point, a
    /// device, a directory, or a Windows 8.3 short-name alias.
    Refused,
    /// The file's bytes as read through a retained handle.
    Source(SourceFile),
}

/// The outcome of one guarded open, for callers that stream the file.
pub enum GuardedOpen<'a> {
    Denied,
    Absent,
    Refused,
    /// A regular file opened through retained no-follow handles. Compare its
    /// `opened_revision()` with a fresh `revision()` after reading, and call
    /// `validate_name()` to confirm the name still denotes it.
    File(NativeRootFile<'a>),
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
    root: &'a NativeSourceRoot,
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

    /// The raw root, for this crate's own policy-checked walker only.
    pub(crate) fn native(&self) -> &NativeSourceRoot {
        &self.root
    }

    pub fn physical_root(&self) -> &Path {
        &self.physical
    }

    /// Confirm the registered root still denotes the pinned directory.
    pub fn check(&self) -> io::Result<()> {
        self.root.check()
    }

    pub fn begin_reads(&self) -> io::Result<GuardedReads<'_>> {
        Ok(GuardedReads {
            root: &self.root,
            scan: self.root.begin_scan()?,
        })
    }

    /// Open one file for streaming after the policy and alias checks.
    pub fn open_guarded_file(&self, path: &str) -> io::Result<GuardedOpen<'_>> {
        if policy::file_denied(path) {
            return Ok(GuardedOpen::Denied);
        }
        if short_name_alias(path) {
            return Ok(GuardedOpen::Refused);
        }
        Ok(
            match refusing(&self.root, path, self.root.open_relative(path))? {
                Opened::Absent => GuardedOpen::Absent,
                Opened::Refused => GuardedOpen::Refused,
                Opened::File(file) => GuardedOpen::File(file),
            },
        )
    }

    /// Read one file and confirm afterwards that the name still denotes the
    /// object that was read, for callers outside a scan.
    pub fn read_guarded_file(&self, path: &str) -> io::Result<GuardedRead> {
        let mut file = match self.open_guarded_file(path)? {
            GuardedOpen::Denied => return Ok(GuardedRead::Denied),
            GuardedOpen::Absent => return Ok(GuardedRead::Absent),
            GuardedOpen::Refused => return Ok(GuardedRead::Refused),
            GuardedOpen::File(file) => file,
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
        if short_name_alias(path) {
            return Ok(GuardedRead::Refused);
        }
        match refusing(self.root, path, self.scan.open_relative(path))? {
            Opened::Absent => Ok(GuardedRead::Absent),
            Opened::Refused => Ok(GuardedRead::Refused),
            Opened::File(mut file) => read_retained(&mut file).map(GuardedRead::Source),
        }
    }

    /// Re-verify every retained directory and the root. A scan whose finish
    /// fails must not publish what it read.
    pub fn finish(self) -> io::Result<()> {
        self.scan.finish()
    }
}

enum Opened<'a> {
    Absent,
    Refused,
    File(NativeRootFile<'a>),
}

/// Split custody's refusals (a link, reparse point, device or directory where
/// a file was named, or an invalid name) from real failures. A changed root
/// stays an error.
fn refusing<'a>(
    root: &'a NativeSourceRoot,
    path: &str,
    opened: io::Result<Option<NativeRootFile<'a>>>,
) -> io::Result<Opened<'a>> {
    match opened {
        Ok(None) => Ok(Opened::Absent),
        Ok(Some(file)) => Ok(Opened::File(file)),
        Err(error) if refusal(&error) => Ok(Opened::Refused),
        // Windows reports a directory opened as a file as access denied;
        // only a directory that really opens as one is a refusal.
        Err(error)
            if cfg!(windows)
                && error.kind() == io::ErrorKind::PermissionDenied
                && matches!(root.open_directory(path), Ok(Some(_))) =>
        {
            Ok(Opened::Refused)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn refusal(error: &io::Error) -> bool {
    use io::ErrorKind::{InvalidInput, IsADirectory, NotADirectory};
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return true;
    }
    matches!(error.kind(), InvalidInput | NotADirectory | IsADirectory)
}

/// Windows resolves an 8.3 short name such as `SECRE~1.YAM` or `.SSH~1` to
/// its long name, which would let an alias reach a file the policy denies by
/// its long name. Any component with `~` and digits ending the stem is
/// refused there; other platforms have no aliases.
fn short_name_alias(path: &str) -> bool {
    cfg!(windows) && path.split('/').any(short_name_component)
}

fn short_name_component(part: &str) -> bool {
    part.match_indices('~').any(|(at, _)| {
        let rest = &part.as_bytes()[at + 1..];
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        digits > 0 && rest.get(digits).is_none_or(|b| *b == b'.')
    })
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
