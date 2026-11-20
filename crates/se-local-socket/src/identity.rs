//! Native identity of a local socket and of the private directory it lives in,
//! and removal that touches only the object a caller recorded.
use std::{io, path::Path};

/// A native object: volume then file, 16 bytes each. On Unix the device and
/// inode; on Windows the volume serial and 128-bit file index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId([u8; 32]);

/// What an exact removal found at the name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    Removed,
    Absent,
}

#[derive(Clone, Copy)]
enum Kind {
    Directory,
    LocalSocket,
}

fn unexpected(kind: Kind) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        match kind {
            Kind::Directory => "a directory without a final link or reparse point",
            Kind::LocalSocket => "a local socket without a final link",
        },
    )
}

fn replaced() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the name now holds another object; it is preserved",
    )
}

impl ObjectId {
    /// A directory, without following a final link or reparse point.
    pub fn directory(path: &Path) -> io::Result<Self> {
        observe(path, Kind::Directory)
    }
    /// A local socket. On Windows the name must be the AF_UNIX reparse point
    /// itself, never another kind of reparse point.
    pub fn local_socket(path: &Path) -> io::Result<Self> {
        observe(path, Kind::LocalSocket)
    }
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Remove an empty directory only while its name still holds `self`.
    pub fn remove_directory(&self, path: &Path) -> io::Result<Removal> {
        remove(path, Kind::Directory, self)
    }
    /// Remove a local socket only while its name still holds `self`.
    pub fn remove_local_socket(&self, path: &Path) -> io::Result<Removal> {
        remove(path, Kind::LocalSocket, self)
    }
}

#[cfg(unix)]
fn observe(path: &Path, kind: Kind) -> io::Result<ObjectId> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let matches = match kind {
        Kind::Directory => metadata.is_dir(),
        Kind::LocalSocket => metadata.file_type().is_socket(),
    };
    if !matches {
        return Err(unexpected(kind));
    }
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&metadata.dev().to_be_bytes());
    bytes[16..24].copy_from_slice(&metadata.ino().to_be_bytes());
    Ok(ObjectId(bytes))
}

/// Unix has no removal by descriptor, so this compares and then unlinks.
#[cfg(unix)]
fn remove(path: &Path, kind: Kind, expected: &ObjectId) -> io::Result<Removal> {
    let observed = match observe(path, kind) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Removal::Absent),
        other => other?,
    };
    if &observed != expected {
        return Err(replaced());
    }
    match kind {
        Kind::Directory => std::fs::remove_dir(path)?,
        Kind::LocalSocket => std::fs::remove_file(path)?,
    }
    Ok(Removal::Removed)
}

#[cfg(windows)]
use windows::{observe, remove};

#[cfg(windows)]
mod windows {
    use super::{Kind, ObjectId, Removal, replaced, unexpected};
    use std::{
        fs::{File, OpenOptions},
        io,
        mem::{size_of, zeroed},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx,
        },
        System::SystemServices::IO_REPARSE_TAG_AF_UNIX,
    };

    fn open(path: &Path, access: u32) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }

    pub(super) fn observe(path: &Path, kind: Kind) -> io::Result<ObjectId> {
        identify(&open(path, FILE_READ_ATTRIBUTES)?, kind)
    }

    /// Check and dispose through one DELETE-capable handle, so the object
    /// removed is the object compared.
    pub(super) fn remove(path: &Path, kind: Kind, expected: &ObjectId) -> io::Result<Removal> {
        let file = match open(path, FILE_READ_ATTRIBUTES | DELETE) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Removal::Absent),
            other => other?,
        };
        if &identify(&file, kind)? != expected {
            return Err(replaced());
        }
        se_proc::remove_held(&file, path).map_err(|e| {
            e.source
                .unwrap_or_else(|| io::Error::other("native removal failed"))
        })?;
        Ok(Removal::Removed)
    }

    fn identify(file: &File, kind: Kind) -> io::Result<ObjectId> {
        // SAFETY: POD output initialized before its exact sized query.
        let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { zeroed() };
        // SAFETY: retained handle and a correctly sized writable output.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let directory = tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let reparse = tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let matches = match kind {
            Kind::Directory => directory && !reparse,
            Kind::LocalSocket => !directory && reparse && tag.ReparseTag == IO_REPARSE_TAG_AF_UNIX,
        };
        if !matches {
            return Err(unexpected(kind));
        }
        // SAFETY: POD output initialized before its exact sized query.
        let mut id: FILE_ID_INFO = unsafe { zeroed() };
        // SAFETY: retained handle and a correctly sized writable output.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&id.VolumeSerialNumber.to_be_bytes());
        bytes[16..].copy_from_slice(&id.FileId.Identifier);
        Ok(ObjectId(bytes))
    }
}
