//! File identity observations that do not disturb SQLite's process-wide locks.
use std::{io, path::Path};
mod sqlite;

/// The native object behind a regular file name, independent of its contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFileIdentity {
    volume: [u8; 16],
    file: [u8; 16],
}

impl NativeFileIdentity {
    /// Observe the final component without following symbolic links or reparse
    /// points. Unix uses metadata only: closing an ordinary descriptor to an
    /// active SQLite inode would release this process's POSIX record locks.
    pub fn observe(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let metadata = std::fs::symlink_metadata(path)?;
            Self::from_metadata(&metadata)
        }
        #[cfg(windows)]
        {
            use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
                FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            let file = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            // This rejects directories, reparse points and non-disk handles.
            let revision = crate::observe_file_revision(&file)?;
            Ok(Self {
                volume: revision.volume,
                file: revision.file,
            })
        }
    }
    /// A directory's native object, without following a final link or
    /// reparse point.
    pub fn observe_directory(path: &Path) -> io::Result<Self> {
        Self::observe_kind(path, Kind::Directory)
    }
    /// A local (AF_UNIX) socket's native object. On Windows the name must be
    /// the AF_UNIX reparse point itself, never another kind of reparse point.
    pub fn observe_local_socket(path: &Path) -> io::Result<Self> {
        Self::observe_kind(path, Kind::LocalSocket)
    }
    /// A stable form for records: volume then file, 16 bytes each.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&self.volume);
        bytes[16..].copy_from_slice(&self.file);
        bytes
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut volume = [0; 16];
        let mut file = [0; 16];
        volume.copy_from_slice(&bytes[..16]);
        file.copy_from_slice(&bytes[16..]);
        Self { volume, file }
    }
    fn observe_kind(path: &Path, kind: Kind) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let metadata = std::fs::symlink_metadata(path)?;
            let matches = match kind {
                Kind::Directory => metadata.is_dir(),
                Kind::LocalSocket => metadata.file_type().is_socket(),
            };
            if !matches {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, kind.expected()));
            }
            let mut volume = [0; 16];
            let mut file = [0; 16];
            volume[..8].copy_from_slice(&metadata.dev().to_be_bytes());
            file[..8].copy_from_slice(&metadata.ino().to_be_bytes());
            Ok(Self { volume, file })
        }
        #[cfg(windows)]
        {
            windows::observe(path, kind)
        }
    }
    #[cfg(unix)]
    fn from_metadata(metadata: &std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "regular file without symbolic links required",
            ));
        }
        let mut volume = [0; 16];
        let mut file = [0; 16];
        volume[..8].copy_from_slice(&metadata.dev().to_be_bytes());
        file[..8].copy_from_slice(&metadata.ino().to_be_bytes());
        Ok(Self { volume, file })
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Directory,
    LocalSocket,
}
impl Kind {
    fn expected(self) -> &'static str {
        match self {
            Self::Directory => "a directory without a final link or reparse point",
            Self::LocalSocket => "a local socket without a final link",
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{Kind, NativeFileIdentity};
    use std::{
        fs::OpenOptions,
        io,
        mem::{size_of, zeroed},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx,
        },
        System::SystemServices::IO_REPARSE_TAG_AF_UNIX,
    };

    pub(super) fn observe(path: &Path, kind: Kind) -> io::Result<NativeFileIdentity> {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        // SAFETY: POD output initialized before its exact sized query on the
        // retained handle.
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
            return Err(io::Error::new(io::ErrorKind::InvalidInput, kind.expected()));
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
        let mut volume = [0; 16];
        volume[..8].copy_from_slice(&id.VolumeSerialNumber.to_be_bytes());
        Ok(NativeFileIdentity {
            volume,
            file: id.FileId.Identifier,
        })
    }
}
