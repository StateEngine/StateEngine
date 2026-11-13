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
