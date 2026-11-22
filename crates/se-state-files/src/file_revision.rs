//! Generic native file revision facts for an already retained regular file or directory.
use std::{fs::File, io};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFileRevision {
    pub volume: [u8; 16],
    pub file: [u8; 16],
    pub size: u64,
    pub mtime_unix_nanos: i128,
    pub ctime_unix_nanos: Option<i128>,
}

/// Volume and file id of one native object, laid out as in [`NativeFileRevision`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeObjectKey {
    pub volume: [u8; 16],
    pub file: [u8; 16],
}

impl NativeFileRevision {
    pub fn same_object(&self, other: &Self) -> bool {
        self.volume == other.volume && self.file == other.file
    }

    pub fn object_key(&self) -> NativeObjectKey {
        NativeObjectKey {
            volume: self.volume,
            file: self.file,
        }
    }

    pub fn root_key(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(self.volume);
        hash.update(self.file);
        hash.finalize().into()
    }
}

/// Generic native facts for an already retained regular file. Ownership and
/// permission policy belong to the caller's file port.
pub fn observe_file_revision(file: &File) -> io::Result<NativeFileRevision> {
    observe_file_revision_for(file, false)
}

/// Generic native facts for an already retained regular file or directory.
#[cfg(unix)]
pub fn observe_file_revision_for(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    file_revision_from_metadata(&file.metadata()?, directory)
}

/// The same facts from metadata the caller already read from its retained handle.
#[cfg(unix)]
pub fn file_revision_from_metadata(
    m: &std::fs::Metadata,
    directory: bool,
) -> io::Result<NativeFileRevision> {
    use std::os::unix::fs::MetadataExt;
    if (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "regular source file or directory required; links and devices refused",
        ));
    }
    let key = object_key_from_metadata(m);
    Ok(NativeFileRevision {
        volume: key.volume,
        file: key.file,
        size: m.len(),
        mtime_unix_nanos: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        ctime_unix_nanos: Some(i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec())),
    })
}

/// Object identity from metadata the caller already read from its retained handle.
#[cfg(unix)]
pub fn object_key_from_metadata(m: &std::fs::Metadata) -> NativeObjectKey {
    use std::os::unix::fs::MetadataExt;
    let mut key = NativeObjectKey {
        volume: [0; 16],
        file: [0; 16],
    };
    key.volume[..8].copy_from_slice(&m.dev().to_be_bytes());
    key.file[..8].copy_from_slice(&m.ino().to_be_bytes());
    key
}

/// Generic native facts for an already retained regular file or directory.
#[cfg(windows)]
pub fn observe_file_revision_for(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};
    let info = se_native_path::windows::file::file_information(file)?;
    // SAFETY: immutable native handle query, no retained external pointers.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(refused());
    }
    file_revision_from_information(file, &info, directory)
}

/// The same facts from this handle's own `GetFileInformationByHandle` result.
/// The caller has already confirmed the handle is a disk file.
#[cfg(windows)]
pub fn file_revision_from_information(
    file: &File,
    info: &windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
    directory: bool,
) -> io::Result<NativeFileRevision> {
    use std::{
        mem::{size_of, zeroed},
        os::windows::io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::*;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(refused());
    }
    let key = observe_object_key(file)?;
    // SAFETY: all-integer native output initialized before the metadata query.
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    // SAFETY: retained handle, initialized output and its exact native size.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let unix_nanos = |ticks: i64| (i128::from(ticks) - 116_444_736_000_000_000) * 100;
    Ok(NativeFileRevision {
        volume: key.volume,
        file: key.file,
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        mtime_unix_nanos: unix_nanos(basic.LastWriteTime),
        ctime_unix_nanos: Some(unix_nanos(basic.ChangeTime)),
    })
}

/// Object identity of one retained handle: a single 128-bit file id query.
#[cfg(windows)]
pub fn observe_object_key(file: &File) -> io::Result<NativeObjectKey> {
    let id = se_native_path::windows::file::file_id(file)?;
    let mut volume = [0; 16];
    volume[..8].copy_from_slice(&id.volume.to_be_bytes());
    Ok(NativeObjectKey {
        volume,
        file: id.index,
    })
}

#[cfg(windows)]
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "regular non-reparse source file/directory required",
    )
}
