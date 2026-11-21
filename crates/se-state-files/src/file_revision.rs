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

impl NativeFileRevision {
    pub fn same_object(&self, other: &Self) -> bool {
        self.volume == other.volume && self.file == other.file
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
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    if (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "regular source file or directory required; links and devices refused",
        ));
    }
    let mut volume = [0; 16];
    let mut id = [0; 16];
    volume[..8].copy_from_slice(&m.dev().to_be_bytes());
    id[..8].copy_from_slice(&m.ino().to_be_bytes());
    Ok(NativeFileRevision {
        volume,
        file: id,
        size: m.len(),
        mtime_unix_nanos: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        ctime_unix_nanos: Some(i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec())),
    })
}

/// Generic native facts for an already retained regular file or directory.
#[cfg(windows)]
pub fn observe_file_revision_for(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    use std::{
        mem::{size_of, zeroed},
        os::windows::io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::*;
    let info = se_native_path::windows::file::file_information(file)?;
    // SAFETY: immutable native handle query, no retained external pointers.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "regular non-reparse source file/directory required",
        ));
    }
    let id = se_native_path::windows::file::file_id(file)?;
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
    let mut volume = [0; 16];
    volume[..8].copy_from_slice(&id.volume.to_be_bytes());
    let unix_nanos = |ticks: i64| (i128::from(ticks) - 116_444_736_000_000_000) * 100;
    Ok(NativeFileRevision {
        volume,
        file: id.index,
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        mtime_unix_nanos: unix_nanos(basic.LastWriteTime),
        ctime_unix_nanos: Some(unix_nanos(basic.ChangeTime)),
    })
}
