//! Shared Windows query primitives. Callers retain their handles/token buffers;
//! typed adapters add their own operation context without copying native walks.
pub(crate) mod console;
pub(crate) mod job;
pub(crate) use se_native_ipc::windows_process::{
    Error, acl, allocation, attributes, handle, parent, parents, process_sid, process_start, query,
    sid_text,
};
use std::{fs::File, io, os::windows::io::AsRawHandle, path::Path};
use windows_sys::Win32::Storage::FileSystem::*;

type Result<T> = std::result::Result<T, Error>;
fn last(operation: &'static str) -> Error {
    Error {
        operation,
        source: io::Error::last_os_error(),
    }
}
fn invalid(operation: &'static str, reason: &'static str) -> Error {
    Error {
        operation,
        source: io::Error::new(io::ErrorKind::InvalidData, reason),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    #[serde(with = "crate::checkpoint::decimal::u64")]
    pub volume: u64,
    pub index: [u8; 16],
}
pub(crate) fn open_image(path: &Path, delete: bool) -> Result<File> {
    let path = crate::state_files::windows::wide(path).map_err(|e| Error {
        operation: "encode native image path",
        source: io::Error::other(e),
    })?;
    let file = open_image_file(&path, delete).map_err(|source| Error {
        operation: "pin native image",
        source,
    })?;
    file_identity(&file)?;
    Ok(file)
}
pub(crate) fn file_identity(file: &File) -> Result<FileIdentity> {
    let info = file_information(file).map_err(|source| Error {
        operation: "read native file identity",
        source,
    })?;
    // SAFETY: immutable type query on the retained file object.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(invalid(
            "read native file identity",
            "single-link regular disk file required",
        ));
    }
    file_id(file).map_err(|source| Error {
        operation: "read 128-bit native file identity",
        source,
    })
}

pub(crate) use se_native_path::windows::file::{file_information, open_image_file};
pub(crate) fn file_id(file: &File) -> io::Result<FileIdentity> {
    let id = se_native_path::windows::file::file_id(file)?;
    Ok(FileIdentity {
        volume: id.volume,
        index: id.index,
    })
}
