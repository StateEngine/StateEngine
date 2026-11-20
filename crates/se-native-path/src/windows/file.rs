//! Raw file metadata and stable native file identifiers.
use std::{
    fs::File,
    io,
    mem::{size_of, zeroed},
    os::windows::io::AsRawHandle,
};
use windows_sys::Win32::Storage::FileSystem::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileId {
    pub volume: u64,
    pub index: [u8; 16],
}
pub fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: native POD is initialized before its exact writable query.
    let mut info = unsafe { zeroed() };
    // SAFETY: retained file and correctly typed writable metadata output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}
pub fn file_id(file: &File) -> io::Result<FileId> {
    // SAFETY: native POD is initialized before its exact sized query.
    let mut id: FILE_ID_INFO = unsafe { zeroed() };
    // SAFETY: retained file and aligned writable FileIdInfo output of the documented size.
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
    Ok(FileId {
        volume: id.VolumeSerialNumber,
        index: id.FileId.Identifier,
    })
}
