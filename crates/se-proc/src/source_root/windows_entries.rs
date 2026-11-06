//! Enumerate a retained directory handle, never an ambient FindFirstFile path.
use super::*;
use std::{
    mem::size_of,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, GetLastError},
    Storage::FileSystem::*,
};
pub(super) struct Cursor {
    file: File,
    buffer: Box<[u64; 2048]>,
    offset: Option<usize>,
    restart: bool,
    ended: bool,
}
impl Cursor {
    pub(super) fn new(file: &File) -> io::Result<Self> {
        Ok(Self {
            file: file.try_clone()?,
            buffer: Box::new([0; 2048]),
            offset: None,
            restart: true,
            ended: false,
        })
    }
    pub(super) fn next(&mut self) -> io::Result<Option<NativeSourceEntry>> {
        loop {
            if self.ended {
                return Ok(None);
            }
            if self.offset.is_none() {
                // SAFETY: aligned, exclusively owned 16 KiB output and a live
                // directory handle with FILE_LIST_DIRECTORY access.
                let ok = unsafe {
                    GetFileInformationByHandleEx(
                        self.file.as_raw_handle(),
                        if self.restart {
                            FileIdBothDirectoryRestartInfo
                        } else {
                            FileIdBothDirectoryInfo
                        },
                        self.buffer.as_mut_ptr().cast(),
                        16384,
                    )
                };
                self.restart = false;
                if ok == 0 {
                    // SAFETY: reads the native thread-local last-error value.
                    let error = unsafe { GetLastError() };
                    if error == ERROR_NO_MORE_FILES {
                        self.ended = true;
                        return Ok(None);
                    }
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                self.offset = Some(0);
            }
            let offset = self
                .offset
                .take()
                .ok_or_else(|| invalid("directory cursor offset absent"))?;
            if offset % 8 != 0 || offset + size_of::<FILE_ID_BOTH_DIR_INFO>() > 16384 {
                return Err(invalid("invalid native directory row offset"));
            }
            // SAFETY: checked aligned prefix in the OS-filled exclusive buffer.
            let row = unsafe {
                &*(self
                    .buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let filename = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName) + offset;
            let length = row.FileNameLength as usize;
            if !length.is_multiple_of(2) || length == 0 || filename + length > 16384 {
                return Err(invalid("invalid native directory filename extent"));
            }
            // SAFETY: checked bounded UTF-16 filename within the filled row.
            let units = unsafe {
                std::slice::from_raw_parts(
                    self.buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(filename)
                        .cast::<u16>(),
                    length / 2,
                )
            };
            let name = std::ffi::OsString::from_wide(units);
            if row.NextEntryOffset != 0 {
                let next = offset
                    .checked_add(row.NextEntryOffset as usize)
                    .ok_or_else(|| invalid("directory offset overflow"))?;
                if next <= offset || next >= 16384 {
                    return Err(invalid("invalid native next directory offset"));
                }
                self.offset = Some(next);
            }
            if name == "." || name == ".." {
                continue;
            }
            let kind = if row.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                NativeSourceKind::Link
            } else if row.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                NativeSourceKind::Directory
            } else if row.FileAttributes & FILE_ATTRIBUTE_DEVICE != 0 {
                NativeSourceKind::Other
            } else {
                NativeSourceKind::File
            };
            return Ok(Some(NativeSourceEntry { name, kind }));
        }
    }
}
