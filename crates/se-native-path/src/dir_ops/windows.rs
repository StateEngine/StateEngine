//! Windows `NtCreateFile` / `FileIdInfo` / `FileFullDirectoryInfo` /
//! `FileBasicInfo` / `FileDispositionInfo` handle-anchored directory ops.
use super::{ChildInfo, ChildKind, DeleteChildError, DirOpError, NodeId};
use crate::windows::file::{file_id, file_information};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        },
    },
    Win32::{
        Foundation::{
            ERROR_NO_MORE_FILES, GENERIC_READ, INVALID_HANDLE_VALUE, RtlNtStatusToDosError,
            UNICODE_STRING,
        },
        Storage::FileSystem::{
            CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
            FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FULL_DIR_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
            FileBasicInfo, FileDispositionInfo, FileFullDirectoryInfo,
            FileFullDirectoryRestartInfo, GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE,
            SetFileInformationByHandle,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

pub(super) struct DirHandle {
    file: File,
}

fn wide_literal_name(name: &OsStr) -> io::Result<Vec<u16>> {
    let units: Vec<u16> = name.encode_wide().collect();
    if units.is_empty()
        || units.len() > u16::MAX as usize / 2
        || units == [b'.' as u16]
        || units == [b'.' as u16, b'.' as u16]
        || units.iter().any(|&u| matches!(u, 0 | 0x2f | 0x5c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child entry must be a single literal name",
        ));
    }
    Ok(units)
}

fn wide_path_nul(path: &Path) -> io::Result<Vec<u16>> {
    let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains NUL",
        ));
    }
    units.push(0);
    Ok(units)
}

fn nt_open_relative(
    parent: &File,
    name: &OsStr,
    access: u32,
    disposition: u32,
    options: u32,
) -> io::Result<File> {
    let mut units = wide_literal_name(name)?;
    let byte_len = u16::try_from(units.len().saturating_mul(2))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
    let mut ustr = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: units.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut ustr,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut raw = ptr::null_mut();
    // SAFETY: zeroed `IO_STATUS_BLOCK` is valid POD for `NtCreateFile`.
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    // SAFETY: `attrs` references live `parent` handle and `ustr` buffer for this call.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attrs,
            &mut iosb,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: `RtlNtStatusToDosError` takes an integer status with no pointers.
        let dos = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(dos as i32));
    }
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("relative open returned null handle"));
    }
    // SAFETY: `NtCreateFile` succeeded and transferred one uniquely owned handle.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

fn node_id_from_handle(file: &File) -> io::Result<NodeId> {
    let id = file_id(file)?;
    Ok(NodeId {
        volume: id.volume,
        index: id.index,
    })
}

fn classify_handle(file: &File) -> io::Result<ChildInfo> {
    let info = file_information(file)?;
    let attrs = info.dwFileAttributes;
    let kind = if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        ChildKind::Link("reparse point / junction")
    } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        ChildKind::Dir
    } else {
        ChildKind::File
    };
    let id = node_id_from_handle(file)?;
    Ok(ChildInfo {
        kind,
        id,
        is_mount_root: false,
    })
}

fn clear_readonly_on_handle(file: &File, current_attrs: u32) -> io::Result<()> {
    if current_attrs & FILE_ATTRIBUTE_READONLY == 0 {
        return Ok(());
    }
    let cleared = current_attrs & !FILE_ATTRIBUTE_READONLY;
    // SAFETY: zeroed `FILE_BASIC_INFO` tells Windows to leave timestamps unchanged
    // and update only `FileAttributes` when non-zero.
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    basic.FileAttributes = if cleared == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        cleared
    };
    // SAFETY: `file` is a live handle opened with `FILE_WRITE_ATTRIBUTES` and
    // `&basic` has exact size `size_of::<FILE_BASIC_INFO>()`.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn delete_on_verified_handle(
    parent: &File,
    name: &OsStr,
    is_dir: bool,
    expected_id: Option<NodeId>,
) -> Result<(), DeleteChildError> {
    let type_opt = if is_dir {
        FILE_DIRECTORY_FILE
    } else {
        FILE_NON_DIRECTORY_FILE
    };
    let handle = nt_open_relative(
        parent,
        name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | type_opt,
    )
    .map_err(DeleteChildError::Io)?;

    let info = file_information(&handle).map_err(DeleteChildError::Io)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DeleteChildError::Link("reparse point / junction"));
    }
    if let Some(expected) = expected_id {
        let actual = node_id_from_handle(&handle).map_err(DeleteChildError::Io)?;
        if actual != expected {
            return Err(DeleteChildError::IdentityMismatch);
        }
    }

    let delete_handle = if info.dwFileAttributes & FILE_ATTRIBUTE_READONLY != 0 {
        drop(handle);
        let rw = nt_open_relative(
            parent,
            name,
            DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | type_opt,
        )
        .map_err(DeleteChildError::ClearReadonlyFailed)?;
        let rw_info = file_information(&rw).map_err(DeleteChildError::Io)?;
        if rw_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DeleteChildError::Link("reparse point / junction"));
        }
        if let Some(expected) = expected_id {
            let actual = node_id_from_handle(&rw).map_err(DeleteChildError::Io)?;
            if actual != expected {
                return Err(DeleteChildError::IdentityMismatch);
            }
        }
        clear_readonly_on_handle(&rw, rw_info.dwFileAttributes)
            .map_err(DeleteChildError::ClearReadonlyFailed)?;
        rw
    } else {
        handle
    };

    let disp = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `delete_handle` is a verified live handle opened with `DELETE` access.
    let ok = unsafe {
        SetFileInformationByHandle(
            delete_handle.as_raw_handle(),
            FileDispositionInfo,
            (&disp as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(DeleteChildError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

impl DirHandle {
    pub(super) fn open_root(path: &Path) -> Result<Self, DirOpError> {
        let wide = wide_path_nul(path).map_err(DirOpError::Io)?;
        // SAFETY: `wide` is NUL-terminated; opens existing directory without following reparse points.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            return Err(match err.kind() {
                io::ErrorKind::NotFound => DirOpError::NotFound,
                _ => DirOpError::Io(err),
            });
        }
        // SAFETY: `CreateFileW` succeeded and transferred one unique handle.
        let file = File::from(unsafe { OwnedHandle::from_raw_handle(raw) });
        let info = classify_handle(&file).map_err(DirOpError::Io)?;
        match info.kind {
            ChildKind::Dir => Ok(Self { file }),
            ChildKind::Link(kind) => Err(DirOpError::Link(kind)),
            _ => Err(DirOpError::NotDir),
        }
    }

    pub(super) fn open_child_dir(&self, name: &OsStr) -> Result<Self, DirOpError> {
        let file = nt_open_relative(
            &self.file,
            name,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => DirOpError::NotFound,
            _ => DirOpError::Io(err),
        })?;
        let info = classify_handle(&file).map_err(DirOpError::Io)?;
        match info.kind {
            ChildKind::Dir => Ok(Self { file }),
            ChildKind::Link(kind) => Err(DirOpError::Link(kind)),
            _ => Err(DirOpError::NotDir),
        }
    }

    pub(super) fn stat_self(&self) -> io::Result<(NodeId, bool)> {
        let id = node_id_from_handle(&self.file)?;
        Ok((id, false))
    }

    pub(super) fn read_entries(&self) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        // 8-byte aligned buffer for `FILE_FULL_DIR_INFO` records.
        let mut buf = vec![0u64; 4096];
        let mut first = true;
        loop {
            let class = if first {
                first = false;
                FileFullDirectoryRestartInfo
            } else {
                FileFullDirectoryInfo
            };
            let byte_len = (buf.len() * size_of::<u64>()) as u32;
            // SAFETY: `self.file` is a valid directory handle and `buf` is 8-byte aligned.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    self.file.as_raw_handle(),
                    class,
                    buf.as_mut_ptr().cast(),
                    byte_len,
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    break;
                }
                return Err(err);
            }
            let raw_bytes: &[u8] =
                // SAFETY: `buf` is initialized `u64` backing `byte_len` readable bytes.
                unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), byte_len as usize) };
            let mut offset = 0usize;
            loop {
                if offset + size_of::<FILE_FULL_DIR_INFO>() > raw_bytes.len() {
                    break;
                }
                // SAFETY: `offset` is aligned per kernel `NextEntryOffset` contract and in bounds.
                let entry =
                    unsafe { &*(raw_bytes.as_ptr().add(offset).cast::<FILE_FULL_DIR_INFO>()) };
                let name_bytes = entry.FileNameLength as usize;
                let name_offset = offset + std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName);
                if name_offset + name_bytes <= raw_bytes.len() && name_bytes.is_multiple_of(2) {
                    let units: Vec<u16> = raw_bytes[name_offset..name_offset + name_bytes]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    if units != [b'.' as u16] && units != [b'.' as u16, b'.' as u16] {
                        names.push(OsString::from_wide(&units));
                    }
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                offset = offset.saturating_add(entry.NextEntryOffset as usize);
            }
        }
        Ok(names)
    }

    pub(super) fn inspect_child(&self, name: &OsStr) -> Result<ChildInfo, DirOpError> {
        let file = nt_open_relative(
            &self.file,
            name,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => DirOpError::NotFound,
            _ => DirOpError::Io(err),
        })?;
        classify_handle(&file).map_err(DirOpError::Io)
    }

    pub(super) fn read_child_file(
        &self,
        name: &OsStr,
        max_bytes: usize,
    ) -> Result<Vec<u8>, DirOpError> {
        let mut file = nt_open_relative(
            &self.file,
            name,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => DirOpError::NotFound,
            _ => DirOpError::Io(err),
        })?;
        let info = classify_handle(&file).map_err(DirOpError::Io)?;
        match info.kind {
            ChildKind::File => {}
            ChildKind::Link(kind) => return Err(DirOpError::Link(kind)),
            _ => return Err(DirOpError::Io(io::Error::other("not a regular file"))),
        }
        let mut buf = Vec::new();
        Read::take(&mut file, (max_bytes as u64).saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(DirOpError::Io)?;
        if buf.len() > max_bytes {
            return Err(DirOpError::Io(io::Error::other(
                "file exceeds maximum read limit",
            )));
        }
        Ok(buf)
    }

    pub(super) fn create_child_file_exclusive(&self, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        let mut file = nt_open_relative(
            &self.file,
            name,
            FILE_WRITE_DATA | SYNCHRONIZE,
            FILE_CREATE,
            FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        file.write_all(bytes)?;
        file.sync_data()?;
        Ok(())
    }

    pub(super) fn unlink_child_file(
        &self,
        name: &OsStr,
        expected_id: Option<NodeId>,
    ) -> Result<(), DeleteChildError> {
        delete_on_verified_handle(&self.file, name, false, expected_id)
    }

    pub(super) fn remove_child_dir(
        &self,
        name: &OsStr,
        expected_id: Option<NodeId>,
    ) -> Result<(), DeleteChildError> {
        delete_on_verified_handle(&self.file, name, true, expected_id)
    }

    pub(super) fn can_modify_entries(&self) -> io::Result<bool> {
        Ok(true)
    }
}
