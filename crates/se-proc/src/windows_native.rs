//! Shared Windows query primitives. Callers retain their handles/token buffers;
//! typed adapters add their own operation context without copying native walks.
pub(crate) mod acl;
pub(crate) mod allocation;
pub(crate) mod attributes;
pub(crate) mod console;
mod parent;
pub(crate) mod pipe;
mod process_query;
pub(crate) use parent::parent;
use std::{
    collections::BTreeMap,
    fs::File,
    io,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::ConvertSidToStringSidW, *},
    Storage::FileSystem::*,
    System::{Diagnostics::ToolHelp::*, Threading::*},
};

pub(crate) struct Error {
    pub operation: &'static str,
    pub source: io::Error,
}
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
pub(crate) fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last(operation));
    }
    // SAFETY: successful native creation/open transfers exactly one new reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub(crate) fn sid_text(sid: PSID) -> Result<String> {
    // SAFETY: callers retain the successful native token/security buffer containing this SID.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid("encode native SID", "invalid native SID"));
    }
    let mut raw = ptr::null_mut();
    // SAFETY: validated retained SID and writable LocalFree-owned output.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(last("encode native SID"));
    }
    let _text = allocation::Allocation(raw.cast());
    let mut length = 0;
    // SAFETY: successful native conversion supplies a terminated SID string;
    // the allocation remains retained for this bounded scan and copy.
    while length < 256 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(invalid(
            "encode native SID",
            "native SID text exceeds 256 units",
        ));
    }
    // SAFETY: measured extent belongs to the retained native allocation.
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| invalid("encode native SID", "native SID text is invalid UTF-16"))
}
pub(crate) fn process_sid(process: HANDLE) -> Result<String> {
    let mut raw = ptr::null_mut();
    // SAFETY: retained query-capable process and writable owned-token output.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open native process owner token"));
    }
    let token = handle(raw, "open native process owner token")?;
    let mut bytes = 0;
    // SAFETY: documented sizing call with null buffer and writable length output.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut bytes,
        );
    }
    if bytes < size_of::<TOKEN_USER>() as u32 || bytes > 65536 {
        return Err(invalid(
            "read native process owner",
            "native token-user size exceeds bounds",
        ));
    }
    let capacity = bytes;
    let mut storage = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: retained token and aligned initialized buffer of the exact queried capacity.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut bytes,
        )
    } == 0
    {
        return Err(last("read native process owner"));
    }
    if bytes < size_of::<TOKEN_USER>() as u32 || bytes > capacity {
        return Err(invalid(
            "read native process owner",
            "native token-user size changed",
        ));
    }
    // SAFETY: successful aligned TOKEN_USER output remains retained through SID conversion.
    sid_text(unsafe { (*storage.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}
pub(crate) fn process_start(process: HANDLE) -> Result<u64> {
    // SAFETY: FILETIME is native POD; all outputs are initialized before use.
    let (mut created, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { zeroed() };
    // SAFETY: retained process query handle and four aligned writable outputs.
    if unsafe { GetProcessTimes(process, &mut created, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(last("read native process start"));
    }
    let value = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if value == 0 {
        return Err(invalid(
            "read native process start",
            "native process creation clock is zero",
        ));
    }
    Ok(value)
}
pub(crate) fn parents() -> Result<BTreeMap<u32, u32>> {
    let snapshot = handle(
        // SAFETY: read-only process snapshot, no heap/process mutation or pointer inputs.
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) },
        "snapshot native ancestry",
    )?;
    // SAFETY: process-entry POD is initialized and its size is set before enumeration.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: retained snapshot and exact aligned process-entry output.
    if unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } == 0 {
        return Err(last("read native ancestry snapshot"));
    }
    let mut result = BTreeMap::new();
    loop {
        if result.len() == 65536 {
            return Err(invalid(
                "read native ancestry",
                "process snapshot exceeds 65536 entries",
            ));
        }
        if result
            .insert(entry.th32ProcessID, entry.th32ParentProcessID)
            .is_some()
        {
            return Err(invalid(
                "read native ancestry",
                "duplicate native process ID",
            ));
        }
        // SAFETY: retained snapshot and initialized writable process-entry output.
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            let cause = io::Error::last_os_error();
            if cause.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(Error {
                    operation: "finish native ancestry snapshot",
                    source: cause,
                });
            }
            break;
        }
    }
    Ok(result)
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

/// Raw image open only: each adapter applies its own retained-file policy.
pub(crate) fn open_image_file(path: &[u16], delete: bool) -> io::Result<File> {
    // SAFETY: callers retain a validated terminated path; these are the shared
    // read/delete rights, sharing mode and no-follow flags of both image callers.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | READ_CONTROL | if delete { DELETE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW transferred one unique reference.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(raw) }))
}
pub(crate) fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: native POD is initialized before its exact writable query.
    let mut info = unsafe { zeroed() };
    // SAFETY: retained file and correctly typed writable metadata output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}
pub(crate) fn file_id(file: &File) -> io::Result<FileIdentity> {
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
    Ok(FileIdentity {
        volume: id.VolumeSerialNumber,
        index: id.FileId.Identifier,
    })
}
