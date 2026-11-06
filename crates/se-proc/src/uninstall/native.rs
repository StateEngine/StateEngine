use super::*;

use sha2::{Digest, Sha256};
use std::{
    mem::size_of,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::System::Pipes::*;

pub(super) fn last(operation: &'static str) -> UninstallNativeError {
    error(operation, io::Error::last_os_error())
}
pub(super) fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    crate::windows_native::handle(raw, operation).map_err(|e| error(e.operation, e.source))
}
pub(super) fn wide(path: &Path) -> Result<Vec<u16>> {
    crate::state_files::windows::wide(path).map_err(custody)
}
pub(super) fn open_image(path: &Path, delete: bool) -> Result<File> {
    let file = crate::windows_native::open_image_file(&wide(path)?, delete)
        .map_err(|e| error("pin uninstall image", e))?;
    file_id(&file)?;
    Ok(file)
}
pub(super) fn file_id(file: &File) -> Result<FileId> {
    let info = crate::windows_native::file_information(file)
        .map_err(|e| error("read pinned uninstall file identity", e))?;
    // SAFETY: immutable type query on this retained native file handle.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(refuse(
            "read pinned uninstall file identity",
            "regular disk file without reparse points or extra hard links required",
        ));
    }
    let id = crate::windows_native::file_id(file)
        .map_err(|e| error("read 128-bit uninstall file identity", e))?;
    Ok(FileId {
        volume: id.volume,
        index: id.index,
    })
}
pub(super) fn digest(file: &mut File) -> Result<[u8; 32]> {
    file.rewind()
        .map_err(|e| error("rewind uninstall image", e))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut length = 0u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| error("read uninstall image", e))?;
        if count == 0 {
            break;
        }
        length += count as u64;
        if length > 512 * 1024 * 1024 {
            return Err(refuse("hash uninstall image", "image capacity exceeded"));
        }
        hash.update(&buffer[..count]);
    }
    file.rewind()
        .map_err(|e| error("rewind uninstall image", e))?;
    Ok(hash.finalize().into())
}
pub(super) fn process_image(process: &OwnedHandle) -> Result<PathBuf> {
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    // SAFETY: retained process handle and writable UTF-16 buffer with explicit capacity.
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(last("read uninstall process image"));
    }
    if length == 0 || length as usize >= image.len() {
        return Err(refuse(
            "read uninstall process image",
            "invalid native image length",
        ));
    }
    Ok(std::ffi::OsString::from_wide(&image[..length as usize]).into())
}

pub(super) fn current_process() -> Result<OwnedHandle> {
    duplicate(
        // SAFETY: native current-process pseudo handle; duplication supplies an owned reference.
        unsafe { GetCurrentProcess() },
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
        false,
    )
}
pub(super) fn duplicate(raw: HANDLE, access: u32, inherit: bool) -> Result<OwnedHandle> {
    let mut out = ptr::null_mut();
    // SAFETY: retained source/current-process handles and writable new-reference output.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut out,
            access,
            i32::from(inherit),
            0,
        )
    } == 0
    {
        return Err(last("duplicate uninstall custody handle"));
    }
    handle(out, "duplicate uninstall custody handle")
}
pub(super) fn duplicate_same(raw: HANDLE, inherit: bool) -> Result<OwnedHandle> {
    let mut out = ptr::null_mut();
    // SAFETY: native validates source; successful duplication yields a new owned reference.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut out,
            0,
            i32::from(inherit),
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last("duplicate uninstall handle with exact access"));
    }
    handle(out, "duplicate uninstall handle with exact access")
}
pub(super) fn pipe() -> Result<(File, File)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: two writable native handle outputs; each successful reference is immediately owned.
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 4096) } == 0 {
        return Err(last("create private uninstall channel"));
    }
    Ok((
        File::from(handle(read, "create uninstall channel reader")?),
        File::from(handle(write, "create uninstall channel writer")?),
    ))
}
pub(super) fn poll_frame(file: &mut File) -> Result<Option<[u8; 33]>> {
    let mut available = 0;
    // SAFETY: retained pipe handle, initialized availability output, and zero-byte nonblocking peek.
    if unsafe {
        PeekNamedPipe(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last("observe private uninstall channel"));
    }
    if available < 33 {
        return Ok(None);
    }
    if available != 33 {
        return Err(refuse(
            "read private uninstall channel",
            "malformed authenticated frame length",
        ));
    }
    let mut frame = [0; 33];
    file.read_exact(&mut frame)
        .map_err(|e| error("read private uninstall channel", e))?;
    Ok(Some(frame))
}
pub(super) fn exited(process: &OwnedHandle) -> Result<bool> {
    // SAFETY: retained synchronize-capable exact process handle and zero timeout.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(last("observe exact uninstall process exit")),
    }
}
pub(super) fn unlink(file: &File, posix: bool) -> Result<()> {
    // ReOpenFile creates an independent native file object for POSIX unlink.
    // Its close removes the name even while inherited read pins remain open.
    let reopened = handle(
        // SAFETY: retained original file handle selects the exact object; no path can substitute a different target.
        unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        },
        "reopen exact uninstall object for deletion",
    )?;
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | if posix {
                FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            } else {
                0
            },
    };
    // SAFETY: retained DELETE-capable handle and correctly sized initialized disposition structure.
    if unsafe {
        SetFileInformationByHandle(
            reopened.as_raw_handle(),
            FileDispositionInfoEx,
            (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        return Err(last("unlink pinned uninstall image"));
    }
    Ok(())
}
pub(super) fn absent_name(path: &Path) -> Result<()> {
    // SAFETY: terminated native path and literal flags; the successful result becomes one owned reference.
    let raw = unsafe {
        CreateFileW(
            wide(path)?.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let cause = io::Error::last_os_error();
        if matches!(cause.raw_os_error(), Some(e) if e == ERROR_FILE_NOT_FOUND as i32 || e == ERROR_PATH_NOT_FOUND as i32)
        {
            return Ok(());
        }
        return Err(error("read back removed uninstall name", cause));
    }
    let _found = handle(raw, "read back removed uninstall name")?;
    Err(refuse(
        "read back removed uninstall name",
        "name remains or was replaced; replacement preserved",
    ))
}

pub(super) fn clear_inherit(raw: HANDLE) -> Result<()> {
    // SAFETY: caller retains this exact valid handle-table entry; only its
    // inheritance flag changes, not rights, object lifetime or another process.
    if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last("clear uninstall handle inheritance"));
    }
    Ok(())
}
