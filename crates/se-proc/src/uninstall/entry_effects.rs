//! Effects use retained objects; path opens only re-admit directory identity or
//! observe absence. The completion channel selects output, never a target.
use super::entry::Held;
use super::*;
use std::{mem::size_of, ptr};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

pub(super) fn identity(file: &File, directory: bool) -> Result<String> {
    let info = crate::windows_native::file_information(file)
        .map_err(|e| error("read carrier object type", e))?;
    // SAFETY: immutable query of the retained native handle.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(refuse(
            "admit carrier object type",
            "original regular no-reparse object required",
        ));
    }
    let id = crate::windows_native::file_id(file)
        .map_err(|e| error("read carrier object identity", e))?;
    Ok(format!(
        "{:016x}:{}",
        id.volume,
        se_types::hex_lower(&id.index)
    ))
}
fn directory(path: &Path, delete: bool) -> Result<File> {
    let path = native::wide(path)?;
    // SAFETY: owned terminated path; successful native reference is immediately owned.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES | if delete { DELETE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    native::handle(raw, "open exact carrier directory").map(File::from)
}
fn unlink_directory(held: &Held) -> Result<()> {
    // Ordinary-user directory handles require a fresh no-reparse path open;
    // compare it with the retained original before setting disposition.
    let file = directory(&held.object.path, true)?;
    let expected = identity(&held.file, true)?;
    if identity(&file, true)? != expected {
        return Err(refuse("unlink carrier directory", "replacement preserved"));
    }
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: retained DELETE-capable exact directory and correctly sized input.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() != Some(ERROR_DIR_NOT_EMPTY as i32) {
            return Err(error("unlink exact carrier directory", cause));
        }
        drop(file);
        if identity(&directory(&held.object.path, false)?, true)? != expected {
            return Err(refuse(
                "retain nonempty carrier directory",
                "replacement preserved",
            ));
        }
        return Ok(());
    }
    drop(file);
    native::absent_name(&held.object.path)
}
pub(super) fn remove(objects: &mut [Held]) -> Result<()> {
    for kind in ["image", "record"] {
        let held = objects
            .iter_mut()
            .find(|h| h.object.kind == kind)
            .ok_or_else(|| refuse("remove carrier object", "admitted original missing"))?;
        held.verify()?;
        // POSIX deletion deliberately omits FORCE_IMAGE_SECTION_CHECK: the
        // carrier still maps this same admitted executable until it exits.
        native::unlink(&held.file, true)?;
        native::absent_name(&held.object.path)?;
    }
    for held in objects.iter().filter(|h| h.object.kind == "flush") {
        // SAFETY: retained original parent directory with admitted flush access.
        if unsafe { FlushFileBuffers(held.file.as_raw_handle()) } == 0 {
            return Err(native::last("flush uninstalled names"));
        }
    }
    let mut directories: Vec<_> = objects
        .iter_mut()
        .filter(|h| h.object.kind == "directory")
        .collect();
    directories.sort_by_key(|h| std::cmp::Reverse(h.object.path.as_os_str().len()));
    for held in directories {
        held.verify()?;
        unlink_directory(held)?;
    }
    Ok(())
}
pub(super) fn complete(
    objects: &[Held],
    report: &serde_json::Value,
    failure: Option<&UninstallNativeError>,
) -> Result<()> {
    let Some(completion) = report.get("completion").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let pipe = completion
        .get("pipe")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| refuse("deliver uninstall completion", "pipe name absent"))?;
    if pipe.is_empty()
        || pipe.len() > 256
        || !pipe
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    {
        return Err(refuse(
            "deliver uninstall completion",
            "invalid local pipe name",
        ));
    }
    let token = completion
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| refuse("deliver uninstall completion", "token absent"))?;
    // This output endpoint is a local device name, not a state-file path.
    // The validated suffix cannot change its namespace or introduce a NUL.
    let name: Vec<u16> = format!(r"\\.\pipe\{pipe}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let until = clock() + 5000;
    let mut channel = loop {
        // Identification SQOS is present before connection, preventing a pipe
        // squatter from impersonating the carrier with its full token.
        // SAFETY: bounded terminated local pipe name and literal access/flags.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            break File::from(native::handle(raw, "open uninstall completion pipe")?);
        }
        let cause = io::Error::last_os_error();
        if clock() >= until
            || !matches!(cause.raw_os_error(), Some(c) if c == ERROR_PIPE_BUSY as i32 || c == ERROR_FILE_NOT_FOUND as i32)
        {
            return Err(error("connect uninstall completion pipe", cause));
        }
        // SAFETY: same bounded pipe name and short wait within the delivery deadline.
        unsafe {
            WaitNamedPipeW(name.as_ptr(), 20);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let path = |kind| {
        objects
            .iter()
            .find(|h| h.object.kind == kind)
            .map(|h| &h.object.path)
    };
    let reply = serde_json::json!({"schema":"se.uninstall-completion/v2", "token":token,
        "complete":failure.is_none(), "error":failure.map(ToString::to_string), "image":path("image"),
        "record":path("record"), "helper":null, "directory":null, "achieved":report.get("achieved")});
    let mut bytes = serde_json::to_vec(&reply)
        .map_err(|e| error("encode uninstall completion", io::Error::other(e)))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(refuse(
            "deliver uninstall completion",
            "reply exceeds two MiB",
        ));
    }
    bytes.push(b'\n');
    channel
        .write_all(&bytes)
        .map_err(|e| error("deliver uninstall completion", e))
}
