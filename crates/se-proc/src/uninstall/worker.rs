//! Native uninstall carrier. The private marker grants no deletion authority.
use super::*;
use serde::Deserialize;
use std::{collections::HashSet, os::windows::io::FromRawHandle, ptr};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    handle: u64,
    path: PathBuf,
    kind: String,
    identity: String,
    sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    parent: u64,
    claim: u64,
    authorize: u64,
    ready: u64,
    report: u64,
    nonce: String,
    deadline: u64,
    entries: Vec<Entry>,
}
struct Object {
    entry: Entry,
    file: File,
}
fn raw(value: u64) -> Result<HANDLE> {
    let value = usize::try_from(value)
        .map_err(|_| refuse("read carrier handle", "handle value out of range"))?;
    if value == 0 || value == usize::MAX {
        return Err(refuse("read carrier handle", "invalid inherited handle"));
    }
    Ok(value as HANDLE)
}
fn owned(value: u64) -> Result<OwnedHandle> {
    let handle = raw(value)?;
    // A successful duplicate proves the table entry is live before taking its ownership.
    drop(native::duplicate_same(handle, false)?);
    // SAFETY: each value is a validated unique inherited table entry owned by this process.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn identity(file: &File, directory: bool) -> Result<String> {
    let id = if directory {
        staging::directory_id(file)?
    } else {
        native::file_id(file)?
    };
    Ok(format!(
        "{:016x}:{}",
        id.volume,
        se_types::hex_lower(&id.index)
    ))
}
fn bounded(file: &mut File) -> Result<serde_json::Value> {
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|cause| error("read private carrier frame", cause))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(refuse(
            "read private carrier frame",
            "frame exceeds two MiB",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|cause| error("decode private carrier frame", io::Error::other(cause)))
}
fn input() -> Result<File> {
    // SAFETY: standard input is inherited exclusively by this native child.
    let standard = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let copy = native::duplicate_same(standard, false)?;
    // SAFETY: close the inherited original after making an independently owned duplicate.
    if unsafe { CloseHandle(standard) } == 0 {
        return Err(native::last("close carrier input"));
    }
    Ok(File::from(copy))
}
fn remaining(deadline: u64) -> Result<u32> {
    let left = deadline
        .checked_sub(clock())
        .filter(|left| *left > 0 && *left <= 90_000)
        .ok_or_else(|| refuse("observe carrier deadline", "deadline expired or invalid"))?;
    Ok(left as u32)
}
fn nonce(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(refuse(
            "read carrier nonce",
            "32-byte lowercase hexadecimal nonce required",
        ));
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|cause| error("decode carrier nonce", io::Error::other(cause)))?;
    }
    Ok(bytes)
}
fn objects(entries: Vec<Entry>) -> Result<Vec<Object>> {
    let mut objects = Vec::new();
    for entry in entries {
        let mut file = File::from(owned(entry.handle)?);
        let directory = matches!(entry.kind.as_str(), "directory" | "flush" | "staging");
        if !matches!(
            entry.kind.as_str(),
            "image" | "record" | "directory" | "flush" | "staging"
        ) || identity(&file, directory)? != entry.identity
        {
            return Err(refuse(
                "validate carrier object",
                "object type or identity differs",
            ));
        }
        if !directory
            && entry.sha256.as_deref() != Some(&se_types::hex_lower(&native::digest(&mut file)?))
        {
            return Err(refuse("validate carrier object", "object content differs"));
        }
        objects.push(Object { entry, file });
    }
    if objects
        .iter()
        .filter(|object| object.entry.kind == "image")
        .count()
        != 1
        || objects
            .iter()
            .filter(|object| object.entry.kind == "record")
            .count()
            != 1
        || objects
            .iter()
            .filter(|object| object.entry.kind == "staging")
            .count()
            > 1
    {
        return Err(refuse(
            "validate carrier inventory",
            "one image, one record, and at most one staging directory required",
        ));
    }
    Ok(objects)
}
fn run() -> Result<()> {
    let mut input = input()?;
    let value = bounded(&mut input)?;
    drop(input);
    let frame: Frame = serde_json::from_value(value)
        .map_err(|cause| error("decode carrier envelope", io::Error::other(cause)))?;
    let random = nonce(&frame.nonce)?;
    remaining(frame.deadline)?;
    if !(4..=133).contains(&frame.entries.len()) {
        return Err(refuse(
            "validate carrier inventory",
            "four to 133 objects required",
        ));
    }
    let mut unique = HashSet::new();
    for handle in [
        frame.parent,
        frame.claim,
        frame.authorize,
        frame.ready,
        frame.report,
    ]
    .into_iter()
    .chain(frame.entries.iter().map(|entry| entry.handle))
    {
        if !unique.insert(handle) {
            return Err(refuse(
                "validate carrier inventory",
                "duplicate inherited handles",
            ));
        }
    }
    let parent = owned(frame.parent)?;
    if native::exited(&parent)? {
        return Err(refuse(
            "validate carrier parent",
            "parent is no longer live",
        ));
    }
    let _claim = owned(frame.claim)?;
    let mut authorize = File::from(owned(frame.authorize)?);
    let mut ready = File::from(owned(frame.ready)?);
    let mut report = File::from(owned(frame.report)?);
    let mut objects = objects(frame.entries)?;
    let mut ready_frame = [0; 33];
    ready_frame[0] = b'R';
    ready_frame[1..].copy_from_slice(&random);
    ready
        .write_all(&ready_frame)
        .map_err(|cause| error("report carrier readiness", cause))?;
    drop(ready);
    loop {
        if let Some(observed) = native::poll_frame(&mut authorize)? {
            if observed[0] != b'G' || observed[1..] != random {
                return Err(refuse("authorize carrier", "authorization differs"));
            }
            break;
        }
        remaining(frame.deadline)?;
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(authorize);
    report
        .rewind()
        .map_err(|cause| error("rewind completion report", cause))?;
    let authorization = bounded(&mut report)?;
    drop(report);
    if authorization
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        != Some(frame.nonce.as_str())
    {
        return Err(refuse("authorize carrier", "completion nonce differs"));
    }
    let output = authorization
        .get("report")
        .ok_or_else(|| refuse("authorize carrier", "completion report absent"))?
        .clone();
    let completion = output.get("completion").cloned();
    let result = perform(&parent, &mut objects, frame.deadline);
    if let Some(completion) = completion.filter(|v| !v.is_null()) {
        finish::send(&completion, &output, &objects, result.as_ref().err())?;
    }
    result
}
fn perform(parent: &OwnedHandle, objects: &mut [Object], deadline: u64) -> Result<()> {
    // SAFETY: retained exact parent process handle and finite remaining timeout.
    if unsafe { WaitForSingleObject(parent.as_raw_handle(), remaining(deadline)?) } != WAIT_OBJECT_0
    {
        return Err(refuse(
            "wait for uninstall parent",
            "exact parent did not exit before the deadline",
        ));
    }
    for object in objects
        .iter_mut()
        .filter(|object| matches!(object.entry.kind.as_str(), "image" | "record"))
    {
        if identity(&object.file, false)? != object.entry.identity
            || object.entry.sha256.as_deref()
                != Some(&se_types::hex_lower(&native::digest(&mut object.file)?))
        {
            return Err(refuse(
                "remove uninstall object",
                "pinned identity or contents changed",
            ));
        }
        native::unlink(&object.file, true)?;
        native::absent_name(&object.entry.path)?;
    }
    for object in objects.iter().filter(|object| object.entry.kind == "flush") {
        // SAFETY: the retained original directory handle is valid.
        if unsafe { FlushFileBuffers(object.file.as_raw_handle()) } == 0 {
            return Err(native::last("flush uninstall directory"));
        }
    }
    let mut directories: Vec<_> = objects
        .iter()
        .filter(|object| object.entry.kind == "directory")
        .collect();
    directories.sort_by_key(|object| std::cmp::Reverse(object.entry.path.as_os_str().len()));
    for object in directories {
        unlink_directory(object, false)?;
    }
    if let Some(stage) = objects.iter().find(|object| object.entry.kind == "staging") {
        // SAFETY: the private diagnostic handle is no longer needed before stage removal.
        let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        let closed = if !stderr.is_null() && stderr != INVALID_HANDLE_VALUE {
            // SAFETY: this inherited diagnostic handle is owned by the carrier.
            unsafe { CloseHandle(stderr) }
        } else {
            1
        };
        if closed == 0 {
            return Err(native::last("close carrier diagnostic"));
        }
        unlink_directory(stage, true)?;
    }
    Ok(())
}
fn unlink_directory(object: &Object, require_empty: bool) -> Result<()> {
    let path = &object.entry.path;
    let file = File::from(native::handle(
        // SAFETY: terminated path and explicit no-follow directory flags.
        unsafe {
            CreateFileW(
                native::wide(path)?.as_ptr(),
                DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        },
        "open exact uninstall directory",
    )?);
    if identity(&file, true)? != object.entry.identity
        || identity(&object.file, true)? != object.entry.identity
    {
        return Err(refuse(
            "remove uninstall directory",
            "directory identity changed",
        ));
    }
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: DELETE-capable exact directory and initialized disposition record.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const info).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        let cause = io::Error::last_os_error();
        if !require_empty && cause.raw_os_error() == Some(ERROR_DIR_NOT_EMPTY as i32) {
            let named = staging::open_directory(path, false, true)?;
            if identity(&named, true)? != object.entry.identity {
                return Err(refuse(
                    "preserve uninstall directory",
                    "directory name changed",
                ));
            }
            return Ok(());
        }
        return Err(error("remove exact uninstall directory", cause));
    }
    drop(file);
    native::absent_name(path)
}
pub fn entry() -> i32 {
    match run() {
        Ok(()) => 0,
        Err(cause) => {
            let _ = writeln!(io::stderr().lock(), "{cause}");
            78
        }
    }
}
mod finish;
