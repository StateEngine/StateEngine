//! High integrity is supplied at directory creation, before elevated helper
//! bytes or names are exposed to a normal-integrity process of the same user.
use super::*;
use serde::{Deserialize, Serialize};
use std::{mem::size_of, ptr};
use windows_sys::Win32::Security::{Authorization::*, *};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryCustody {
    #[serde(with = "se_custody::checkpoint::native_path")]
    pub path: PathBuf,
    pub id: FileId,
}
pub(super) struct Staging {
    files: NativeStateFiles,
    pub directory: DirectoryCustody,
    _pin: File,
}
use se_native_path::windows::allocation::Allocation;
use se_state_files::state_files::effects::DirectoryRemoval;

pub(super) fn elevated() -> Result<bool> {
    let mut raw = ptr::null_mut();
    // SAFETY: current-process pseudo handle and writable owned-token output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(native::last("read uninstall elevation"));
    }
    // SAFETY: the successful OpenProcessToken above transferred sole ownership of `raw`.
    let token = unsafe { native::handle(raw, "own uninstall elevation token") }?;
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut length = 0;
    // SAFETY: retained token and exact initialized TOKEN_ELEVATION output.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(native::last("read native uninstall elevation"));
    }
    if length as usize != size_of::<TOKEN_ELEVATION>() {
        return Err(refuse(
            "read native uninstall elevation",
            "invalid token elevation size",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}
pub(super) fn open_directory(path: &Path, delete: bool, share_delete: bool) -> Result<File> {
    // SAFETY: terminated no-follow directory path and explicit read/delete access.
    let raw = unsafe {
        CreateFileW(
            native::wide(path)?.as_ptr(),
            GENERIC_READ | READ_CONTROL | if delete { DELETE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 },
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    // SAFETY: the successful open above transferred unique ownership to `raw`.
    let file = File::from(unsafe { native::handle(raw, "pin elevated uninstall directory") }?);
    directory_id(&file)?;
    Ok(file)
}
pub(super) fn directory_id(file: &File) -> Result<FileId> {
    let info = se_native_path::windows::file::file_information(file)
        .map_err(|e| error("read uninstall directory identity", e))?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(refuse(
            "read uninstall directory identity",
            "ordinary no-follow directory required",
        ));
    }
    let id = se_native_path::windows::file::file_id(file)
        .map_err(|e| error("read uninstall directory file ID", e))?;
    Ok(FileId {
        volume: id.volume,
        index: id.index,
    })
}
pub(super) fn verify_high(file: &File, directory: bool) -> Result<()> {
    // SAFETY: the caller retains the native handle throughout this query.
    let descriptor = unsafe {
        se_native_path::windows::acl::SecurityDescriptor::query(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
        )
    }
    .map_err(|e| error("read mandatory uninstall label", e))?;
    let sacl = descriptor.sacl().ok_or_else(|| {
        refuse(
            "verify mandatory uninstall label",
            "valid High label ACL required",
        )
    })?;
    if sacl.len() != 1 {
        return Err(refuse(
            "verify mandatory uninstall label",
            "one exact High mandatory label required",
        ));
    }
    let entry = sacl
        .ace(0)
        .map_err(|e| error("read High mandatory label ACE", e))?;
    let header = entry.header();
    let ace = entry
        .mandatory_label()
        .filter(|_| {
            header.AceFlags & INHERIT_ONLY_ACE as u8 == 0
                && (!directory
                    || header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                        == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8)
        })
        .ok_or_else(|| {
            refuse(
                "verify mandatory uninstall label",
                "applicable inheritable mandatory label required",
            )
        })?;
    // SAFETY: `ace` borrows a validated mandatory-label ACE retained in the descriptor buffer.
    let sid = unsafe {
        se_native_ipc::windows_process::sid_text((&raw const ace.SidStart).cast_mut().cast())
    }
    .map_err(|e| error(e.operation, e.source))?;
    if sid != "S-1-16-12288" || ace.Mask & 1 == 0 {
        return Err(refuse(
            "verify mandatory uninstall label",
            "High no-write-up label required",
        ));
    }
    Ok(())
}
impl Staging {
    pub fn create(parent: &NativeStateFiles) -> Result<Self> {
        // SAFETY: immutable native current-process pseudo handle for token query.
        let sid = unsafe { se_native_ipc::windows_process::process_sid(GetCurrentProcess()) }
            .map_err(|e| error(e.operation, e.source))?;
        let sddl = format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})S:(ML;OICI;NW;;;HI)");
        Self::create_with(parent, &sddl, |created| verify_high(created, true))
    }
    /// Creates staging with `sddl` installed at creation; `verify` judges the
    /// created object once it is pinned, opened and proven to be that object.
    fn create_with(
        parent: &NativeStateFiles,
        sddl: &str,
        verify: impl FnOnce(&File) -> Result<()>,
    ) -> Result<Self> {
        let descriptor: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = ptr::null_mut();
        // SAFETY: owned terminated SDDL and writable LocalFree descriptor output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(native::last("create High uninstall security descriptor"));
        }
        // SAFETY: the native API returned a unique LocalFree allocation.
        let descriptor = unsafe { Allocation::from_raw(raw) };
        let mut nonce = [0; 16];
        se_state_files::fill_entropy(&mut nonce)
            .map_err(|e| error("create High uninstall staging", io::Error::other(e)))?;
        let leaf = format!(".se-uninstall-{}", se_types::hex_lower(&nonce));
        let path = parent.root().join(&leaf);
        let root = NativeStateFiles::open(parent.root()).map_err(custody)?;
        let created = create_retained(&root, &leaf, &path, &descriptor)?;
        // The created handle stays held until setup succeeds, so a failure
        // retires exactly the object this call created, wherever its name is.
        // It holds no DELETE access, so handles that refuse delete sharing open.
        let setup = (|| {
            let id = directory_id(&created)?;
            let pin = open_directory(&path, false, true)?;
            if directory_id(&pin)? != id {
                return Err(refuse(
                    "pin High uninstall staging directory",
                    "directory name was replaced after creation",
                ));
            }
            let files = NativeStateFiles::open(&path).map_err(custody)?;
            files.verify_held_root(&created).map_err(custody)?;
            verify(&created)?;
            Ok((pin, id, files))
        })();
        match setup {
            Ok((pin, id, files)) => Ok(Self {
                files,
                directory: DirectoryCustody { path, id },
                _pin: pin,
            }),
            Err(cause) => Err(retire_created(cause, &created, &path)),
        }
    }
    pub fn files(&self) -> &NativeStateFiles {
        &self.files
    }
    pub fn pin(&self) -> &File {
        &self._pin
    }
}
fn pending(mut cause: UninstallNativeError, path: &Path) -> UninstallNativeError {
    cause.pending_paths.push(path.to_owned());
    cause
}
/// Retires the staging directory this call created, through DELETE custody
/// taken from its creation handle only now, after a later setup step fails,
/// and returns that step's failure. An object it cannot remove is pending.
fn retire_created(
    cause: UninstallNativeError,
    created: &File,
    path: &Path,
) -> UninstallNativeError {
    let failure = match se_state_files::state_files::windows::effects::dispose_created_directory(
        created, path,
    ) {
        Ok(DirectoryRemoval::Removed | DirectoryRemoval::AlreadyAbsent) => return cause,
        Ok(DirectoryRemoval::NotEmpty) => refuse(
            "retire created High uninstall staging directory",
            "directory is not empty; preserved",
        ),
        Err(failure) => custody(failure),
    };
    let mut cause = pending(cause, path);
    cause.cleanup_failures.push(failure);
    cause
}
/// Exclusively creates `leaf` under the held state root with `descriptor`
/// installed at creation, returning custody of the created object.
fn create_retained(
    root: &NativeStateFiles,
    leaf: &str,
    path: &Path,
    descriptor: &Allocation,
) -> Result<File> {
    // SAFETY: terminated no-follow directory path; this handle only names the
    // creation parent and grants the right to add one subdirectory.
    let raw = unsafe {
        CreateFileW(
            native::wide(root.root())?.as_ptr(),
            GENERIC_READ | READ_CONTROL | FILE_ADD_SUBDIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    // SAFETY: the successful open above transferred unique ownership to `raw`.
    let parent = File::from(unsafe { native::handle(raw, "pin uninstall staging parent") }?);
    root.verify_held_root(&parent).map_err(custody)?;
    let access = GENERIC_READ | READ_CONTROL | SYNCHRONIZE;
    // SAFETY: `descriptor` is the security descriptor converted by the caller.
    let created = unsafe {
        se_state_files::state_files::windows::effects::create_directory_at(
            &parent,
            std::ffi::OsStr::new(leaf),
            path,
            descriptor,
            access,
        )
    };
    match created {
        Ok((file, true)) => Ok(file),
        // The handle does not prove this call created the object: never retire it.
        Ok((_, false)) => Err(pending(
            refuse(
                "create High uninstall staging directory",
                "native create did not report a new directory",
            ),
            path,
        )),
        Err(failure) => {
            // Creation was reported without held custody, so the name may exist.
            let unheld = failure.code == se_state_files::StateFileErrorCode::SourceChanged;
            let cause = custody(failure);
            Err(if unheld { pending(cause, path) } else { cause })
        }
    }
}
pub(super) fn verify_directory(custody: &DirectoryCustody) -> Result<File> {
    let pin = open_directory(&custody.path, false, false)?;
    if directory_id(&pin)? != custody.id {
        return Err(refuse(
            "verify elevated staging custody",
            "directory identity changed",
        ));
    }
    verify_high(&pin, true)?;
    Ok(pin)
}
pub(super) fn cleanup_directory(custody: &DirectoryCustody) -> Result<()> {
    let pin = match open_directory(&custody.path, true, false) {
        Ok(pin) => pin,
        Err(cause)
            if cause.source.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32)
                || cause.source.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32) =>
        {
            return Ok(());
        }
        Err(cause) => return Err(cause),
    };
    if directory_id(&pin)? != custody.id {
        return Err(refuse(
            "retire High uninstall directory",
            "directory was replaced; replacement preserved",
        ));
    }
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: exact held DELETE-capable directory and initialized disposition;
    // nonempty directories refuse, without traversing or deleting descendants.
    if unsafe {
        SetFileInformationByHandle(
            pin.as_raw_handle(),
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        return Err(native::last("retire empty High uninstall directory"));
    }
    drop(pin);
    native::absent_name(&custody.path)
}
#[cfg(test)]
#[path = "../../tests/support/windows_staging_custody.rs"]
mod custody_judges;
#[cfg(test)]
#[path = "../../tests/support/windows_high_policy.rs"]
mod judges;
