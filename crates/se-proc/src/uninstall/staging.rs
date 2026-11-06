//! High integrity is supplied at directory creation, before elevated helper
//! bytes or names are exposed to a normal-integrity process of the same user.
use super::*;
use serde::{Deserialize, Serialize};
use std::{mem::size_of, ptr};
use windows_sys::Win32::Security::{Authorization::*, *};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectoryCustody {
    #[serde(with = "crate::checkpoint::native_path")]
    pub path: PathBuf,
    pub id: FileId,
}
pub(super) struct Staging {
    files: NativeStateFiles,
    pub directory: DirectoryCustody,
    _pin: File,
}
use crate::windows_native::allocation::Allocation;

pub(super) fn elevated() -> Result<bool> {
    let mut raw = ptr::null_mut();
    // SAFETY: current-process pseudo handle and writable owned-token output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(native::last("read uninstall elevation"));
    }
    let token = native::handle(raw, "own uninstall elevation token")?;
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
fn open_directory(path: &Path, delete: bool) -> Result<File> {
    let file = File::from(native::handle(
        // SAFETY: terminated no-follow directory path and explicit read/delete access.
        unsafe {
            CreateFileW(
                native::wide(path)?.as_ptr(),
                GENERIC_READ | READ_CONTROL | if delete { DELETE } else { 0 },
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        },
        "pin elevated uninstall directory",
    )?);
    directory_id(&file)?;
    Ok(file)
}
pub(super) fn directory_id(file: &File) -> Result<FileId> {
    let info = crate::windows_native::file_information(file)
        .map_err(|e| error("read uninstall directory identity", e))?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(refuse(
            "read uninstall directory identity",
            "ordinary no-follow directory required",
        ));
    }
    let id = crate::windows_native::file_id(file)
        .map_err(|e| error("read uninstall directory file ID", e))?;
    Ok(FileId {
        volume: id.volume,
        index: id.index,
    })
}
pub(super) fn verify_high(file: &File, directory: bool) -> Result<()> {
    let descriptor = crate::windows_native::acl::SecurityDescriptor::query(
        file.as_raw_handle(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
    )
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
    let sid = crate::windows_native::sid_text((&raw const ace.SidStart).cast_mut().cast())
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
        let sid = crate::windows_native::process_sid(
            // SAFETY: immutable native current-process pseudo handle for token query.
            unsafe { GetCurrentProcess() },
        )
        .map_err(|e| error(e.operation, e.source))?;
        let descriptor: Vec<_> =
            format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})S:(ML;OICI;NW;;;HI)")
                .encode_utf16()
                .chain(Some(0))
                .collect();
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
        let descriptor = Allocation(raw);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let mut nonce = [0; 16];
        crate::fill_entropy(&mut nonce)
            .map_err(|e| error("create High uninstall staging", io::Error::other(e)))?;
        let name: String = se_types::hex_lower(&nonce);
        let path = parent.root().join(format!(".se-uninstall-{name}"));
        let _root = NativeStateFiles::open(parent.root()).map_err(custody)?;
        // SAFETY: retained descriptor supplies High integrity at creation; the
        // new directory is never first exposed with a Medium mandatory label.
        if unsafe { CreateDirectoryW(native::wide(&path)?.as_ptr(), &attributes) } == 0 {
            return Err(native::last("create High uninstall staging directory"));
        }
        let pin = open_directory(&path, false)?;
        verify_high(&pin, true)?;
        let id = directory_id(&pin)?;
        let files = NativeStateFiles::open(&path).map_err(custody)?;
        Ok(Self {
            files,
            directory: DirectoryCustody { path, id },
            _pin: pin,
        })
    }
    pub fn files(&self) -> &NativeStateFiles {
        &self.files
    }
}
pub(super) fn verify_directory(custody: &DirectoryCustody) -> Result<File> {
    let pin = open_directory(&custody.path, false)?;
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
    let pin = match open_directory(&custody.path, true) {
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
#[path = "../../tests/support/windows_high_policy.rs"]
mod judges;
