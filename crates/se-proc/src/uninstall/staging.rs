//! High integrity is supplied at directory creation, before elevated helper
//! bytes or names are exposed to a normal-integrity process of the same user.
use super::*;
use serde::{Deserialize, Serialize};
use std::{
    mem::{size_of, zeroed},
    ptr,
};
use windows_sys::Win32::{
    Security::{Authorization::*, *},
    System::SystemServices::SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};

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
struct Allocation(*mut std::ffi::c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: successful conversion/query transferred this LocalFree allocation.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
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
    // SAFETY: native POD metadata output, initialized before the exact query.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: retained directory and writable exact metadata output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(native::last("read uninstall directory identity"));
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(refuse(
            "read uninstall directory identity",
            "ordinary no-follow directory required",
        ));
    }
    // SAFETY: FILE_ID_INFO is native POD, initialized before its sized query.
    let mut id: FILE_ID_INFO = unsafe { zeroed() };
    // SAFETY: retained directory and exact aligned FileIdInfo output.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(native::last("read uninstall directory file ID"));
    }
    Ok(FileId {
        volume: id.VolumeSerialNumber,
        index: id.FileId.Identifier,
    })
}
pub(super) fn verify_high(file: &File, directory: bool) -> Result<()> {
    let mut sacl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    // SAFETY: retained READ_CONTROL object and exact writable security outputs.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sacl,
            &mut raw,
        )
    };
    let _allocation = Allocation(raw);
    if status != ERROR_SUCCESS {
        return Err(error(
            "read mandatory uninstall label",
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    // SAFETY: successful security query retains the returned ACL allocation.
    if sacl.is_null() || unsafe { IsValidAcl(sacl) } == 0 {
        return Err(refuse(
            "verify mandatory uninstall label",
            "valid High label ACL required",
        ));
    }
    // SAFETY: validated ACL is retained through the following ACE reads.
    if unsafe { (*sacl).AceCount } != 1 {
        return Err(refuse(
            "verify mandatory uninstall label",
            "one exact High mandatory label required",
        ));
    }
    let mut raw_ace = ptr::null_mut();
    // SAFETY: valid nonempty ACL and writable borrowed ACE output.
    if unsafe { GetAce(sacl, 0, &mut raw_ace) } == 0 {
        return Err(native::last("read High mandatory label ACE"));
    }
    // SAFETY: successful GetAce supplies an aligned header in the retained ACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE
        || usize::from(header.AceSize) < size_of::<SYSTEM_MANDATORY_LABEL_ACE>()
        || header.AceFlags & INHERIT_ONLY_ACE as u8 != 0
        || (directory
            && header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8)
    {
        return Err(refuse(
            "verify mandatory uninstall label",
            "applicable inheritable mandatory label required",
        ));
    }
    // SAFETY: validated label ACE type and extent provide its mask and inline SID.
    let ace = unsafe { &*raw_ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
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
pub(super) fn arm_directory_cleanup(custody: &DirectoryCustody, deadline: u64) -> Result<File> {
    let until = deadline.min(clock().saturating_add(2000));
    loop {
        // SAFETY: terminated no-follow path and explicit directory delete-on-close
        // flags; a successful exact reference stays alive through carrier exit.
        let raw = unsafe {
            CreateFileW(
                native::wide(&custody.path)?.as_ptr(),
                GENERIC_READ | READ_CONTROL | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_BACKUP_SEMANTICS
                    | FILE_FLAG_DELETE_ON_CLOSE,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE && !raw.is_null() {
            let file = File::from(native::handle(raw, "arm High staging directory cleanup")?);
            if directory_id(&file)? != custody.id {
                return Err(refuse(
                    "arm High staging cleanup",
                    "directory identity changed",
                ));
            }
            verify_high(&file, true)?;
            return Ok(file);
        }
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() != Some(ERROR_SHARING_VIOLATION as i32) || clock() >= until {
            return Err(error("arm High staging directory cleanup", cause));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
