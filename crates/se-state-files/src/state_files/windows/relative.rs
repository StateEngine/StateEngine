//! Handle-relative reads beneath a retained, recently verified directory.
use super::*;
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    },
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) fn retry_by_name(error: &StateFileError) -> bool {
    error.source.as_ref().is_some_and(|source| {
        matches!(
            source.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
        )
    })
}

pub(super) fn open(
    parent: &File,
    leaf: &std::ffi::OsStr,
    path: &Path,
    directory: bool,
) -> Result<File> {
    let mut units = literal_leaf(leaf, path)?;
    let mut name = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: 0x40,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut raw = ptr::null_mut();
    // SAFETY: native completion output is initialized for the synchronous call.
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    // SAFETY: a single validated name is resolved relative to the retained parent.
    let code = unsafe {
        NtCreateFile(
            &mut raw,
            GENERIC_READ | READ_CONTROL | SYNCHRONIZE | if directory { GENERIC_WRITE } else { 0 },
            &attributes,
            &mut status,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | if directory { 0 } else { FILE_SHARE_DELETE },
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | if directory {
                    FILE_DIRECTORY_FILE
                } else {
                    FILE_NON_DIRECTORY_FILE
                },
            ptr::null(),
            0,
        )
    };
    if code < 0 {
        // SAFETY: native status conversion takes no pointers.
        return Err(io_error(
            "open relative protected name",
            path,
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(code) } as i32),
        ));
    }
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(unsafe_path("relative open returned no handle", path));
    }
    // SAFETY: successful native open returned one owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}

impl Directory {
    pub(super) fn readback_relative(&self, path: &Path) -> Result<Option<File>> {
        let leaf = path
            .file_name()
            .ok_or_else(|| unsafe_path("state file name missing", path))?;
        let file = match open(&self.file, leaf, path, false) {
            Ok(file) => file,
            Err(error)
                if error
                    .source
                    .as_ref()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        metadata_for(&file, path, false, self.layout)?;
        Ok(Some(file))
    }
}
