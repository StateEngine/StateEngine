use super::*;
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    },
};
use windows_sys::Win32::{
    Foundation::{RtlNtStatusToDosError, UNICODE_STRING},
    System::IO::IO_STATUS_BLOCK,
};

pub(in crate::state_files) struct CreatedDirectory {
    path: PathBuf,
    file: File,
    identity: Identity,
    parent: Parent,
}
impl CreatedDirectory {
    pub(in crate::state_files) fn path(&self) -> &Path {
        &self.path
    }
    pub(in crate::state_files) fn cleanup(&self) -> Result<DirectoryRemoval> {
        let (parent, physical) = location(&self.path)?;
        if parent.identity != self.parent.identity {
            return Err(changed(
                "created directory parent identity changed; preserved",
                &self.path,
            ));
        }
        let named = match open(&physical, true, 0, false) {
            Ok(file) => file,
            Err(error) if absent(&error) => return Ok(DirectoryRemoval::AlreadyAbsent),
            Err(error) => return Err(error),
        };
        if metadata(&named, &self.path, true, false)? != self.identity
            || metadata(&self.file, &self.path, true, false)? != self.identity
        {
            return Err(changed(
                "created directory identity differs; preserved",
                &self.path,
            ));
        }
        security::verify(&self.file, &self.path, false)?;
        // An empty relative name reopens the retained directory itself. Unlike
        // an open by file ID this preserves the directory-link context needed
        // by native disposition, without granting custody to a later pathname.
        let mut name = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.file.as_raw_handle(),
            ObjectName: &mut name,
            Attributes: 0x40,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };
        let mut raw = ptr::null_mut();
        // SAFETY: native POD output initialized before the synchronous call.
        let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
        // SAFETY: the empty relative name resolves only the retained live root
        // handle, with cleanup-only access and no final-path lookup.
        let code = unsafe {
            NtCreateFile(
                &mut raw,
                GENERIC_READ | READ_CONTROL | DELETE | SYNCHRONIZE,
                &attributes,
                &mut status,
                ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if code < 0 {
            // SAFETY: native status translation has no pointer inputs.
            return Err(io_error(
                "reopen retained created directory for cleanup",
                &self.path,
                io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(code) } as i32),
            ));
        }
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(changed("created cleanup returned no handle", &self.path));
        }
        // SAFETY: successful native open transferred a uniquely owned handle.
        let cleanup = unsafe { File::from_raw_handle(raw) };
        if metadata(&cleanup, &self.path, true, false)? != self.identity {
            return Err(changed(
                "created cleanup handle identity differs",
                &self.path,
            ));
        }
        if let Err(error) = dispose(&cleanup, &self.path) {
            return if error
                .source
                .as_ref()
                .is_some_and(|cause| cause.raw_os_error() == Some(ERROR_DIR_NOT_EMPTY as i32))
            {
                Ok(DirectoryRemoval::NotEmpty)
            } else {
                Err(error)
            };
        }
        // POSIX disposition removes the name when this DELETE-capable handle
        // closes; the original creation handle remains retained for identity.
        drop(cleanup);
        self.parent.sync(&self.path)?;
        match open(&physical, true, 0, false) {
            Err(error) if absent(&error) => Ok(DirectoryRemoval::Removed),
            Err(error) => Err(error),
            Ok(_) => Err(changed(
                "created directory remained after native cleanup",
                &self.path,
            )),
        }
    }
}
pub(in crate::state_files) fn prepare_created_directory(
    path: &Path,
    created: &mut Vec<CreatedDirectory>,
) -> Result<()> {
    // Existing ancestors are read-only observations, never creation custody.
    // Do not demand WRITE access to system ancestors such as C:\Users merely
    // to traverse an already-existing user profile.
    wide(path)?;
    match open(path, true, 0, false) {
        Ok(file) => {
            metadata(&file, path, true, false)?;
            return Ok(());
        }
        Err(error) if absent(&error) => (),
        Err(error) => return Err(error),
    }
    let (parent, physical) = location(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| unsafe_path("directory creation leaf missing", path))?;
    let mut units: Vec<u16> = name.encode_wide().collect();
    if units.is_empty() || units.len() > u16::MAX as usize / 2 || units.contains(&0) {
        return Err(unsafe_path("bounded literal directory leaf required", path));
    }
    let mut unicode = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let descriptor = security::descriptor(path, true)?;
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.file()?.as_raw_handle(),
        ObjectName: &mut unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE; no inherited handle or namespace escape.
        SecurityDescriptor: descriptor.0.cast(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut raw = ptr::null_mut();
    // SAFETY: native POD completion result, initialized before the synchronous call.
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    // SAFETY: retained trusted parent handle, one validated relative leaf,
    // protected descriptor and initialized outputs. FILE_CREATE never opens
    // an existing directory; its returned handle is the created object's custody.
    let code = unsafe {
        NtCreateFile(
            &mut raw,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if code < 0 {
        // SAFETY: native status translation has no pointer inputs.
        let cause = io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(code) } as i32);
        if cause.kind() == io::ErrorKind::AlreadyExists {
            let file = open(&physical, true, 0, false)?;
            metadata(&file, path, true, false)?;
            return Ok(());
        }
        return Err(io_error(
            "create directory with retained native handle",
            path,
            cause,
        ));
    }
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(changed(
            "native directory creation returned no handle",
            path,
        ));
    }
    // SAFETY: successful synchronous FILE_CREATE transferred unique ownership.
    let file = unsafe { File::from_raw_handle(raw) };
    let identity = metadata(&file, path, true, false)?;
    // Retain custody before any later verification can fail, so failed init
    // still offers exact identity-bound cleanup for everything it created.
    created.push(CreatedDirectory {
        path: path.into(),
        file,
        identity,
        parent,
    });
    let held = created
        .last()
        .ok_or_else(|| changed("created directory custody unavailable", path))?;
    if status.Information != 2 {
        return Err(changed("native create did not report FILE_CREATED", path));
    }
    security::verify(&held.file, path, false)?;
    let named = open(&physical, true, 0, false)?;
    if metadata(&named, path, true, false)? != held.identity {
        return Err(changed("created directory name identity differs", path));
    }
    held.file
        .sync_all()
        .map_err(|error| io_error("flush created native directory", path, error))?;
    held.parent.sync(path)
}

pub(in crate::state_files) fn validate_creation_target(path: &Path) -> Result<()> {
    let (_parent, physical) = location(path)?;
    let file = open(&physical, true, 0, false)?;
    metadata(&file, path, true, false)?;
    security::verify_no_foreign_writer(&file, path)
}
