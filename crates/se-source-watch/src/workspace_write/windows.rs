use super::{WorkspaceWriteError, WorkspaceWriteRefusal, stage_name};
use se_state_files::NativeObjectKey;
use std::{
    fs::File,
    io::{self, Write},
    mem::{size_of, zeroed},
    os::windows::io::AsRawHandle,
    ptr,
};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    },
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::IO::IO_STATUS_BLOCK};

fn invalid(reason: impl Into<String>) -> WorkspaceWriteError {
    WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(reason.into()))
}

fn io_before(error: io::Error) -> WorkspaceWriteError {
    WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(error))
}

fn utf16_component(part: &str) -> Result<Vec<u16>, WorkspaceWriteError> {
    if part.is_empty() || part.ends_with(['.', ' ']) {
        return Err(invalid("ambiguous or empty Windows path component"));
    }
    let units: Vec<u16> = part.encode_utf16().collect();
    if units.is_empty() || units.len() > u16::MAX as usize / 2 {
        return Err(invalid("bounded Windows path component required"));
    }
    Ok(units)
}

fn nt_open_relative(
    parent: &File,
    units: &mut [u16],
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<File, io::Error> {
    let mut name = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: 0,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut raw = ptr::null_mut();
    // SAFETY: POD native completion output initialized to zero.
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    // SAFETY: literal component relative to retained parent directory handle;
    // FILE_OPEN_REPARSE_POINT prevents reparse/symlink traversal.
    let code = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if code < 0 {
        // SAFETY: NTSTATUS conversion takes no pointers.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(code) } as i32,
        ));
    }
    // SAFETY: successful NtCreateFile transferred unique handle ownership.
    unsafe { crate::source_root::windows::owned(raw) }
}

fn dot_git_key(parent: &File) -> Result<Option<NativeObjectKey>, WorkspaceWriteError> {
    let mut units: Vec<u16> = ".git".encode_utf16().collect();
    match nt_open_relative(
        parent,
        &mut units,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
    ) {
        Ok(file) => Ok(Some(
            se_state_files::observe_object_key(&file).map_err(io_before)?,
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(io_before(err)),
    }
}

fn open_or_create_dir(parent: &File, part: &str) -> Result<File, WorkspaceWriteError> {
    if part.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path enters .git metadata, which StateEngine does not write",
        ));
    }
    let dot_git = dot_git_key(parent)?;
    let mut units = utf16_component(part)?;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let child = match nt_open_relative(
        parent,
        &mut units,
        GENERIC_READ | SYNCHRONIZE,
        share,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    ) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            match nt_open_relative(
                parent,
                &mut units,
                GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                share,
                FILE_CREATE,
                FILE_DIRECTORY_FILE,
            ) {
                Ok(dir) => dir,
                Err(create_err) if create_err.kind() == io::ErrorKind::AlreadyExists => {
                    nt_open_relative(
                        parent,
                        &mut units,
                        GENERIC_READ | SYNCHRONIZE,
                        share,
                        FILE_OPEN,
                        FILE_DIRECTORY_FILE,
                    )
                    .map_err(io_before)?
                }
                Err(create_err) => return Err(io_before(create_err)),
            }
        }
        Err(err) => return Err(io_before(err)),
    };
    crate::source_root::windows::verify_handle(&child, true).map_err(|e| invalid(e.to_string()))?;
    if dot_git.is_some()
        && Some(se_state_files::observe_object_key(&child).map_err(io_before)?) == dot_git
    {
        return Err(invalid(
            "path aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok(child)
}

fn inspect_target_leaf(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
) -> Result<(), WorkspaceWriteError> {
    let existing = match nt_open_relative(
        parent,
        leaf_units,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
    ) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(io_before(err)),
    };
    crate::source_root::windows::verify_handle(&existing, false)
        .map_err(|e| invalid(e.to_string()))?;
    if dot_git.is_some()
        && Some(se_state_files::observe_object_key(&existing).map_err(io_before)?) == dot_git
    {
        return Err(invalid(
            "target aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok(())
}

fn dispose_stage(file: &File) {
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: DELETE-capable handle and exact FILE_DISPOSITION_INFO_EX layout.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        let fallback = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: DELETE-capable handle and exact FILE_DISPOSITION_INFO layout.
        let _ = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&fallback as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
    }
}

fn rename_replace_at(file: &File, parent: &File, leaf_units: &[u16]) -> Result<(), io::Error> {
    // Win32 FILE_RENAME_INFO::Flags values for FileRenameInfoEx.
    const RENAME_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
    const RENAME_POSIX_SEMANTICS: u32 = 0x0000_0002;
    let name_bytes = leaf_units.len() * 2;
    let total = size_of::<FILE_RENAME_INFO>() + name_bytes;
    let mut buf = vec![0u64; total.div_ceil(size_of::<u64>())];
    // SAFETY: `buf` is 8-byte aligned and sized for FILE_RENAME_INFO + UTF-16 name.
    unsafe {
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*info).Anonymous.Flags = RENAME_REPLACE_IF_EXISTS | RENAME_POSIX_SEMANTICS;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            leaf_units.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            leaf_units.len(),
        );
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfoEx,
            buf.as_ptr().cast(),
            total as u32,
        ) != 0
        {
            return Ok(());
        }
        let first_err = io::Error::last_os_error();
        if !matches!(
            first_err.raw_os_error(),
            Some(c) if c == ERROR_INVALID_PARAMETER as i32 || c == ERROR_NOT_SUPPORTED as i32
        ) {
            return Err(first_err);
        }
        (*info).Anonymous.ReplaceIfExists = true;
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            buf.as_ptr().cast(),
            total as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(super) fn write_relative(
    root: &File,
    path: &str,
    bytes: &[u8],
) -> Result<(), WorkspaceWriteError> {
    let (parent_prefix, leaf_str) = match path.rsplit_once('/') {
        Some((prefix, leaf)) => (Some(prefix), leaf),
        None => (None, path),
    };
    if leaf_str.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path targets .git metadata, which StateEngine does not write",
        ));
    }
    let mut held: Option<File> = None;
    if let Some(prefix) = parent_prefix {
        for part in prefix.split('/') {
            let parent = held.as_ref().unwrap_or(root);
            held = Some(open_or_create_dir(parent, part)?);
        }
    }
    let parent = held.as_ref().unwrap_or(root);
    let dot_git = dot_git_key(parent)?;
    let mut leaf_units = utf16_component(leaf_str)?;
    inspect_target_leaf(parent, &mut leaf_units, dot_git)?;

    let stage_str = stage_name()?;
    let mut stage_units = utf16_component(&stage_str)?;
    let mut stage = nt_open_relative(
        parent,
        &mut stage_units,
        DELETE | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    )
    .map_err(io_before)?;
    if let Err(error) = stage
        .write_all(bytes)
        .and_then(|()| stage.sync_all())
        .map_err(io_before)
    {
        dispose_stage(&stage);
        return Err(error);
    }
    if let Err(error) = inspect_target_leaf(parent, &mut leaf_units, dot_git) {
        dispose_stage(&stage);
        return Err(error);
    }
    if let Err(error) = rename_replace_at(&stage, parent, &leaf_units).map_err(io_before) {
        dispose_stage(&stage);
        return Err(error);
    }
    Ok(())
}
