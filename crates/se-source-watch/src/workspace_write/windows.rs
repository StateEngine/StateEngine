use super::{WorkspaceWriteError, WorkspaceWriteRefusal, stage_name};
use se_state_files::{NativeFileRevision, NativeObjectKey};
use std::{
    fs::File,
    io::{self, Write},
    mem::{size_of, zeroed},
    os::windows::io::AsRawHandle,
    path::Path,
    ptr,
};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
        FileRenameInformation, FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
    },
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::IO::IO_STATUS_BLOCK};

/// O(1) target baseline excluding `ctime_unix_nanos`, which `ReplaceFileW`
/// updates when moving the displaced original to its backup name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetBaseline {
    volume: [u8; 16],
    file: [u8; 16],
    size: u64,
    mtime_unix_nanos: i128,
}

impl TargetBaseline {
    fn from_revision(rev: NativeFileRevision) -> Self {
        Self {
            volume: rev.volume,
            file: rev.file,
            size: rev.size,
            mtime_unix_nanos: rev.mtime_unix_nanos,
        }
    }
}

fn invalid(reason: impl Into<String>) -> WorkspaceWriteError {
    WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(reason.into()))
}

fn io_before(error: io::Error) -> WorkspaceWriteError {
    WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(error))
}

fn wide_path(path: &Path) -> Result<Vec<u16>, WorkspaceWriteError> {
    se_state_files::state_files::windows::wide(path)
        .map_err(|_| invalid("normalized Windows workspace path required"))
}

/// Pin the registered root directory without `FILE_SHARE_DELETE` so neither
/// the root nor any descendant in `chain` can be moved during `ReplaceFileW`.
fn pin_root_no_delete(root: &File, root_path: &Path) -> Result<File, WorkspaceWriteError> {
    let name = wide_path(root_path)?;
    // SAFETY: terminated UTF-16 root path; no reparse traversal, no delete share.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    // SAFETY: CreateFileW returned a newly opened handle owned by this process.
    let pin = unsafe { crate::source_root::windows::owned(raw) }.map_err(|error| {
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
    })?;
    let expected = se_state_files::observe_object_key(root).map_err(|error| {
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
    })?;
    let observed = se_state_files::observe_object_key(&pin).map_err(|error| {
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
    })?;
    if observed != expected {
        return Err(WorkspaceWriteError::BeforePublish(
            WorkspaceWriteRefusal::RootUnverified(io::Error::other(
                "registered physical source root changed before write",
            )),
        ));
    }
    Ok(pin)
}

fn sibling_exists(parent: &File, name: &str) -> bool {
    let Ok(mut units) = utf16_component(name) else {
        return false;
    };
    nt_open_relative(
        parent,
        &mut units,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
    )
    .is_ok()
}

fn matches_staged(file: &File, stage_key: NativeObjectKey, stage_baseline: TargetBaseline) -> bool {
    let Ok(key) = se_state_files::observe_object_key(file) else {
        return false;
    };
    let Ok(rev) = se_state_files::observe_file_revision(file) else {
        return false;
    };
    key == stage_key && TargetBaseline::from_revision(rev) == stage_baseline
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

/// Open or create a child directory without `FILE_SHARE_DELETE` so it cannot
/// be renamed or moved out of the workspace while the returned handle is held.
fn open_or_create_dir(
    parent: &File,
    part: &str,
) -> Result<(File, NativeObjectKey), WorkspaceWriteError> {
    if part.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path enters .git metadata, which StateEngine does not write",
        ));
    }
    let dot_git = dot_git_key(parent)?;
    let mut units = utf16_component(part)?;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
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
    let key = se_state_files::observe_object_key(&child).map_err(io_before)?;
    if dot_git == Some(key) {
        return Err(invalid(
            "path aliases .git metadata, which StateEngine does not write",
        ));
    }
    Ok((child, key))
}

fn verify_parent_chain(
    root: &File,
    chain: &[(&str, File, NativeObjectKey)],
) -> Result<(), WorkspaceWriteError> {
    let mut cursor: Option<File> = None;
    for (part, _, expected_key) in chain {
        let parent = cursor.as_ref().unwrap_or(root);
        let mut units = utf16_component(part)?;
        let fresh = nt_open_relative(
            parent,
            &mut units,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        )
        .map_err(|err| {
            invalid(format!(
                "workspace parent directory changed during write: {err}"
            ))
        })?;
        crate::source_root::windows::verify_handle(&fresh, true)
            .map_err(|e| invalid(e.to_string()))?;
        if se_state_files::observe_object_key(&fresh).map_err(io_before)? != *expected_key {
            return Err(invalid(
                "workspace parent directory was moved or replaced during write",
            ));
        }
        cursor = Some(fresh);
    }
    Ok(())
}

/// Open an existing target leaf with `GENERIC_READ` and `FILE_SHARE_READ |
/// FILE_SHARE_DELETE` (excluding `FILE_SHARE_WRITE`) so no concurrent writer
/// can hold or acquire write access while we stage and replace it.
fn open_target_leaf(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
) -> Result<Option<(File, TargetBaseline)>, WorkspaceWriteError> {
    let existing = match nt_open_relative(
        parent,
        leaf_units,
        GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
    ) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
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
    let rev = se_state_files::observe_file_revision(&existing).map_err(io_before)?;
    Ok(Some((existing, TargetBaseline::from_revision(rev))))
}

fn inspect_target_leaf(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
) -> Result<Option<TargetBaseline>, WorkspaceWriteError> {
    let existing = match nt_open_relative(
        parent,
        leaf_units,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        0,
    ) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
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
    let rev = se_state_files::observe_file_revision(&existing).map_err(io_before)?;
    Ok(Some(TargetBaseline::from_revision(rev)))
}

fn verify_target_unchanged(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
    baseline: Option<TargetBaseline>,
) -> Result<(), WorkspaceWriteError> {
    let current = inspect_target_leaf(parent, leaf_units, dot_git)?;
    match (baseline, current) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(io_before(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "target file was created concurrently during staging",
        ))),
        (Some(_), None) => Err(invalid(
            "target file was removed concurrently during staging",
        )),
        (Some(expected), Some(actual)) => {
            if expected != actual {
                return Err(invalid(
                    "target file changed concurrently during staging; retry write",
                ));
            }
            Ok(())
        }
    }
}

fn dispose_checked(file: &File) -> Result<(), io::Error> {
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
    if ok != 0 {
        return Ok(());
    }
    let fallback = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: DELETE-capable handle and exact FILE_DISPOSITION_INFO layout.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&fallback as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn dispose_stage(file: &File) {
    let _ = dispose_checked(file);
}

fn rename_at(
    file: &File,
    parent: &File,
    leaf_units: &[u16],
    replace_if_exists: bool,
) -> Result<(), io::Error> {
    // NT FILE_RENAME_INFORMATION::Flags values for FileRenameInformationEx.
    const RENAME_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
    const RENAME_POSIX_SEMANTICS: u32 = 0x0000_0002;
    let name_bytes = leaf_units.len() * 2;
    let total = (std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName) + name_bytes)
        .max(size_of::<FILE_RENAME_INFORMATION>());
    let mut buf = vec![0u64; total.div_ceil(size_of::<u64>())];
    // SAFETY: `buf` is 8-byte aligned and sized for FILE_RENAME_INFORMATION + UTF-16 name.
    // NtSetInformationFile natively supports non-null RootDirectory (unlike Win32
    // SetFileInformationByHandle, which rejects non-null RootDirectory with error 87).
    unsafe {
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        (*info).Anonymous.Flags = if replace_if_exists {
            RENAME_REPLACE_IF_EXISTS | RENAME_POSIX_SEMANTICS
        } else {
            RENAME_POSIX_SEMANTICS
        };
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            leaf_units.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            leaf_units.len(),
        );
        let mut status: IO_STATUS_BLOCK = zeroed();
        let code = NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            buf.as_ptr().cast(),
            total as u32,
            FileRenameInformationEx,
        );
        if code >= 0 {
            return Ok(());
        }
        if !matches!(
            code,
            STATUS_INVALID_INFO_CLASS | STATUS_NOT_SUPPORTED | STATUS_INVALID_PARAMETER
        ) {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(code) as i32
            ));
        }
        (*info).Anonymous.Flags = 0;
        (*info).Anonymous.ReplaceIfExists = replace_if_exists;
        let mut fallback_status: IO_STATUS_BLOCK = zeroed();
        let fallback_code = NtSetInformationFile(
            file.as_raw_handle(),
            &mut fallback_status,
            buf.as_ptr().cast(),
            total as u32,
            FileRenameInformation,
        );
        if fallback_code < 0 {
            return Err(io::Error::from_raw_os_error(
                RtlNtStatusToDosError(fallback_code) as i32,
            ));
        }
    }
    Ok(())
}

#[path = "windows_replace.rs"]
mod replace;

use replace::{ReplaceCtx, publish_replace};

pub(super) fn write_relative(
    root: &File,
    root_path: &Path,
    path: &str,
    bytes: &[u8],
    root_check: &dyn Fn() -> io::Result<()>,
) -> Result<(), WorkspaceWriteError> {
    let _root_pin = pin_root_no_delete(root, root_path)?;
    let (parent_prefix, leaf_str) = match path.rsplit_once('/') {
        Some((prefix, leaf)) => (Some(prefix), leaf),
        None => (None, path),
    };
    if leaf_str.eq_ignore_ascii_case(".git") {
        return Err(invalid(
            "path targets .git metadata, which StateEngine does not write",
        ));
    }
    let mut chain: Vec<(&str, File, NativeObjectKey)> = Vec::new();
    let mut parent_path = root_path.to_path_buf();
    if let Some(prefix) = parent_prefix {
        for part in prefix.split('/') {
            let parent = chain.last().map_or(root, |(_, dir, _)| dir);
            let (dir, key) = open_or_create_dir(parent, part)?;
            chain.push((part, dir, key));
            parent_path.push(part);
        }
    }
    let parent = chain.last().map_or(root, |(_, dir, _)| dir);
    let dot_git = dot_git_key(parent)?;
    let mut leaf_units = utf16_component(leaf_str)?;
    let held_target = open_target_leaf(parent, &mut leaf_units, dot_git)?;
    let baseline = held_target.as_ref().map(|(_, rev)| *rev);

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
    let stage_key = se_state_files::observe_object_key(&stage).map_err(|error| {
        dispose_stage(&stage);
        io_before(error)
    })?;
    let stage_baseline = se_state_files::observe_file_revision(&stage)
        .map(TargetBaseline::from_revision)
        .map_err(|error| {
            dispose_stage(&stage);
            io_before(error)
        })?;
    let pre_publish = (|| -> Result<(), WorkspaceWriteError> {
        root_check().map_err(|error| {
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::RootUnverified(error))
        })?;
        verify_parent_chain(root, &chain)?;
        verify_target_unchanged(parent, &mut leaf_units, dot_git, baseline)
    })();
    if let Err(error) = pre_publish {
        dispose_stage(&stage);
        return Err(error);
    }

    if let Some((held_file, expected)) = held_target {
        // Close staging handle so ReplaceFileW can open it exclusively.
        drop(stage);
        return publish_replace(
            &ReplaceCtx {
                root,
                chain: &chain,
                parent,
                parent_path: &parent_path,
                leaf_str,
                stage_str: &stage_str,
                stage_key,
                stage_baseline,
                expected,
                root_check,
            },
            held_file,
        );
    }

    // Absent-destination exclusive creation via handle-relative NtSetInformationFile.
    if let Err(error) = rename_at(&stage, parent, &leaf_units, false).map_err(io_before) {
        dispose_stage(&stage);
        return Err(error);
    }
    verify_parent_chain(root, &chain).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "workspace parent ancestry changed after publication: {error}"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
