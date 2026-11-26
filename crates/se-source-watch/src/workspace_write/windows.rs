use super::{WorkspaceWriteError, WorkspaceWriteRefusal, stage_name};
use se_state_files::{NativeFileRevision, NativeObjectKey};
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
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
        FileRenameInformation, FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
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
/// can hold or acquire write access while we stage and atomically replace it.
fn open_target_leaf(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
) -> Result<Option<(File, NativeFileRevision)>, WorkspaceWriteError> {
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
    Ok(Some((existing, rev)))
}

fn inspect_target_leaf(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
) -> Result<Option<NativeFileRevision>, WorkspaceWriteError> {
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
    Ok(Some(rev))
}

fn verify_target_unchanged(
    parent: &File,
    leaf_units: &mut [u16],
    dot_git: Option<NativeObjectKey>,
    baseline: Option<NativeFileRevision>,
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

pub(super) fn write_relative(
    root: &File,
    path: &str,
    bytes: &[u8],
    root_check: &dyn Fn() -> io::Result<()>,
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
    let mut chain: Vec<(&str, File, NativeObjectKey)> = Vec::new();
    if let Some(prefix) = parent_prefix {
        for part in prefix.split('/') {
            let parent = chain.last().map_or(root, |(_, dir, _)| dir);
            let (dir, key) = open_or_create_dir(parent, part)?;
            chain.push((part, dir, key));
        }
    }
    let parent = chain.last().map_or(root, |(_, dir, _)| dir);
    let dot_git = dot_git_key(parent)?;
    let mut leaf_units = utf16_component(leaf_str)?;
    // Hold the existing target open without FILE_SHARE_WRITE through rename_at
    // so no concurrent editor/writer can modify it while we stage and replace.
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
    if let Err(error) =
        rename_at(&stage, parent, &leaf_units, baseline.is_some()).map_err(io_before)
    {
        dispose_stage(&stage);
        return Err(error);
    }
    drop(held_target);
    verify_parent_chain(root, &chain).map_err(|error| {
        WorkspaceWriteError::PublishedUncertain(format!(
            "workspace parent ancestry changed after publication: {error}"
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_root::NativeSourceRoot;
    use std::path::PathBuf;

    type Check = Result<(), Box<dyn std::error::Error>>;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(label: &str) -> Result<Scratch, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "se-workspace-write-win-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(Scratch(dir))
    }

    #[test]
    fn write_relative_creates_replaces_and_refuses_concurrent_create() -> Check {
        let dir = scratch("nt-rename")?;
        let root = NativeSourceRoot::open(&dir.0)?;

        // Create new file under nested directory via handle-relative NtSetInformationFile.
        root.write_relative("nested/note.txt", b"v1")?;
        assert_eq!(std::fs::read(dir.0.join("nested").join("note.txt"))?, b"v1");

        // Replace existing file atomically.
        root.write_relative("nested/note.txt", b"v2-updated")?;
        assert_eq!(
            std::fs::read(dir.0.join("nested").join("note.txt"))?,
            b"v2-updated"
        );

        // Non-replacing rename must refuse overwriting an existing target.
        let mut stage_units = utf16_component("stage.tmp")?;
        let leaf_units = utf16_component("existing.txt")?;
        std::fs::write(dir.0.join("existing.txt"), b"other-writer")?;
        let mut stage = nt_open_relative(
            &root.directory,
            &mut stage_units,
            DELETE | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
            0,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
        )?;
        stage.write_all(b"stale-create")?;
        let err = rename_at(&stage, &root.directory, &leaf_units, false)
            .err()
            .ok_or("expected non-replacing rename to fail on existing target")?;
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        dispose_stage(&stage);
        drop(stage);
        // An open concurrent writer holding write access must block replacement
        // cleanly instead of being silently clobbered.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.0.join("existing.txt"))?;
        let conflict = root
            .write_relative("existing.txt", b"clobber")
            .err()
            .ok_or("expected open writer to block replacement")?;
        assert!(matches!(
            conflict,
            WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(_))
        ));
        drop(writer);
        assert_eq!(std::fs::read(dir.0.join("existing.txt"))?, b"other-writer");
        Ok(())
    }
}
