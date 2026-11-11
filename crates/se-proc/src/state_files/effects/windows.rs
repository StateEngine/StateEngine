use super::{Identity, last, metadata, random, security, wide};
use crate::state_files::effects::{DirectoryRemoval, absent, changed, digest, verify};
use crate::state_files::{Result, io_error, unsafe_path};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Write},
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::{Component, Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{Foundation::*, Security::*, Storage::FileSystem::*};

#[path = "permissions_windows.rs"]
pub(in crate::state_files) mod permissions;

#[path = "windows/parent.rs"]
mod parent;
use parent::{Parent, location};

fn open(path: &Path, directory: bool, access: u32, create: bool) -> Result<File> {
    open_shared(path, directory, access, create, true)
}
fn open_shared(
    path: &Path,
    directory: bool,
    access: u32,
    create: bool,
    share_write: bool,
) -> Result<File> {
    open_shared_with_layout(
        path,
        directory,
        access,
        create,
        share_write,
        security::Layout::State,
    )
}
fn open_shared_with_layout(
    path: &Path,
    directory: bool,
    access: u32,
    create: bool,
    share_write: bool,
    layout: security::Layout,
) -> Result<File> {
    let name = wide(path)?;
    let descriptor = if create {
        Some(security::descriptor_for(path, false, layout)?)
    } else {
        None
    };
    let attributes = descriptor.as_ref().map(|d| SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: d.0,
        bInheritHandle: 0,
    });
    // SAFETY: retained terminated pathname, optional native security descriptor
    // and correctly sized attributes; no handle inheritance or reparse traversal.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            READ_CONTROL
                | if directory {
                    FILE_READ_ATTRIBUTES | access
                } else {
                    if access == FILE_READ_ATTRIBUTES {
                        FILE_READ_ATTRIBUTES
                    } else {
                        GENERIC_READ | DELETE | access | if create { GENERIC_WRITE } else { 0 }
                    }
                },
            FILE_SHARE_READ | FILE_SHARE_DELETE | if share_write { FILE_SHARE_WRITE } else { 0 },
            attributes.as_ref().map_or(ptr::null(), |a| a as *const _),
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
            ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last("pin installation object", path));
    }
    // SAFETY: successful CreateFileW transfers one uniquely owned native handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn dispose(file: &File, path: &Path) -> Result<()> {
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: held DELETE-capable handle and exact FILE_DISPOSITION_INFO_EX layout.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        return Err(last("remove exact pinned installation object", path));
    }
    Ok(())
}
pub(in crate::state_files) struct Pin {
    path: PathBuf,
    physical: PathBuf,
    parent: Parent,
    file: File,
    identity: Identity,
    claim: bool,
    layout: security::Layout,
}
impl Pin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        let (parent, physical) = match location(path) {
            Ok(v) => v,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let file = match open(&physical, false, 0, false) {
            Ok(v) => v,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let identity = metadata(&file, path, false, false)?;
        security::verify_owner(&file, path)?;
        let pin = Self {
            path: path.into(),
            physical,
            parent,
            file,
            identity,
            claim: false,
            layout: security::Layout::State,
        };
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn open_profile(path: &Path) -> Result<Option<Self>> {
        let Some(mut pin) = Self::open(path)? else {
            return Ok(None);
        };
        pin.layout = security::Layout::UserPrivate;
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn create_claim(path: &Path) -> Result<Self> {
        let (parent, physical) = location(path)?;
        // Every account-wide claimant requests WRITE while denying WRITE
        // sharing. An inherited duplicate preserves this exclusion even after
        // the holder process exits and its byte-range lock is released.
        let file = match open_shared(&physical, false, GENERIC_WRITE, false, false) {
            Ok(file) => file,
            Err(error) if absent(&error) => {
                match open_shared(&physical, false, GENERIC_WRITE, true, false) {
                    Ok(file) => {
                        file.sync_all().map_err(|error| {
                            io_error("flush new installation claim", path, error)
                        })?;
                        parent.sync(path)?;
                        file
                    }
                    Err(error)
                        if error
                            .source
                            .as_ref()
                            .is_some_and(|cause| cause.kind() == io::ErrorKind::AlreadyExists) =>
                    {
                        open_shared(&physical, false, GENERIC_WRITE, false, false)?
                    }
                    Err(error) => return Err(claim_error(error)),
                }
            }
            Err(error) => return Err(claim_error(error)),
        };
        let identity = metadata(&file, path, false, false)?;
        security::verify(&file, path, true)?;
        let pin = Self {
            path: path.into(),
            physical,
            parent,
            file,
            identity,
            claim: true,
            layout: security::Layout::State,
        };
        pin.check()?;
        Ok(pin)
    }
    pub(in crate::state_files) fn claim_record(&self) -> Result<()> {
        self.check()?;
        security::verify_no_foreign_writer(&self.file, &self.path)?;
        // SAFETY: initialized synchronous OVERLAPPED with offset zero, retained
        // readable record handle and one-byte exclusive lock that fails immediately.
        let mut overlap: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { zeroed() };
        // Lock outside all representable record content, leaving normal reads
        // available while retaining the shared protocol's exclusive byte range.
        overlap.Anonymous.Anonymous.Offset = u32::MAX - 1;
        overlap.Anonymous.Anonymous.OffsetHigh = u32::MAX;
        // SAFETY: retained file and initialized overlap identify the high-offset byte.
        if unsafe {
            LockFileEx(
                self.file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlap,
            )
        } == 0
        {
            return Err(last(
                "installation record is busy; retry after install or uninstall finishes",
                &self.path,
            ));
        }
        self.check()
    }
    pub(in crate::state_files) fn file(&self) -> &File {
        &self.file
    }
    pub(in crate::state_files) fn path(&self) -> &Path {
        &self.path
    }
    fn check_parent(&self) -> Result<()> {
        let (current, _) = location(&self.path)?;
        if current.identity != self.parent.identity {
            return Err(changed("installation parent identity changed", &self.path));
        }
        if self.layout == security::Layout::UserPrivate {
            let path = self
                .path
                .parent()
                .ok_or_else(|| unsafe_path("profile parent missing", &self.path))?;
            security::verify_for(current.file()?, path, false, self.layout)?;
            security::verify_for(self.parent.file()?, path, false, self.layout)?;
        }
        Ok(())
    }
    pub(in crate::state_files) fn check(&self) -> Result<()> {
        self.check_parent()?;
        let current = open(
            &self.physical,
            false,
            if self.claim { FILE_READ_ATTRIBUTES } else { 0 },
            false,
        )?;
        if metadata(&current, &self.path, false, false)? != self.identity
            || metadata(&self.file, &self.path, false, false)? != self.identity
        {
            return Err(changed("installation file identity changed", &self.path));
        }
        security::verify_owner(&current, &self.path)?;
        if self.layout == security::Layout::UserPrivate {
            security::verify_for(&current, &self.path, true, self.layout)?;
            security::verify_for(&self.file, &self.path, true, self.layout)?;
        }
        Ok(())
    }
    pub(in crate::state_files) fn mutation_guard(&self) -> Result<File> {
        self.check()?;
        let guard = open_shared(&self.physical, false, 0, false, false)?;
        if metadata(&guard, &self.path, false, false)? != self.identity {
            return Err(changed(
                "installation object changed before mutation custody",
                &self.path,
            ));
        }
        Ok(guard)
    }
    pub(in crate::state_files) fn remove(self, expected: [u8; 32]) -> Result<()> {
        let _guard = self.mutation_guard()?;
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        self.check()?;
        dispose(&self.file, &self.path)?;
        drop(self.file);
        self.parent.sync(&self.path)?;
        let (outside, physical) = location(&self.path)?;
        if outside.identity != self.parent.identity {
            return Err(changed(
                "installation parent changed after removal",
                &self.path,
            ));
        }
        match open(&physical, false, 0, false) {
            Err(e) if absent(&e) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(changed(
                "installation file remained after removal",
                &self.path,
            )),
        }
    }
    pub(in crate::state_files) fn restore_to(
        self,
        destination: &Path,
        expected: [u8; 32],
    ) -> Result<()> {
        let _guard = self.mutation_guard()?;
        wide(destination)?;
        if destination.parent() != self.path.parent() || destination == self.path {
            return Err(unsafe_path(
                "recovery target must be a distinct exact name in the held parent",
                destination,
            ));
        }
        let target = self.parent.path.join(
            destination
                .file_name()
                .ok_or_else(|| unsafe_path("recovery target leaf missing", destination))?,
        );
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        self.check()?;
        // SAFETY: two exact normalized names beneath the pinned physical parent;
        // no REPLACE_EXISTING or copy fallback. The held source identity survives.
        if unsafe {
            MoveFileExW(
                wide(&self.physical)?.as_ptr(),
                wide(&target)?.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(last(
                "restore exact recovery object without replacement",
                destination,
            ));
        }
        self.parent.sync(destination)?;
        self.check_parent()?;
        let outside = open(&target, false, 0, false)?;
        security::verify_owner(&outside, destination)?;
        if metadata(&outside, destination, false, false)? != self.identity
            || digest(&outside, destination)? != expected
        {
            return Err(changed(
                "restored recovery object changed on outside readback",
                destination,
            ));
        }
        match open(&self.physical, false, 0, false) {
            Err(error) if absent(&error) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(changed(
                "recovery source pathname reappeared after restoration; preserved",
                &self.path,
            )),
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(in crate::state_files) fn replace(self, expected: [u8; 32], bytes: &[u8]) -> Result<()> {
        let _guard = self.mutation_guard()?;
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        let random = random(&self.path)?;
        let suffix: String = se_types::hex_lower(&random);
        let stage_path = self.physical.with_file_name(format!(".se-edit-{suffix}"));
        let backup_path = self
            .physical
            .with_file_name(format!(".se-edit-backup-{suffix}"));
        let mut stage = open_shared_with_layout(&stage_path, false, 0, true, true, self.layout)?;
        if self.layout == security::Layout::UserPrivate {
            security::verify_for(&stage, &stage_path, true, self.layout)?;
        }
        let stage_identity = metadata(&stage, &stage_path, false, false)?;
        let prepared = (|| {
            stage
                .write_all(bytes)
                .map_err(|e| io_error("write staged profile", &stage_path, e))?;
            stage
                .sync_all()
                .map_err(|e| io_error("flush staged profile", &stage_path, e))?;
            self.check()?;
            verify(&self.file, &self.path, expected)?;
            self.check()
        })();
        if let Err(error) = prepared {
            dispose(&stage, &stage_path)?;
            return Err(error);
        }
        // ReplaceFileW opens the replacement with no sharing. Close our staging
        // handle, retaining its native identity and the original profile pin.
        drop(stage);
        // SAFETY: absolute physical names below pinned parents and terminated
        // UTF-16 buffers. A unique backup preserves the old profile even for the
        // documented partial-failure outcomes of ReplaceFileW; it is not a journal.
        if unsafe {
            ReplaceFileW(
                wide(&self.physical)?.as_ptr(),
                wide(&stage_path)?.as_ptr(),
                wide(&backup_path)?.as_ptr(),
                0,
                ptr::null(),
                ptr::null(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_UNABLE_TO_REMOVE_REPLACED as i32) {
                let staging = open(&stage_path, false, 0, false)?;
                if metadata(&staging, &stage_path, false, false)? != stage_identity {
                    return Err(changed(
                        "profile staging identity changed before cleanup",
                        &stage_path,
                    ));
                }
                dispose(&staging, &stage_path)?;
                drop(staging);
                self.parent.sync(&self.path)?;
                return Err(io_error(
                    "profile replacement refused before publication; staging removed",
                    &self.path,
                    error,
                ));
            }
            // Other outcomes may have displaced the old profile. Retain recovery
            // siblings and the exact native cause, rather than deleting evidence.
            return Err(io_error(
                "profile replacement failed; preserve recovery siblings",
                &backup_path,
                error,
            ));
        }
        self.check_parent()?;
        let access = if self.layout == security::Layout::UserPrivate {
            WRITE_DAC
        } else {
            0
        };
        let observed = open(&self.physical, false, access, false)?;
        let wanted: [u8; 32] = Sha256::digest(bytes).into();
        if metadata(&observed, &self.path, false, false)? != stage_identity
            || digest(&observed, &self.path)? != wanted
        {
            return Err(changed(
                "profile replacement readback differs; original retained at recovery sibling",
                &backup_path,
            ));
        }
        security::verify_owner(&observed, &self.path)?;
        if self.layout == security::Layout::UserPrivate {
            // Replacement merges the incumbent DACL into our staged object.
            // Finish only this identity/content/owner-verified new output;
            // the held original and its recovery sibling stay untouched.
            security::finish_private_replacement(&observed, &self.path)?;
            security::verify_for(&observed, &self.path, true, self.layout)?;
        }
        // The backup is the still-held original object, not a new path claim.
        let backup = open(&backup_path, false, 0, false)?;
        if metadata(&backup, &backup_path, false, false)? != self.identity {
            return Err(changed("profile backup identity changed", &backup_path));
        }
        drop(backup);
        dispose(&self.file, &backup_path)?;
        drop(self.file);
        self.parent.sync(&self.path)?;
        match open(&backup_path, false, 0, false) {
            Err(e) if absent(&e) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(changed(
                "profile recovery sibling remained after completion",
                &backup_path,
            )),
        }
    }
}
pub(in crate::state_files) fn remove_empty_directory(path: &Path) -> Result<DirectoryRemoval> {
    let (parent, physical) = match location(path) {
        Ok(v) => v,
        Err(e) if absent(&e) => return Ok(DirectoryRemoval::AlreadyAbsent),
        Err(e) => return Err(e),
    };
    // The retained state root deliberately denies delete sharing. Preserve a
    // nonempty directory before requesting DELETE; its retained history/config
    // must not turn successful archive recovery into a sharing violation.
    let observed = match open(&physical, true, 0, false) {
        Ok(file) => file,
        Err(error) if absent(&error) => return Ok(DirectoryRemoval::AlreadyAbsent),
        Err(error) => return Err(error),
    };
    let identity = metadata(&observed, path, true, false)?;
    security::verify_owner(&observed, path)?;
    if recovery::has_entries(&physical)? {
        let outside = open(&physical, true, 0, false)?;
        let (outside_parent, _) = location(path)?;
        if metadata(&outside, path, true, false)? != identity
            || outside_parent.identity != parent.identity
        {
            return Err(changed(
                "nonempty directory changed during inspection",
                path,
            ));
        }
        return Ok(DirectoryRemoval::NotEmpty);
    }
    let directory = match open(
        &physical,
        true,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        false,
    ) {
        Ok(v) => v,
        Err(e) if absent(&e) => return Ok(DirectoryRemoval::AlreadyAbsent),
        Err(e) => return Err(e),
    };
    if metadata(&directory, path, true, false)? != identity {
        return Err(changed("empty directory changed before removal", path));
    }
    security::verify_owner(&directory, path)?;
    if let Err(error) = dispose(&directory, path) {
        return if error
            .source
            .as_ref()
            .is_some_and(|e| e.raw_os_error() == Some(ERROR_DIR_NOT_EMPTY as i32))
        {
            Ok(DirectoryRemoval::NotEmpty)
        } else {
            Err(error)
        };
    }
    drop(directory);
    parent.sync(path)?;
    let (outside, physical) = location(path)?;
    if outside.identity != parent.identity {
        return Err(changed("directory parent changed after removal", path));
    }
    match open(&physical, true, 0, false) {
        Err(e) if absent(&e) => Ok(DirectoryRemoval::Removed),
        Err(e) => Err(e),
        Ok(_) => Err(changed("directory remained after removal", path)),
    }
}

/// Retain an admitted directory without requesting DELETE while the native
/// state-root pin still denies delete sharing. The carrier reopens this exact
/// object with DELETE only after the actual parent exits.
pub(crate) fn uninstall_directory(path: &Path) -> Result<Option<File>> {
    let (_parent, physical) = match location(path) {
        Ok(value) => value,
        Err(error) if absent(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let file = match open(&physical, true, GENERIC_READ | GENERIC_WRITE, false) {
        Ok(file) => file,
        Err(error) if absent(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    metadata(&file, path, true, false)?;
    security::verify_owner(&file, path)?;
    Ok(Some(file))
}

#[path = "recovery_windows.rs"]
mod recovery;
pub(in crate::state_files) use recovery::{list_names, scan_recovery, scan_temporary};

pub(in crate::state_files) fn installation_claim_path() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::{
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::Shell::GetUserProfileDirectoryW,
    };
    let path = Path::new("native account profile");
    let mut token = ptr::null_mut();
    // SAFETY: current process, query-only token and valid native output pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last("open native account token", path));
    }
    // SAFETY: successful OpenProcessToken transfers one uniquely owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    // SAFETY: retained query token and initialized bounded UTF-16 output.
    if unsafe { GetUserProfileDirectoryW(token.as_raw_handle(), buffer.as_mut_ptr(), &mut size) }
        == 0
    {
        return Err(last("resolve native account profile", path));
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| unsafe_path("native profile is unterminated", path))?;
    let profile = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end]));
    wide(&profile)?;
    Ok(profile.join(".stateengine-install.lock"))
}

fn claim_error(
    mut error: crate::state_files::StateFileError,
) -> crate::state_files::StateFileError {
    if error
        .source
        .as_ref()
        .is_some_and(|cause| matches!(cause.raw_os_error(), Some(32 | 33)))
    {
        error.operation = "installation record is busy; retry after install or uninstall finishes";
    }
    error
}

#[path = "source_windows.rs"]
mod source;
pub(in crate::state_files) use source::ReadPin;

#[path = "created_windows.rs"]
mod created;
pub(in crate::state_files) use created::{
    CreatedDirectory, prepare_created_directory, validate_creation_target,
};
