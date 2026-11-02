use super::{components, name, owned};
#[path = "unix_metadata.rs"]
mod metadata;
use crate::state_files::effects::{DirectoryRemoval, absent, changed, digest, verify};
use crate::state_files::{Result, io_error, unsafe_path};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("native installation effects support Linux and macOS Unix targets");

fn id(file: &File, path: &Path, directory: bool, owner: bool) -> Result<(u64, u64)> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("inspect installation pin", path, e))?;
    // SAFETY: immutable native identity query with no pointers.
    let user = unsafe { libc::geteuid() };
    if (owner && meta.uid() != user)
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o6000 != 0
        }
    {
        return Err(unsafe_path(
            "require current-user regular installation object without hard links or special bits",
            path,
        ));
    }
    Ok((meta.dev(), meta.ino()))
}

/// Share the native private-primary-group ancestor policy. Sticky shared
/// ancestors protect child names, but the final mutation parent is never shared
/// with arbitrary users. POSIX ACL write masks remain reflected in mode bits.
pub(super) fn trusted_directory(file: &File, path: &Path, final_parent: bool) -> Result<()> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("inspect mutation directory security", path, e))?;
    crate::state_files::validate_existing_ancestor(file, path)?;
    if final_parent && meta.mode() & 0o002 != 0 {
        return Err(unsafe_path(
            "final mutation directory is world-writable",
            path,
        ));
    }
    #[cfg(target_os = "macos")]
    metadata::check_directory_acl(file, path)?;
    Ok(())
}

fn parent(path: &Path) -> Result<(File, CString)> {
    components(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| unsafe_path("cannot mutate filesystem root", path))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| unsafe_path("installation leaf missing", path))?;
    Ok((super::walk_effect_parent(parent)?, name(leaf, path)?))
}
fn lock(file: &File, path: &Path) -> Result<()> {
    // SAFETY: advisory exclusive lock on a retained descriptor, nonblocking. Every
    // effect in this module takes the parent lock, serializing cooperating writers.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(io_error(
            "installation object is in use",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[path = "install_claim_unix.rs"]
mod inherited_claim;
pub(in crate::state_files) use inherited_claim::inherited_installation_claim;

fn leaf(parent: &File, name: &CString, path: &Path, directory: bool) -> Result<File> {
    // SAFETY: native stat output, retained parent and a terminated literal leaf.
    let mut entry: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: no-follow query explicitly identifies a final directory symlink;
    // ENOTDIR from a later O_DIRECTORY open must not masquerade as that check.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut entry,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io_error(
            "inspect installation leaf",
            path,
            io::Error::last_os_error(),
        ));
    }
    if entry.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(unsafe_path("installation leaf is a symbolic link", path));
    }
    // SAFETY: retained parent, literal leaf; nonblocking open rejects FIFOs before
    // they can hang the worker and O_NOFOLLOW rejects final symlinks.
    owned(
        unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
        },
        "open installation object without following links",
        path,
    )
}

fn exchange(parent: &File, left: &CString, right: &CString, path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: retained directory, two terminated literal names, and the kernel's
    // atomic exchange operation. Unsupported kernels/filesystems refuse.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: retained directory, literal names and macOS atomic rename swap.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result < 0 {
        return Err(io_error(
            "atomically exchange profile with staging",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn move_no_replace(parent: &File, left: &CString, right: &CString, path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: retained parent and terminated literal names; no-replace move never
    // overwrites a concurrently created user file while restoring a raced removal.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: retained parent and literal names, using macOS atomic exclusive move.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result < 0 {
        return Err(io_error(
            "move owned removal without replacement",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}
fn recovery_name(path: &Path) -> Result<(PathBuf, CString)> {
    let random = super::random(path)?;
    let suffix: String = se_types::hex_lower(&random);
    let sibling = path.with_file_name(format!(".se-edit-backup-{suffix}"));
    let leaf = name(
        sibling
            .file_name()
            .ok_or_else(|| unsafe_path("recovery leaf missing", path))?,
        path,
    )?;
    Ok((sibling, leaf))
}

pub(in crate::state_files) struct Pin {
    path: PathBuf,
    parent: File,
    name: CString,
    file: File,
    identity: (u64, u64),
}
impl Pin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        let (parent, name) = match parent(path) {
            Ok(v) => v,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        lock(&parent, path)?;
        let file = match leaf(&parent, &name, path, false) {
            Ok(v) => v,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let identity = id(&file, path, false, true)?;
        lock(&file, path)?;
        let pin = Self {
            path: path.into(),
            parent,
            name,
            file,
            identity,
        };
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn create_claim(path: &Path) -> Result<Self> {
        if let Some(pin) = Self::open(path).map_err(claim_error)? {
            if pin
                .file
                .metadata()
                .map_err(|error| io_error("inspect permanent claim mode", path, error))?
                .mode()
                & 0o077
                != 0
            {
                return Err(unsafe_path(
                    "permanent installation claim must be owner-only",
                    path,
                ));
            }
            return Ok(pin);
        }
        let (directory, leaf_name) = parent(path)?;
        // SAFETY: held trusted parent, exclusive no-follow private creation;
        // the existing permanent claim inode is never truncated or replaced.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                leaf_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error(
                    "create shared installation claim",
                    path,
                    io::Error::last_os_error(),
                ));
            }
        } else {
            let file = owned(raw, "create shared installation claim", path)?;
            file.sync_all()
                .map_err(|error| io_error("sync installation claim", path, error))?;
            directory
                .sync_all()
                .map_err(|error| io_error("sync installation claim parent", path, error))?;
        }
        Self::open(path)
            .map_err(claim_error)?
            .ok_or_else(|| changed("new installation claim disappeared", path))
    }
    pub(in crate::state_files) fn claim_record(&self) -> Result<()> {
        self.check()?;
        let security = self.file.metadata().map_err(|error| {
            io_error("inspect installation claim protection", &self.path, error)
        })?;
        if security.mode() & 0o022 != 0 {
            return Err(unsafe_path(
                "installation record permits another native writer",
                &self.path,
            ));
        }
        #[cfg(target_os = "macos")]
        metadata::check_directory_acl(&self.file, &self.path)?;
        lock(&self.file, &self.path).map_err(|mut error| {
            error.operation =
                "installation record is busy; retry after install or uninstall finishes";
            error
        })?;
        // The file claim remains held while unrelated children use the parent
        // mutation lock. Rename/digest checks still guard every later effect.
        // SAFETY: release only this pin's own cooperating-parent flock.
        if unsafe { libc::flock(self.parent.as_raw_fd(), libc::LOCK_UN) } < 0 {
            return Err(io_error(
                "release installer claim parent lock",
                &self.path,
                io::Error::last_os_error(),
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
        let (observed, _) = parent(&self.path)?;
        if id(&observed, &self.path, true, false)? != id(&self.parent, &self.path, true, false)? {
            return Err(changed("installation parent changed", &self.path));
        }
        Ok(())
    }
    pub(in crate::state_files) fn check(&self) -> Result<()> {
        self.check_parent()?;
        let current = leaf(&self.parent, &self.name, &self.path, false)?;
        if id(&current, &self.path, false, true)? != self.identity
            || id(&self.file, &self.path, false, true)? != self.identity
        {
            return Err(changed("installation file identity changed", &self.path));
        }
        Ok(())
    }
    pub(in crate::state_files) fn remove(self, expected: [u8; 32]) -> Result<()> {
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        self.check()?;
        let (recovery_path, recovery_name) = recovery_name(&self.path)?;
        move_no_replace(&self.parent, &self.name, &recovery_name, &self.path)?;
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync staged removal", &recovery_path, e))?;
        let displaced = leaf(&self.parent, &recovery_name, &recovery_path, false)?;
        if id(&displaced, &recovery_path, false, true)? != self.identity
            || digest(&displaced, &recovery_path)? != expected
        {
            move_no_replace(&self.parent, &recovery_name, &self.name, &recovery_path)?;
            self.parent
                .sync_all()
                .map_err(|e| io_error("sync restored raced removal", &self.path, e))?;
            return Err(changed(
                "file changed during removal; displaced file restored",
                &self.path,
            ));
        }
        self.check_parent()?;
        // SAFETY: only the uniquely named, held and reverified original is unlinked.
        // A new file created at the original pathname is never touched.
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), recovery_name.as_ptr(), 0) } < 0 {
            return Err(io_error(
                "unlink exact held original",
                &recovery_path,
                io::Error::last_os_error(),
            ));
        }
        let after = self
            .file
            .metadata()
            .map_err(|e| io_error("read unlinked original identity", &self.path, e))?;
        if after.nlink() != 0 {
            return Err(changed(
                "unlink did not retire the held original object",
                &recovery_path,
            ));
        }
        if !matches!(digest(&self.file, &self.path), Ok(value) if value == expected) {
            self.retain_raced_bytes(&recovery_path, &recovery_name)?;
            return Err(changed(
                "file changed through an open handle during unlink; recovery copy retained",
                &recovery_path,
            ));
        }
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync installation unlink", &self.path, e))?;
        self.check_parent()?;
        match leaf(&self.parent, &self.name, &self.path, false) {
            Err(e) if absent(&e) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(changed(
                "a new file appeared at the removed pathname; it was preserved",
                &self.path,
            )),
        }
    }
    fn retain_raced_bytes(&self, path: &Path, name: &CString) -> Result<()> {
        // SAFETY: exclusive no-follow creation of a recovery sibling; no user name
        // is overwritten. Preserve any bytes that raced through the old open FD.
        let mut recovery = owned(
            unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            },
            "retain raced original bytes",
            path,
        )?;
        let mut original = &self.file;
        original
            .seek(SeekFrom::Start(0))
            .map_err(|e| io_error("seek raced original", path, e))?;
        io::copy(&mut original, &mut recovery)
            .map_err(|e| io_error("copy raced original to recovery sibling", path, e))?;
        metadata::copy(&self.file, &recovery, path)?;
        recovery
            .sync_all()
            .map_err(|e| io_error("sync raced original recovery", path, e))?;
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync raced original recovery parent", path, e))
    }
    pub(in crate::state_files) fn restore_to(
        self,
        destination: &Path,
        expected: [u8; 32],
    ) -> Result<()> {
        components(destination)?;
        if destination.parent() != self.path.parent() || destination == self.path {
            return Err(unsafe_path(
                "recovery target must be a distinct exact name in the held parent",
                destination,
            ));
        }
        let target = name(
            destination
                .file_name()
                .ok_or_else(|| unsafe_path("recovery target leaf missing", destination))?,
            destination,
        )?;
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        self.check()?;
        move_no_replace(&self.parent, &self.name, &target, destination)?;
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync recovery restoration", destination, e))?;
        self.check_parent()?;
        let outside = leaf(&self.parent, &target, destination, false)?;
        if id(&outside, destination, false, true)? != self.identity
            || digest(&outside, destination)? != expected
        {
            return Err(changed(
                "restored recovery object changed on outside readback",
                destination,
            ));
        }
        match leaf(&self.parent, &self.name, &self.path, false) {
            Err(error) if absent(&error) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(changed(
                "recovery source pathname reappeared after restoration; preserved",
                &self.path,
            )),
        }
    }
    pub(in crate::state_files) fn replace(self, expected: [u8; 32], bytes: &[u8]) -> Result<()> {
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        let random = super::random(&self.path)?;
        let suffix: String = se_types::hex_lower(&random);
        let stage_path = self
            .path
            .with_file_name(format!(".se-edit-backup-{suffix}"));
        let stage_name = name(
            stage_path
                .file_name()
                .ok_or_else(|| unsafe_path("staging leaf missing", &stage_path))?,
            &stage_path,
        )?;
        // SAFETY: same held parent and exclusive no-follow creation; no existing
        // entry is overwritten and the private stage cannot expose profile text.
        let mut stage = owned(
            unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            },
            "create owned profile staging",
            &stage_path,
        )?;
        let stage_identity = id(&stage, &stage_path, false, true)?;
        let wanted: [u8; 32] = Sha256::digest(bytes).into();
        let mut swapped = false;
        let result = (|| {
            stage
                .write_all(bytes)
                .map_err(|e| io_error("write staged profile", &stage_path, e))?;
            let security = self
                .file
                .metadata()
                .map_err(|e| io_error("read original profile security", &self.path, e))?;
            metadata::copy(&self.file, &stage, &self.path)?;
            stage
                .sync_all()
                .map_err(|e| io_error("sync staged profile", &stage_path, e))?;
            self.check()?;
            verify(&self.file, &self.path, expected)?;
            self.check()?;
            let current_security = self
                .file
                .metadata()
                .map_err(|e| io_error("recheck profile security", &self.path, e))?;
            if metadata::stamp(&security) != metadata::stamp(&current_security) {
                return Err(changed(
                    "profile security changed before publication",
                    &self.path,
                ));
            }
            exchange(&self.parent, &stage_name, &self.name, &self.path)?;
            swapped = true;
            let displaced = leaf(&self.parent, &stage_name, &stage_path, false)?;
            let intact = id(&displaced, &stage_path, false, true)? == self.identity
                && digest(&displaced, &stage_path)? == expected;
            if !intact {
                let current = leaf(&self.parent, &self.name, &self.path, false)?;
                if id(&current, &self.path, false, true)? != stage_identity
                    || digest(&current, &self.path)? != wanted
                {
                    return Err(changed(
                        "profile raced with exchange; both versions retained",
                        &stage_path,
                    ));
                }
                exchange(&self.parent, &stage_name, &self.name, &self.path)?;
                swapped = false;
                self.parent
                    .sync_all()
                    .map_err(|e| io_error("sync rolled-back profile exchange", &self.path, e))?;
                return Err(changed(
                    "profile changed during atomic exchange; original restored",
                    &self.path,
                ));
            }
            self.parent
                .sync_all()
                .map_err(|e| io_error("sync profile replacement", &self.path, e))?;
            self.check_parent()?;
            let observed = leaf(&self.parent, &self.name, &self.path, false)?;
            if id(&observed, &self.path, false, true)? != id(&stage, &stage_path, false, true)?
                || digest(&observed, &self.path)? != <[u8; 32]>::from(Sha256::digest(bytes))
            {
                return Err(changed("profile replacement readback differs", &self.path));
            }
            // SAFETY: the displaced entry's exact identity and digest were checked
            // after atomic exchange; unlink only that held original name.
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), stage_name.as_ptr(), 0) } < 0 {
                return Err(io_error(
                    "remove displaced original profile",
                    &stage_path,
                    io::Error::last_os_error(),
                ));
            }
            let retired = self
                .file
                .metadata()
                .map_err(|e| io_error("read displaced original link count", &stage_path, e))?;
            if retired.nlink() != 0 {
                return Err(changed(
                    "profile exchange did not retire the held original",
                    &stage_path,
                ));
            }
            if !matches!(digest(&self.file, &self.path), Ok(value) if value == expected) {
                let (retained_path, retained_name) = recovery_name(&self.path)?;
                self.retain_raced_bytes(&retained_path, &retained_name)?;
                return Err(changed(
                    "profile changed through an open displaced handle; recovery copy retained",
                    &retained_path,
                ));
            }
            self.parent
                .sync_all()
                .map_err(|e| io_error("sync retired profile sibling", &self.path, e))?;
            Ok(())
        })();
        // An uncertain exchange retains both versions. After a successful rollback,
        // only our original staging object is eligible for cleanup.
        // SAFETY: this random O_EXCL-created literal name belongs to this operation.
        if result.is_err() && !swapped {
            let cleanup = leaf(&self.parent, &stage_name, &stage_path, false)?;
            if id(&cleanup, &stage_path, false, true)? != stage_identity {
                return Err(changed(
                    "profile staging changed before cleanup",
                    &stage_path,
                ));
            }
        }
        // SAFETY: only the checked uniquely-created staging entry is removed.
        if result.is_err()
            && !swapped
            // SAFETY: retained parent descriptor and NUL-terminated staging leaf;
            // this removes only the validated staging name within that parent.
            && unsafe { libc::unlinkat(self.parent.as_raw_fd(), stage_name.as_ptr(), 0) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::NotFound
        {
            return Err(io_error(
                "cleanup owned profile staging failed",
                &stage_path,
                io::Error::last_os_error(),
            ));
        }
        result
    }
}
use sha2::{Digest, Sha256};

pub(in crate::state_files) fn remove_empty_directory(path: &Path) -> Result<DirectoryRemoval> {
    let (parent_pin, name) = match parent(path) {
        Ok(v) => v,
        Err(e) if absent(&e) => return Ok(DirectoryRemoval::AlreadyAbsent),
        Err(e) => return Err(e),
    };
    lock(&parent_pin, path)?;
    let directory = match leaf(&parent_pin, &name, path, true) {
        Ok(v) => v,
        Err(e) if absent(&e) => return Ok(DirectoryRemoval::AlreadyAbsent),
        Err(e) => return Err(e),
    };
    let identity = id(&directory, path, true, true)?;
    let observed = leaf(&parent_pin, &name, path, true)?;
    if id(&observed, path, true, true)? != identity {
        return Err(changed("installation directory changed", path));
    }
    // SAFETY: held parent and checked directory entry; the kernel removes only an
    // empty directory. There is no recursive walk or removal of foreign contents.
    if unsafe { libc::unlinkat(parent_pin.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
        let error = io::Error::last_os_error();
        return if matches!(
            error.raw_os_error(),
            Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
        ) {
            Ok(DirectoryRemoval::NotEmpty)
        } else {
            Err(io_error(
                "remove owned empty installation directory",
                path,
                error,
            ))
        };
    }
    parent_pin
        .sync_all()
        .map_err(|e| io_error("sync installation directory removal", path, e))?;
    let (outside, _) = parent(path)?;
    if id(&outside, path, true, false)? != id(&parent_pin, path, true, false)? {
        return Err(changed("installation directory parent changed", path));
    }
    match leaf(&outside, &name, path, true) {
        Err(e) if absent(&e) => Ok(DirectoryRemoval::Removed),
        Err(e) => Err(e),
        Ok(_) => Err(changed("directory remained after removal", path)),
    }
}

#[path = "recovery_unix.rs"]
mod recovery;
pub(in crate::state_files) use recovery::{list_names, scan_recovery, scan_temporary};

pub(in crate::state_files) fn installation_claim_path() -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let diagnostic = Path::new("native account profile");
    // SAFETY: reentrant account lookup with owned bounded storage; native result
    // pointers are copied before the storage is released.
    let uid = unsafe { libc::geteuid() };
    for size in [4096usize, 16384, 65536, 262144] {
        // SAFETY: native POD account output, initialized result pointer and owned buffer.
        let mut account: libc::passwd = unsafe { std::mem::zeroed() };
        let mut storage = vec![0u8; size];
        let mut result = std::ptr::null_mut();
        // SAFETY: account/result are writable native output pointers and storage
        // has the stated length; all returned pointers are copied while it lives.
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                &mut account,
                storage.as_mut_ptr().cast(),
                storage.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE {
            continue;
        }
        if code != 0 {
            return Err(io_error(
                "resolve native account profile",
                diagnostic,
                io::Error::from_raw_os_error(code),
            ));
        }
        if result.is_null() || account.pw_dir.is_null() {
            return Err(unsafe_path(
                "native account has no profile directory",
                diagnostic,
            ));
        }
        // SAFETY: successful getpwuid_r provides a terminated directory in storage.
        let home = unsafe { std::ffi::CStr::from_ptr(account.pw_dir) }
            .to_bytes()
            .to_vec();
        let path = PathBuf::from(std::ffi::OsString::from_vec(home));
        components(&path)?;
        return Ok(path.join(".stateengine-install.lock"));
    }
    Err(unsafe_path(
        "native account profile lookup exceeds its finite bound",
        diagnostic,
    ))
}

fn claim_error(
    mut error: crate::state_files::StateFileError,
) -> crate::state_files::StateFileError {
    if error
        .source
        .as_ref()
        .is_some_and(|cause| cause.raw_os_error() == Some(libc::EWOULDBLOCK))
    {
        error.operation = "installation record is busy; retry after install or uninstall finishes";
    }
    error
}

#[path = "source_unix.rs"]
mod source;
pub(in crate::state_files) use source::ReadPin;

#[path = "created_unix.rs"]
mod created;
pub(in crate::state_files) use created::{
    CreatedDirectory, prepare_created_directory, validate_creation_target,
};
