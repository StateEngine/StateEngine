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

/// POSIX ACL effective write permissions are reflected in the group mask bits.
/// Sticky root/user-owned ancestors (for example /tmp) protect owned children;
/// the final mutation directory must admit no other writer at all.
pub(super) fn trusted_directory(file: &File, path: &Path, final_parent: bool) -> Result<()> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("inspect mutation directory security", path, e))?;
    // SAFETY: immutable native identity query.
    let user = unsafe { libc::geteuid() };
    if !meta.is_dir()
        || (meta.uid() != 0 && meta.uid() != user)
        || (meta.mode() & 0o022 != 0 && (final_parent || meta.mode() & 0o1000 == 0))
    {
        return Err(unsafe_path(
            "mutation parent permits another native principal to replace names",
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
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
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
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
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
        if result.is_err()
            && !swapped
            // SAFETY: retained parent descriptor and checked NUL-terminated staging name.
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
pub(in crate::state_files) use recovery::scan_recovery;
