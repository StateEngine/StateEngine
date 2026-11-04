use super::{components, name, owned};
#[path = "unix_metadata.rs"]
mod metadata;
#[cfg(target_os = "linux")]
#[path = "permissions_linux.rs"]
pub(in crate::state_files) mod permissions;
#[cfg(target_os = "macos")]
#[path = "permissions_macos.rs"]
pub(in crate::state_files) mod permissions;
use crate::state_files::effects::{DirectoryRemoval, absent, changed, digest, verify};
use crate::state_files::{Result, io_error, unsafe_path};
use std::{
    ffi::CString,
    fs::File,
    io,
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

#[path = "claim_unix.rs"]
mod claim;

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
}
#[path = "file_mutation_unix.rs"]
mod file_mutation;

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
