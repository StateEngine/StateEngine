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
/// How a guard's lock ends when the guard goes away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseMode {
    /// Clear the lock with `LOCK_UN` before the descriptor closes, so a
    /// duplicate a child inherited between fork and exec cannot keep it.
    Unlock,
    /// Leave the lock to the last duplicate of this description closing.
    CloseOnly,
}

/// An exclusive advisory lock that is released explicitly rather than by the
/// descriptor closing.
///
/// `flock` belongs to the open file description, and a spawned child inherits
/// duplicates of every descriptor between fork and exec. Closing this process's
/// duplicate while such a child is alive therefore leaves the lock held by the
/// child's copy, and a concurrent writer in this process is refused. Releasing
/// with `LOCK_UN` first clears the lock on the shared description, so no
/// inherited copy can outlive the release. Every holding site keeps one of
/// these for as long as it intends to hold the lock.
///
/// The rule has one deliberate exception. The account-wide installation claim
/// shares its description with the installer worker by design: the worker
/// inherits it across exec and may still be changing files after the shell
/// stops waiting for it. A `child::wait` error path can drop the claim while
/// that worker lives, so `LOCK_UN` there would release a live holder's claim.
/// That one guard ends by close only (`end_by_close`), and the lock then clears
/// when the worker's own duplicate closes. Every other site keeps `Unlock`,
/// because a child must never be able to keep an abandoned lock alive.
#[must_use = "dropping the guard releases the lock when its last duplicate closes"]
pub(in crate::state_files) struct LockGuard {
    file: File,
    release: ReleaseMode,
}
impl LockGuard {
    pub(in crate::state_files) fn acquire(file: File, path: &Path) -> Result<Self> {
        // SAFETY: advisory exclusive lock on a retained descriptor, nonblocking.
        // Every effect in this module takes the parent lock, serializing
        // cooperating writers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io_error(
                "installation object is in use",
                path,
                io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            file,
            release: ReleaseMode::Unlock,
        })
    }
    /// Release early while keeping the descriptor, for a holder that
    /// deliberately narrows what it keeps locked. Returns the native failure
    /// rather than swallowing it: a lock that did not release is a fact the
    /// caller must be able to report.
    pub(in crate::state_files) fn release(&mut self) -> std::io::Result<()> {
        // SAFETY: release this guard's own cooperating description; the
        // descriptor stays open and owned by the guard.
        if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    /// End the lock by close only: every duplicate of this description, even
    /// one a long-lived child inherited across exec, must close before the lock
    /// frees. Only the account claim uses this, because its worker deliberately
    /// inherits the description; a `LOCK_UN` there would release the claim of a
    /// worker that is still changing files.
    pub(in crate::state_files) fn end_by_close(&mut self) {
        self.release = ReleaseMode::CloseOnly;
    }
}
impl Drop for LockGuard {
    fn drop(&mut self) {
        if self.release == ReleaseMode::CloseOnly {
            // Closing the last duplicate releases the lock. An explicit
            // `LOCK_UN` would free it under an inherited holder still at work.
            return;
        }
        // A failed unlock is not actionable during drop, but it must not vanish:
        // the lock stays held by this description until it closes.
        if let Err(error) = self.release() {
            eprintln!("advisory lock release failed: {error}");
        }
    }
}

/// Take the exclusive lock on a descriptor this process alone opened, and
/// return it held.
///
/// `flock` belongs to the open file description, so the guard must own a
/// description nothing else holds. Never pass a descriptor shared with a child
/// or another process: `LOCK_UN` acts on the whole shared description and would
/// release that holder's claim too. Descriptors this module opens for its own
/// effects qualify; an inherited claim does not.
fn lock(file: &File, path: &Path) -> Result<LockGuard> {
    let owned = file
        .try_clone()
        .map_err(|error| io_error("retain installation lock", path, error))?;
    LockGuard::acquire(owned, path)
}

#[cfg(target_os = "macos")]
#[path = "private_stage_macos.rs"]
mod private_stage;

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
    private: bool,
    /// Held for the pin's lifetime unless a claim narrows it; released
    /// explicitly on drop so no inherited duplicate keeps it alive. The claim
    /// narrows only this parent lock, never the record's.
    parent_lock: Option<LockGuard>,
    file_lock: LockGuard,
}
impl Pin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        let (parent, name) = match parent(path) {
            Ok(v) => v,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let parent_lock = lock(&parent, path)?;
        let file = match leaf(&parent, &name, path, false) {
            Ok(v) => v,
            Err(e) if absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let identity = id(&file, path, false, true)?;
        let file_lock = lock(&file, path)?;
        let pin = Self {
            path: path.into(),
            parent,
            name,
            file,
            identity,
            private: false,
            parent_lock: Some(parent_lock),
            file_lock,
        };
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn open_profile(path: &Path) -> Result<Option<Self>> {
        let Some(mut pin) = Self::open(path)? else {
            return Ok(None);
        };
        pin.private = true;
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
        if self.private {
            let path = self
                .path
                .parent()
                .ok_or_else(|| unsafe_path("profile parent missing", &self.path))?;
            super::metadata(&observed, path, true)?;
            super::metadata(&self.parent, path, true)?;
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
        if self.private {
            super::metadata(&current, &self.path, false)?;
            super::metadata(&self.file, &self.path, false)?;
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
    let _parent_lock = lock(&parent_pin, path)?;
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

#[cfg(test)]
mod release_mode_tests {
    use super::*;
    use std::os::fd::FromRawFd;

    type Check = std::result::Result<(), Box<dyn std::error::Error>>;

    struct Case {
        root: PathBuf,
        record: PathBuf,
    }
    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn case(label: &str) -> std::result::Result<Case, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let unique = format!(
            "se-claim-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&root)?;
        let record = root.join("claim-record");
        std::fs::write(&record, b"record")?;
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600))?;
        Ok(Case { root, record })
    }

    /// A duplicate of the same open file description, as a spawned child holds
    /// between fork and exec.
    fn inherited(file: &File) -> std::result::Result<File, Box<dyn std::error::Error>> {
        // SAFETY: duplicate this retained descriptor into a new owned one.
        let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: fcntl transferred this newly allocated descriptor to us.
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    /// Whether a fresh pin cannot take the record's lock, i.e. it is held.
    fn lock_is_held(path: &Path) -> std::result::Result<bool, Box<dyn std::error::Error>> {
        match Pin::open(path) {
            Ok(Some(_pin)) => Ok(false),
            Ok(None) => Err("record disappeared".into()),
            Err(error) => {
                let busy = error
                    .source
                    .as_ref()
                    .is_some_and(|cause| cause.raw_os_error() == Some(libc::EWOULDBLOCK));
                if !busy {
                    return Err(format!("unexpected open failure: {error}").into());
                }
                Ok(true)
            }
        }
    }

    /// The account claim outlives the shell while a worker still holds its
    /// inherited description, and frees once that last duplicate closes.
    #[test]
    fn a_claim_ends_only_when_its_last_duplicate_closes() -> Check {
        let case = case("close-only")?;
        let pin = Pin::create_claim(&case.record)?;
        let worker = inherited(pin.file())?;
        drop(pin);
        assert!(
            lock_is_held(&case.record)?,
            "the claim released while an inherited worker still held its description"
        );
        drop(worker);
        assert!(
            !lock_is_held(&case.record)?,
            "the claim stayed held after its last duplicate closed"
        );
        Ok(())
    }

    /// Every other guard still clears its lock explicitly, so a child's
    /// inherited duplicate cannot keep an abandoned ordinary lock alive.
    #[test]
    fn an_ordinary_guard_still_clears_its_lock_explicitly() -> Check {
        let case = case("unlock")?;
        let pin = Pin::open(&case.record)?.ok_or("record missing")?;
        let child = inherited(pin.file())?;
        drop(pin);
        assert!(
            !lock_is_held(&case.record)?,
            "an ordinary guard left its lock to an inherited duplicate"
        );
        drop(child);
        Ok(())
    }
}
