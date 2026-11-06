//! Protected native files for the store's StateFiles port. CLI/host wrappers
//! translate these native results into StoreResult; se-proc does not depend on
//! se-store or se-host. This object pins one already-authorized state directory.
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};
pub(crate) mod effects;
mod permissions;
pub(crate) mod source;
pub use permissions::{
    PermissionKind, PermissionProtection, PermissionRepairPin, PermissionRepairWitness,
    PermissionSnapshot,
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
pub(crate) mod user_path;
#[cfg(windows)]
pub(crate) mod windows;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
use windows as os;

/// Clear inheritance only on a newly created, held private directory. Existing
/// IPC directories remain read-only admission checks, never implicit repairs.
#[cfg(target_os = "macos")]
pub(crate) fn protect_created_ipc_directory(file: &File, path: &Path) -> Result<()> {
    unix::clear_created_acl(file, path, true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateFileErrorCode {
    AlreadyExists,
    Unreadable,
    LocationUnsafe,
    SourceChanged,
    Unsupported,
}
#[derive(Debug)]
pub struct StateFileError {
    pub code: StateFileErrorCode,
    pub operation: &'static str,
    pub path: PathBuf,
    pub source: Option<io::Error>,
}
impl StateFileError {
    /// A measured nonblocking native lock refusal, distinct from access failure.
    pub fn is_contended(&self) -> bool {
        self.source.as_ref().is_some_and(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                return true;
            }
            #[cfg(windows)]
            if error.raw_os_error() == Some(33) {
                return true;
            } // ERROR_LOCK_VIOLATION
            false
        })
    }
}
crate::native_error::native_error!(StateFileError, |error, out| {
    write!(out, "{} at {}: {:?}", error.operation, error.path.display(), error.code)?;
    if let Some(source) = &error.source {
        write!(out, ": {source}")?;
    }
    Ok(())
}; source error.source.as_ref().map(|e| e as _));
pub(super) type Result<T> = std::result::Result<T, StateFileError>;
pub(super) fn failure(
    code: StateFileErrorCode,
    operation: &'static str,
    path: &Path,
) -> StateFileError {
    StateFileError {
        code,
        operation,
        path: path.to_owned(),
        source: None,
    }
}
pub(super) fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StateFileError {
    #[cfg(unix)]
    if source.raw_os_error() == Some(libc::ELOOP) {
        return StateFileError {
            code: StateFileErrorCode::LocationUnsafe,
            operation,
            path: path.to_owned(),
            source: Some(source),
        };
    }
    StateFileError {
        code: if source.kind() == io::ErrorKind::AlreadyExists {
            StateFileErrorCode::AlreadyExists
        } else {
            StateFileErrorCode::Unreadable
        },
        operation,
        path: path.to_owned(),
        source: Some(source),
    }
}
pub(super) fn unsafe_path(operation: &'static str, path: &Path) -> StateFileError {
    failure(StateFileErrorCode::LocationUnsafe, operation, path)
}
pub struct ProtectedStateStaging {
    pub path: PathBuf,
    pub file: File,
}
pub struct NativeStateFiles {
    root: PathBuf,
    directory: os::Directory,
}
impl NativeStateFiles {
    /// Opens an existing private state root without following its final name
    /// or any owned descendant. Trusted system-ancestor links may resolve. Missing,
    /// unreadable, unsafe and replaced roots are failures, never a new directory.
    pub fn open(root: &Path) -> Result<Self> {
        let directory = os::Directory::open(root)?;
        Ok(Self {
            root: root.to_owned(),
            directory,
        })
    }
    /// Explicit init only: creates absent directory components with native
    /// owner-only protection, and refuses an existing unsafe final directory.
    /// Existing ancestor permissions are never changed.
    pub fn create(root: &Path) -> Result<Self> {
        os::create_directories(root)?;
        Self::open(root)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Space available to this OS user on the retained state-root volume.
    /// Failure is unmeasured, never zero; both sides revalidate root custody.
    pub fn available_bytes(&self) -> Result<u64> {
        self.directory.check_name(&self.root)?;
        let available = self.directory.available_bytes(&self.root)?;
        self.directory.check_name(&self.root)?;
        Ok(available)
    }
    pub fn create_staging(&self, directory: &Path) -> Result<ProtectedStateStaging> {
        self.check(directory)?;
        for _ in 0..8 {
            let random = os::random(directory)?;
            let suffix: String = se_types::hex_lower(&random);
            let path = directory.join(format!(".se-stage-{suffix}"));
            let file = match self.directory.create_staging_at(&path, &self.root) {
                Ok(file) => file,
                Err(e) if e.code == StateFileErrorCode::AlreadyExists => continue,
                Err(e) => return Err(e),
            };
            self.check(directory)?;
            return Ok(ProtectedStateStaging { path, file });
        }
        Err(failure(
            StateFileErrorCode::AlreadyExists,
            "native staging name collisions",
            directory,
        ))
    }
    /// Retire a fresh empty staging name while keeping its exact writable file.
    /// No user text may be written before this succeeds.
    pub fn retire_empty_staging(&self, staged: ProtectedStateStaging) -> Result<File> {
        self.check(&staged.path)?;
        if !staged
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".se-stage-"))
            || staged
                .file
                .metadata()
                .map_err(|e| io_error("inspect empty staging", &staged.path, e))?
                .len()
                != 0
        {
            return Err(unsafe_path(
                "only a fresh empty native staging file may become anonymous",
                &staged.path,
            ));
        }
        #[cfg(unix)]
        {
            use sha2::Digest;
            let owned = effects::OwnedFile::open(&staged.path)?
                .ok_or_else(|| unsafe_path("empty staging disappeared", &staged.path))?;
            owned.remove(sha2::Sha256::digest([]).into())?;
        }
        #[cfg(windows)]
        self.directory
            .retire_empty_staging(&staged.path, &staged.file, &self.root)?;
        Ok(staged.file)
    }
    /// Some is a verified regular, owner-only file. None is witnessed native
    /// absence. Every other read outcome remains a typed error with its cause.
    pub fn readback(&self, path: &Path) -> Result<Option<File>> {
        self.check(path)?;
        let result = self.directory.readback(path, &self.root)?;
        self.check(path)?;
        Ok(result)
    }
    /// Pin verified regular-file metadata without reading content. On Linux the
    /// O_PATH descriptor preserves process-wide POSIX locks held by SQLite when
    /// it closes. Other platforms retain the protected readback semantics.
    pub fn pin_metadata(&self, path: &Path) -> Result<Option<File>> {
        #[cfg(target_os = "linux")]
        {
            self.check(path)?;
            let result = self.directory.pin_metadata(path, &self.root)?;
            self.check(path)?;
            Ok(result)
        }
        #[cfg(not(target_os = "linux"))]
        self.readback(path)
    }
    /// Prepare one immediate protected child of this held root. Existing unsafe
    /// directories refuse and are never chmod/chowned to make them admissible.
    pub fn prepare_directory(&self, path: &Path) -> Result<()> {
        self.check(path)?;
        if path.parent() != Some(self.root.as_path()) {
            return Err(unsafe_path(
                "directory must be an immediate child of the held root",
                path,
            ));
        }
        self.directory.prepare_directory(path, &self.root)?;
        self.check(path)
    }

    /// Exclusively create one protected child. An incumbent directory, even an
    /// empty one, is preserved and refused; the caller must choose a fresh name.
    pub fn prepare_new_directory(&self, path: &Path) -> Result<()> {
        self.check(path)?;
        if path.parent() != Some(self.root.as_path()) {
            return Err(unsafe_path(
                "directory must be an immediate child of the held root",
                path,
            ));
        }
        self.directory.prepare_new_directory(path, &self.root)?;
        self.check(path)
    }

    /// Call after closing every SQLite/backup handle. The source must be a
    /// native staging name within this held root. A collision preserves both
    /// the winner and the staging file, returning AlreadyExists.
    pub fn publish_no_replace(&self, staged: &Path, destination: &Path) -> Result<()> {
        self.check(staged)?;
        self.check(destination)?;
        if staged == destination
            || !staged
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".se-stage-"))
        {
            return Err(unsafe_path(
                "require a distinct native staging file",
                staged,
            ));
        }
        let source = self.directory.open_for_publication(staged, &self.root)?;
        source
            .sync_all()
            .map_err(|e| io_error("sync staged data", staged, e))?;
        let before = os::identity(&source, staged)?;
        self.directory
            .publish(staged, destination, &self.root, &source)?;
        let published = self
            .directory
            .readback(destination, &self.root)?
            .ok_or_else(|| {
                failure(
                    StateFileErrorCode::SourceChanged,
                    "published file absent on readback",
                    destination,
                )
            })?;
        if os::identity(&published, destination)? != before {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "publication identity changed",
                destination,
            ));
        }
        if self.directory.readback(staged, &self.root)?.is_some() {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "staging name remained after publication",
                staged,
            ));
        }
        self.check(destination)?;
        Ok(())
    }
    fn check(&self, path: &Path) -> Result<()> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| unsafe_path("path outside held state directory", path))?;
        if relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
            || !self.root.is_absolute()
        {
            return Err(unsafe_path("require normalized absolute state path", path));
        }
        self.directory.check_name(&self.root)
    }
}

/// Shared owned-root traversal for native IPC: trusted system ancestors may
/// resolve links; the owned directory itself remains no-follow and owner-only.
#[cfg(unix)]
pub(crate) fn pin_owned_directory(path: &Path) -> Result<File> {
    os::pin_directory(path)
}

/// A root-owned sticky temporary parent may contain a private runtime leaf.
/// The caller must validate that leaf with the ordinary owned-root checks.
#[cfg(unix)]
pub(crate) fn pin_runtime_temporary_parent(path: &Path) -> Result<File> {
    os::walk_effect_parent_for_creation(path)
}

/// Existing ancestors use the same native account/group policy in every creator.
/// This never changes permissions and does not validate an owned state root.
#[cfg(unix)]
pub(crate) fn validate_existing_ancestor(file: &File, path: &Path) -> Result<()> {
    os::validate_ancestor(file, path)
}
