//! Protected native files for the store's StateFiles port. CLI/host wrappers
//! translate these native results into StoreResult; se-proc does not depend on
//! se-store or se-host. This object pins one already-authorized state directory.
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
use windows as os;

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
impl std::fmt::Display for StateFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at {}: {:?}",
            self.operation,
            self.path.display(),
            self.code
        )?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StateFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}
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
    pub fn create_staging(&self, directory: &Path) -> Result<ProtectedStateStaging> {
        self.check(directory)?;
        for _ in 0..8 {
            let random = os::random(directory)?;
            let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
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
    /// Some is a verified regular, owner-only file. None is witnessed native
    /// absence. Every other read outcome remains a typed error with its cause.
    pub fn readback(&self, path: &Path) -> Result<Option<File>> {
        self.check(path)?;
        let result = self.directory.readback(path, &self.root)?;
        self.check(path)?;
        Ok(result)
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

/// Existing ancestors use the same native account/group policy in every creator.
/// This never changes permissions and does not validate an owned state root.
#[cfg(unix)]
pub(crate) fn validate_existing_ancestor(file: &File, path: &Path) -> Result<()> {
    os::validate_ancestor(file, path)
}
