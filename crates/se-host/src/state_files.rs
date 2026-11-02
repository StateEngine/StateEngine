//! Shared native custody adapter for direct CLI and hosted store access.
//!
//! Both routes retain the same root and use the same no-follow reads and
//! digest-checked mutations. Policy preserves their public inventory errors,
//! directory allowlists and recovery advice.
use se_proc::{NativeStateFiles, StateFileError, StateFileErrorCode};
use se_store::{StateFiles, StoreDetail, StoreError, StoreErrorCode, StoreResult};
use se_types::{Read, Remedy, Retry};
use std::{
    fs::File,
    io::Write,
    path::{Component, Path},
};

/// Caller policy; native custody and mutation rules are identical in both modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilePolicy {
    /// Explicit initialization and direct-client operations.
    Direct,
    /// Host backups and transcript capture under an initialized state root.
    Host,
}
impl FilePolicy {
    fn fail(self, code: StoreErrorCode, cause: &str) -> Box<StoreError> {
        let remedy = match self {
            Self::Direct => {
                "Use explicit init for missing state; otherwise restore access or use the authenticated live-host route."
            }
            Self::Host => {
                "Preserve the original protected state and restore exact native custody before retrying."
            }
        };
        Box::new(StoreError {
            code,
            cause: cause.into(),
            detail: StoreDetail::None,
            remedy: Remedy {
                text: remedy.into(),
                command: None,
            },
            retry: Retry::AfterReread,
        })
    }
    fn inventory_error(self, exceeded: bool) -> Box<StoreError> {
        match (self, exceeded) {
            (Self::Direct, false) => self.fail(
                StoreErrorCode::ReadBudgetTooSmall,
                "owned file inventory requires a positive maximum",
            ),
            (Self::Direct, true) => self.fail(
                StoreErrorCode::ReadIncomplete,
                "owned file inventory exceeds its requested maximum; no partial list returned",
            ),
            (Self::Host, false) => self.fail(
                StoreErrorCode::BackupFailed,
                "positive native inventory bound required",
            ),
            (Self::Host, true) => self.fail(
                StoreErrorCode::BackupFailed,
                "native inventory exceeds the caller's item budget; nothing was truncated",
            ),
        }
    }
}

/// Store file port with a retained native root and an immutable caller policy.
/// The native handle remains available for process-specific custody operations.
pub struct Files(pub NativeStateFiles, FilePolicy);
impl Files {
    /// Open for direct CLI access. Hosts must select `FilePolicy::Host` explicitly.
    pub fn open(path: &Path) -> StoreResult<Self> {
        Self::open_with_policy(path, FilePolicy::Direct)
    }
    pub fn open_with_policy(path: &Path, policy: FilePolicy) -> StoreResult<Self> {
        NativeStateFiles::open(path)
            .map(|native| Self(native, policy))
            .map_err(native_error)
    }
    /// Attach the direct-client policy to an already retained native root.
    pub fn from_native(native: NativeStateFiles) -> Self {
        Self(native, FilePolicy::Direct)
    }
    pub fn create(path: &Path) -> StoreResult<Self> {
        NativeStateFiles::create(path)
            .map(Self::from_native)
            .map_err(native_error)
    }
    /// Complete bounded immediate-file inventory through retained native
    /// custody. A budget or unsafe entry refuses the whole list.
    pub fn list_owned(
        &self,
        directory: &Path,
        maximum: usize,
    ) -> StoreResult<Vec<std::path::PathBuf>> {
        if maximum == 0 {
            return Err(self.1.inventory_error(false));
        }
        if directory == self.0.root() {
            self.check_root()?;
        } else {
            self.check_path(directory)?;
        }
        let paths = self.0.list_owned(directory).map_err(native_error)?;
        if paths.len() > maximum {
            return Err(self.1.inventory_error(true));
        }
        if paths.iter().any(|path| path.parent() != Some(directory)) {
            return Err(self.1.fail(
                StoreErrorCode::LocationUnsafe,
                "native inventory returned a path outside the requested immediate directory",
            ));
        }
        self.check_root()?;
        Ok(paths)
    }
}
impl Files {
    /// Retire only this caller's exact native staging bytes. A losing create
    /// can briefly contend with another retirement's cooperating parent pin.
    pub fn retire_staging(&self, path: &Path, digest: [u8; 32]) -> StoreResult<()> {
        self.check_path(path)?;
        if !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(".se-stage-"))
        {
            return Err(self.1.fail(
                StoreErrorCode::LocationUnsafe,
                "staging retirement requires a native unique staging name",
            ));
        }
        for attempt in 0..50 {
            match se_proc::OwnedFile::open(path) {
                Ok(Some(file)) => {
                    file.remove(digest).map_err(native_error)?;
                    return self.check_root();
                }
                Ok(None) => return self.check_root(),
                Err(error)
                    if error
                        .source
                        .as_ref()
                        .is_some_and(|source| source.kind() == std::io::ErrorKind::WouldBlock)
                        && attempt < 49 =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(error) => return Err(native_error(error)),
            }
        }
        Err(self.1.fail(
            StoreErrorCode::Unreadable,
            "bounded native staging parent contention did not clear",
        ))
    }
    fn check_root(&self) -> StoreResult<()> {
        // The real database read revalidates the original retained root before
        // and after opening. A missing database is still a valid root observation.
        self.0
            .readback(&self.0.root().join("state.db"))
            .map_err(native_error)?;
        Ok(())
    }
    fn check_path(&self, path: &Path) -> StoreResult<()> {
        let relative = path.strip_prefix(self.0.root()).map_err(|_| {
            self.1.fail(
                StoreErrorCode::LocationUnsafe,
                "owned state effect is outside its retained root",
            )
        })?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(self.1.fail(
                StoreErrorCode::LocationUnsafe,
                "owned state effect requires a normalized descendant file",
            ));
        }
        self.check_root()
    }
}
impl StateFiles for Files {
    fn list_owned(&self, directory: &Path, maximum: usize) -> StoreResult<Vec<std::path::PathBuf>> {
        Files::list_owned(self, directory, maximum)
    }
    fn prepare_directory(&self, path: &Path) -> StoreResult<()> {
        if path != self.0.root().join("backups")
            && path != self.0.root().join("staging")
            && !(self.1 == FilePolicy::Host && path == self.0.root().join("transcripts"))
        {
            return Err(self.1.fail(
                StoreErrorCode::LocationUnsafe,
                match self.1 {
                    FilePolicy::Direct => "only the fixed state backups/staging directories may be prepared",
                    FilePolicy::Host => "only the fixed state backups/staging/transcripts directories may be prepared",
                },
            ));
        }
        self.check_root()?;
        self.0.prepare_directory(path).map_err(native_error)?;
        self.check_root()
    }
    fn replace_owned(
        &self,
        path: &Path,
        expected: Option<[u8; 32]>,
        bytes: &[u8],
    ) -> StoreResult<()> {
        self.check_path(path)?;
        // Read through the private-root port before the common native mutation pin.
        // This preserves owner-only protection in addition to the effects pin's identity.
        self.0.readback(path).map_err(native_error)?;
        match (
            se_proc::OwnedFile::open(path).map_err(native_error)?,
            expected,
        ) {
            (Some(file), Some(digest)) => file.replace(digest, bytes).map_err(native_error)?,
            (None, None) => {
                let parent = path.parent().ok_or_else(|| {
                    self.1
                        .fail(StoreErrorCode::LocationUnsafe, "manifest parent is absent")
                })?;
                let mut staged = self.0.create_staging(parent).map_err(native_error)?;
                staged.file.write_all(bytes).map_err(|error| {
                    self.1.fail(
                        StoreErrorCode::Unreadable,
                        &format!("write manifest staging: {error}"),
                    )
                })?;
                staged.file.sync_all().map_err(|error| {
                    self.1.fail(
                        StoreErrorCode::Unreadable,
                        &format!("sync manifest staging: {error}"),
                    )
                })?;
                drop(staged.file);
                self.0
                    .publish_no_replace(&staged.path, path)
                    .map_err(native_error)?;
            }
            _ => {
                return Err(self.1.fail(
                    StoreErrorCode::SourceChanged,
                    "owned manifest presence differs from its measured expectation",
                ));
            }
        }
        if self.0.readback(path).map_err(native_error)?.is_none() {
            return Err(self.1.fail(
                StoreErrorCode::SourceChanged,
                "published state manifest is absent on private-root readback",
            ));
        }
        self.check_root()
    }
    fn remove_owned(&self, path: &Path, expected: [u8; 32]) -> StoreResult<()> {
        self.check_path(path)?;
        self.0.readback(path).map_err(native_error)?;
        if let Some(file) = se_proc::OwnedFile::open(path).map_err(native_error)? {
            file.remove(expected).map_err(native_error)?;
        }
        if self.0.readback(path).map_err(native_error)?.is_some() {
            return Err(self.1.fail(
                StoreErrorCode::SourceChanged,
                "retired state generation remains present",
            ));
        }
        self.check_root()
    }

    fn create_staging(&self, directory: &Path) -> StoreResult<se_store::ProtectedStaging> {
        let staged = self.0.create_staging(directory).map_err(native_error)?;
        Ok(se_store::ProtectedStaging {
            path: staged.path,
            file: staged.file,
        })
    }
    fn readback(&self, path: &Path) -> StoreResult<Read<File>> {
        Ok(match self.0.readback(path).map_err(native_error)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked: format!("native no-follow readback at {}", path.display()),
            },
        })
    }
    fn publish_no_replace(&self, staged: &Path, destination: &Path) -> StoreResult<()> {
        self.0
            .publish_no_replace(staged, destination)
            .map_err(native_error)
    }
}
fn native_error(error: StateFileError) -> Box<StoreError> {
    Box::new(StoreError {code:match error.code {
        StateFileErrorCode::AlreadyExists=>StoreErrorCode::AlreadyExists,
        StateFileErrorCode::Unreadable=>StoreErrorCode::Unreadable,
        StateFileErrorCode::LocationUnsafe|StateFileErrorCode::Unsupported=>StoreErrorCode::LocationUnsafe,
        StateFileErrorCode::SourceChanged=>StoreErrorCode::SourceChanged,
    },cause:error.to_string(),detail:StoreDetail::None,remedy:Remedy {text:"Preserve the existing file and restore native ownership/protection before retrying the same request identity.".into(),command:None},retry:Retry::Never})
}

/// Read-only machine identity for a host that never creates one (the embedded
/// SE Code path): the same bounded, twice-read, byte-compared rule the CLI's
/// creating port applies, through this root's retained native custody.
pub fn machine_identity(files: &Files) -> se_types::Result<se_types::MachineId> {
    use se_core::machine_identity::{
        MACHINE_IDENTITY_FILE, MACHINE_IDENTITY_MAX_BYTES, MachineIdentityPort, Publication,
    };
    use std::io::Read as _;
    struct ReadOnly<'a>(&'a Files);
    fn read_bounded(files: &Files, path: &Path) -> se_types::Result<Option<Vec<u8>>> {
        let unreadable = |e: &dyn std::fmt::Display| {
            se_core::scope::unreadable("protected machine identity", &e.to_string())
        };
        let Some(file) = files.0.readback(path).map_err(|e| unreadable(&e))? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take((MACHINE_IDENTITY_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| unreadable(&e))?;
        if bytes.len() > MACHINE_IDENTITY_MAX_BYTES {
            return Err(unreadable(&"record exceeds 1024 bytes"));
        }
        Ok(Some(bytes))
    }
    impl MachineIdentityPort for ReadOnly<'_> {
        fn read(&self, home: &Path) -> se_types::Result<Read<Vec<u8>>> {
            if home != self.0.0.root() {
                return Err(se_core::scope::unreadable(
                    "protected machine identity",
                    "home differs from retained native custody",
                ));
            }
            let path = home.join(MACHINE_IDENTITY_FILE);
            let Some(bytes) = read_bounded(self.0, &path)? else {
                return Ok(Read::Absent {
                    checked: format!("native owner-only file absence at {}", path.display()),
                });
            };
            // Reopen independently; a changed record supplies no startup fact.
            if read_bounded(self.0, &path)?.as_ref() != Some(&bytes) {
                return Err(se_core::scope::unreadable(
                    "protected machine identity",
                    "record changed during read",
                ));
            }
            Ok(Read::Present { value: bytes })
        }
        fn publish_no_replace(&self, _home: &Path, _bytes: &[u8]) -> se_types::Result<Publication> {
            Err(se_types::SeError::invalid(
                "machine identity",
                "one created by se init; an embedded host never creates it",
            ))
        }
    }
    se_core::machine_identity::require_machine_identity(files.0.root(), &ReadOnly(files))
}
