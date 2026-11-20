//! Protected per-launch rendezvous, including the short-path fallback. The
//! actual directory incarnation is journaled before the provider can start.
use super::*;
use std::io::Write;
#[cfg(unix)]
mod endpoint;
/// The Windows private endpoint: the forwarder's AF_UNIX socket in the
/// launch's private directory. Its directory incarnation is the creation time
/// recorded at launch; a replaced directory is refused, never repaired.
#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::fs::MetadataExt;

    const REPARSE_POINT: u32 = 0x400;

    fn failure(reason: &str) -> SeError {
        se_core::scope::unreadable("Codex private endpoint custody", reason)
    }

    /// The private directory's incarnation, after its owner-only access is checked.
    pub(super) fn incarnation(parent: &Path) -> Result<u64> {
        let _private = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
        let created = std::fs::symlink_metadata(parent)
            .and_then(|metadata| metadata.created())
            .map_err(|e| failure(&e.to_string()))?;
        let nanos = created
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| failure(&e.to_string()))?
            .as_nanos();
        u64::try_from(nanos).map_err(|_| failure("directory creation time is out of range"))
    }

    fn original(socket: &Path, value: &Record) -> Result<()> {
        if value.socket.to_local()? != socket || socket.file_name().is_none_or(|name| name != "s") {
            return Err(failure(
                "listen path differs from the original launch record",
            ));
        }
        let parent = socket
            .parent()
            .ok_or_else(|| failure("missing listen parent"))?;
        if incarnation(parent)? != value.created {
            return Err(failure("original private listen directory was replaced"));
        }
        Ok(())
    }

    /// Before any session secret is sent: the recorded directory, and a socket leaf.
    pub(super) fn check(socket: &Path, record: &Path, session: &se_types::SessionId) -> Result<()> {
        let mut file = se_proc::OwnedFile::open(record)
            .map_err(native_error)?
            .ok_or_else(|| failure("original private rendezvous record is absent"))?;
        let value: Record = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
            .map_err(|e| failure(&e.to_string()))?;
        drop(file);
        if &value.session != session {
            return Err(failure("the record names another session"));
        }
        original(socket, &value)?;
        let leaf = std::fs::symlink_metadata(socket).map_err(|e| failure(&e.to_string()))?;
        if leaf.is_dir() || leaf.file_attributes() & REPARSE_POINT == 0 {
            return Err(failure("listen leaf is not a local socket"));
        }
        Ok(())
    }

    /// After native exit: remove only the recorded socket leaf and its directory.
    pub(super) fn retire(socket: &Path, value: &Record) -> Result<()> {
        let parent = socket
            .parent()
            .ok_or_else(|| failure("missing listen parent"))?;
        match std::fs::symlink_metadata(parent) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(failure(&e.to_string())),
            Ok(_) => {}
        }
        original(socket, value)?;
        match std::fs::symlink_metadata(socket) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(failure(&e.to_string())),
            Ok(leaf) if leaf.is_dir() || leaf.file_attributes() & REPARSE_POINT == 0 => {
                return Err(failure("listen leaf is not a local socket; preserve it"));
            }
            Ok(_) => std::fs::remove_file(socket).map_err(|e| failure(&e.to_string()))?,
        }
        match se_proc::remove_empty_directory(parent).map_err(native_error)? {
            se_proc::DirectoryRemoval::Removed | se_proc::DirectoryRemoval::AlreadyAbsent => Ok(()),
            _ => Err(failure("the exact directory remains nonempty")),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    session: se_types::SessionId,
    socket: NativePath,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    /// The private directory's creation time, its incarnation on Windows.
    #[cfg(windows)]
    created: u64,
}
impl CodexHarness {
    pub(super) fn validate_socket(
        socket: &Path,
        record: &Path,
        session: &se_types::SessionId,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            endpoint::prepare(socket, record, session)?;
        }
        #[cfg(windows)]
        windows::check(socket, record, session)?;
        #[cfg(not(any(unix, windows)))]
        let _ = (socket, record, session);
        Ok(())
    }
    pub(super) fn socket(&self, request: &HarnessRequest) -> Result<Option<PathBuf>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let directory = self.directory(&request.identity.session)?;
            let preferred = directory.join("cx/s");
            let selected = if preferred.as_os_str().as_bytes().len() < 100 {
                preferred
            } else {
                let launch =
                    se_proc::session_launch_id(&request.identity.session).map_err(native_error)?;
                let requested = self
                    .socket_root
                    .join(format!(
                        "se-cx-{}",
                        launch.as_str().trim_start_matches("lch_")
                    ))
                    .join("s");
                if requested.as_os_str().as_bytes().len() < 100 {
                    requested
                } else {
                    se_proc::native_ipc::UnixSocketPaths::short_provider_root()
                        .join(format!(
                            "se-cx-{}",
                            launch.as_str().trim_start_matches("lch_")
                        ))
                        .join("s")
                }
            };
            if !selected.is_absolute() || selected.as_os_str().as_bytes().len() >= 100 {
                return Err(incompatible(
                    "no protected Unix socket path fits the provider limit",
                    "Select a shorter private runtime/temp location.",
                ));
            }
            Ok(Some(selected))
        }
        // The forwarder listens in the launch's own private directory.
        #[cfg(windows)]
        {
            let selected = self
                .directory(&request.identity.session)?
                .join("cx")
                .join("s");
            if selected.as_os_str().as_encoded_bytes().len() >= 100 {
                return Err(incompatible(
                    "the private local socket path is longer than Windows allows",
                    "Move the StateEngine data home to a shorter folder and relaunch.",
                ));
            }
            Ok(Some(selected))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = request;
            Ok(None)
        }
    }
    /// Recovery reads the original protected address, never a newly selected path.
    #[cfg(any(unix, windows))]
    pub(super) fn retained_socket(record: &Path, session: &se_types::SessionId) -> Result<PathBuf> {
        let mut file = se_proc::OwnedFile::open(record)
            .map_err(native_error)?
            .ok_or_else(|| {
                se_core::scope::unreadable(
                    "Codex recovery",
                    "original private rendezvous record is absent",
                )
            })?;
        let value: Record = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
            .map_err(|e| se_core::scope::unreadable("Codex recovery record", &e.to_string()))?;
        drop(file);
        if &value.session != session {
            return Err(SeError::invalid(
                "Codex recovery",
                "the exact recorded session",
            ));
        }
        let socket = value.socket.to_local()?;
        #[cfg(unix)]
        endpoint::recover(&socket, record, session)?;
        #[cfg(windows)]
        windows::check(&socket, record, session)?;
        Ok(socket)
    }
    pub(crate) async fn prepare_socket(
        &self,
        request: &HarnessRequest,
        cx: &CallContext,
    ) -> Result<()> {
        let Some(socket) = self.socket(request)? else {
            return Ok(());
        };
        let record = self
            .directory(&request.identity.session)?
            .join("codex-runtime.json");
        let session = request.identity.session.clone();
        let deadline = crate::client::lease::Deadline::idle()?.stage(cx.timeout)?;
        self.pool.run_owned(&deadline, move || {
            let parent = socket.parent().ok_or_else(|| SeError::invalid("Codex socket", "a parent"))?;
            #[cfg(unix)]
            let _short_root = {
                let root = se_proc::native_ipc::UnixSocketPaths::short_provider_root();
                if parent.parent() == Some(root.as_path()) {
                    Some(se_proc::NativeStateFiles::create(&root).map_err(native_error)?)
                } else { None }
            };
            match std::fs::symlink_metadata(parent) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Ok(_) => return Err(incompatible("the rendezvous directory already exists", "Reconcile its original launch; a new launch never reuses or repairs it.")),
                Err(e) => return Err(se_core::scope::unreadable("Codex rendezvous directory", &e.to_string())),
            }
            let directory = se_proc::NativeStateFiles::create(parent).map_err(native_error)?;
            #[cfg(unix)]
            let (device, inode) = { use std::os::unix::fs::MetadataExt; let metadata = std::fs::symlink_metadata(parent).map_err(|e| se_core::scope::unreadable("Codex socket directory identity", &e.to_string()))?; (metadata.dev(), metadata.ino()) };
            #[cfg(windows)]
            let created = windows::incarnation(parent)?;
            let value = Record { session, socket: NativePath::from_local(socket)?, #[cfg(unix)] device, #[cfg(unix)] inode, #[cfg(windows)] created };
            let bytes = serde_json::to_vec(&value).map_err(|e| se_core::scope::unreadable("Codex runtime record", &e.to_string()))?;
            let parent = record.parent().ok_or_else(|| SeError::invalid("Codex runtime record", "a protected launch directory"))?;
            let files = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
            let mut staged = files.create_staging(parent).map_err(native_error)?;
            staged.file.write_all(&bytes).and_then(|()| staged.file.sync_all()).map_err(|e| se_core::scope::unreadable("Codex runtime durability", &e.to_string()))?;
            drop(staged.file);
            files.publish_no_replace(&staged.path, &record).map_err(native_error)?;
            let mut witness = se_proc::OwnedFile::open(&record).map_err(native_error)?.ok_or_else(|| se_core::scope::unreadable("Codex runtime record", "published record is absent"))?;
            if witness.read(8192).map_err(native_error)? != bytes { return Err(se_core::scope::unreadable("Codex runtime record", "published bytes differ")); }
            drop(directory);
            Ok(())
        }).await
    }
    /// Called only after native scope exit, including cold cleanup. No recursive
    /// removal, path reconstruction from provider output, or permission repair.
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(crate) fn retire_socket(&self, session: &se_types::SessionId) -> Result<()> {
        let path = self.directory(session)?.join("codex-runtime.json");
        let Some(mut owned) = se_proc::OwnedFile::open(&path).map_err(native_error)? else {
            // A durable plan precedes creation. If creation was interrupted
            // before its incarnation record, absence and unproved custody are
            // different outcomes; never call a remaining directory removed.
            let plan = self.directory(session)?.join("codex-plan.json");
            if let Some(mut file) = se_proc::OwnedFile::open(&plan).map_err(native_error)? {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Planned {
                    session: se_types::SessionId,
                    socket: Option<NativePath>,
                }
                let planned: Planned =
                    serde_json::from_slice(&file.read(8192).map_err(native_error)?).map_err(
                        |e| se_core::scope::unreadable("Codex planned rendezvous", &e.to_string()),
                    )?;
                if &planned.session != session {
                    return Err(SeError::invalid(
                        "Codex planned rendezvous",
                        "the exact original session",
                    ));
                }
                if let Some(socket) = planned.socket {
                    let socket = socket.to_local()?;
                    let parent = socket
                        .parent()
                        .ok_or_else(|| SeError::invalid("Codex socket", "a parent"))?;
                    match std::fs::symlink_metadata(parent) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                        _ => {
                            return Err(se_core::scope::unreadable(
                                "Codex rendezvous custody",
                                "the planned directory remains without an actual creation record; preserve it for owner reconciliation",
                            ));
                        }
                    }
                }
            }
            return Ok(());
        };
        let bytes = owned.read(8192).map_err(native_error)?;
        let value: Record = serde_json::from_slice(&bytes)
            .map_err(|e| se_core::scope::unreadable("Codex runtime record", &e.to_string()))?;
        if &value.session != session {
            return Err(SeError::invalid(
                "Codex runtime cleanup",
                "the exact original session",
            ));
        }
        // OwnedFile takes an exclusive parent hold. Release it before opening
        // the endpoint sibling, then reacquire and compare the original bytes
        // before removing the runtime record.
        drop(owned);
        let socket = value.socket.to_local()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let parent = socket
                .parent()
                .ok_or_else(|| SeError::invalid("Codex socket", "a private parent"))?;
            let directory = match std::fs::symlink_metadata(parent) {
                Ok(metadata) => Some(metadata),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(se_core::scope::unreadable(
                        "Codex rendezvous cleanup",
                        &e.to_string(),
                    ));
                }
            };
            if let Some(metadata) = &directory {
                let _pin = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
                if metadata.dev() != value.device
                    || metadata.ino() != value.inode
                    || socket.file_name().is_none_or(|name| name != "s")
                {
                    return Err(se_core::scope::unreadable(
                        "Codex socket cleanup",
                        "recorded directory incarnation differs; preserve the replacement",
                    ));
                }
            }
            endpoint::retire(&socket, &path, &value)?;
            if directory.is_some() {
                match se_proc::remove_empty_directory(parent).map_err(native_error)? {
                    se_proc::DirectoryRemoval::Removed
                    | se_proc::DirectoryRemoval::AlreadyAbsent => (),
                    _ => {
                        return Err(se_core::scope::unreadable(
                            "Codex rendezvous cleanup",
                            "the exact directory remains nonempty",
                        ));
                    }
                }
            }
        }
        #[cfg(windows)]
        windows::retire(&socket, &value)?;
        #[cfg(not(any(unix, windows)))]
        let _ = socket;
        se_proc::OwnedFile::open(&path)
            .map_err(native_error)?
            .ok_or_else(|| {
                se_core::scope::unreadable(
                    "Codex runtime cleanup",
                    "original record disappeared before removal",
                )
            })?
            .remove(Sha256::digest(&bytes).into())
            .map_err(native_error)
    }
}
