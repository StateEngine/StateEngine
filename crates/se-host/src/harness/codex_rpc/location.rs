//! Protected per-launch rendezvous, including the short-path fallback. The
//! actual directory incarnation is journaled before the provider can start.
use super::*;
use std::io::Write;
#[cfg(unix)]
mod endpoint;
/// The Windows private endpoint: the forwarder's AF_UNIX socket in a private
/// per-launch directory. The directory and the socket leaf are pinned by native
/// object identity (volume and file index) and the leaf by its AF_UNIX reparse
/// tag; any mismatch is preserved and reported, never repaired or unlinked.
#[cfg(windows)]
mod windows {
    use super::*;
    use se_proc::NativeFileIdentity;

    /// The socket leaf's identity, pinned when the host first checks it.
    pub(super) const PIN: &str = "codex-endpoint.json";

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pin {
        session: se_types::SessionId,
        leaf: [u8; 32],
    }

    fn failure(reason: &str) -> SeError {
        se_core::scope::unreadable("Codex private endpoint custody", reason)
    }

    /// The private directory's identity, after its owner-only access is checked.
    pub(super) fn directory_identity(parent: &Path) -> Result<[u8; 32]> {
        let _private = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
        NativeFileIdentity::observe_directory(parent)
            .map(|identity| identity.to_bytes())
            .map_err(|e| failure(&e.to_string()))
    }

    fn read_record(record: &Path, session: &se_types::SessionId) -> Result<Record> {
        let mut file = se_proc::OwnedFile::open(record)
            .map_err(native_error)?
            .ok_or_else(|| failure("original private rendezvous record is absent"))?;
        let value: Record = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
            .map_err(|e| failure(&e.to_string()))?;
        if &value.session != session {
            return Err(failure("the record names another session"));
        }
        Ok(value)
    }

    fn original_directory(socket: &Path, value: &Record) -> Result<()> {
        if value.socket.to_local()? != socket || socket.file_name().is_none_or(|name| name != "s") {
            return Err(failure(
                "listen path differs from the original launch record",
            ));
        }
        let parent = socket
            .parent()
            .ok_or_else(|| failure("missing listen parent"))?;
        if directory_identity(parent)? != value.directory {
            return Err(failure("original private listen directory was replaced"));
        }
        Ok(())
    }

    fn leaf(socket: &Path) -> Result<[u8; 32]> {
        NativeFileIdentity::observe_local_socket(socket)
            .map(|identity| identity.to_bytes())
            .map_err(|e| failure(&format!("listen leaf is not the local socket: {e}")))
    }

    fn read_pin(path: &Path, session: &se_types::SessionId) -> Result<Option<[u8; 32]>> {
        let Some(mut file) = se_proc::OwnedFile::open(path).map_err(native_error)? else {
            return Ok(None);
        };
        let pin: Pin = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
            .map_err(|e| failure(&e.to_string()))?;
        if &pin.session != session {
            return Err(failure("the endpoint pin names another session"));
        }
        Ok(Some(pin.leaf))
    }

    /// Before any session secret is sent: the recorded directory, and the
    /// socket leaf, pinned the first time and compared on every later check.
    pub(super) fn check(socket: &Path, record: &Path, session: &se_types::SessionId) -> Result<()> {
        let value = read_record(record, session)?;
        original_directory(socket, &value)?;
        let observed = leaf(socket)?;
        let pin = record
            .parent()
            .ok_or_else(|| failure("missing launch directory"))?
            .join(PIN);
        match read_pin(&pin, session)? {
            Some(pinned) if pinned == observed => Ok(()),
            Some(_) => Err(failure("the socket leaf was replaced since it was pinned")),
            None => {
                let bytes = serde_json::to_vec(&Pin {
                    session: session.clone(),
                    leaf: observed,
                })
                .map_err(|e| failure(&e.to_string()))?;
                let parent = pin
                    .parent()
                    .ok_or_else(|| failure("missing launch directory"))?;
                let files = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
                let mut staged = files.create_staging(parent).map_err(native_error)?;
                use std::io::Write;
                staged
                    .file
                    .write_all(&bytes)
                    .and_then(|()| staged.file.sync_all())
                    .map_err(|e| failure(&e.to_string()))?;
                drop(staged.file);
                files
                    .publish_no_replace(&staged.path, &pin)
                    .map_err(native_error)
            }
        }
    }

    /// After native exit: remove only the pinned leaf and its exact directory;
    /// anything that changed is preserved and reported.
    pub(super) fn retire(socket: &Path, record: &Path, value: &Record) -> Result<()> {
        let parent = socket
            .parent()
            .ok_or_else(|| failure("missing listen parent"))?;
        match std::fs::symlink_metadata(parent) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(failure(&e.to_string())),
            Ok(_) => {
                original_directory(socket, value)?;
                let pin_path = record
                    .parent()
                    .ok_or_else(|| failure("missing launch directory"))?
                    .join(PIN);
                // Each removal compares and disposes through one handle.
                match read_pin(&pin_path, &value.session)? {
                    Some(pinned) => {
                        NativeFileIdentity::from_bytes(pinned)
                            .remove_local_socket(socket)
                            .map_err(|e| failure(&format!("socket leaf: {e}")))?;
                    }
                    None if std::fs::symlink_metadata(socket).is_ok() => {
                        return Err(failure("the socket leaf was never pinned; it is preserved"));
                    }
                    None => {}
                }
                NativeFileIdentity::from_bytes(value.directory)
                    .remove_directory(parent)
                    .map_err(|e| failure(&format!("private listen directory: {e}")))?;
                if let Some(mut file) = se_proc::OwnedFile::open(&pin_path).map_err(native_error)? {
                    let digest: [u8; 32] =
                        Sha256::digest(file.read(8192).map_err(native_error)?).into();
                    file.remove(digest).map_err(native_error)?;
                }
            }
        }
        Ok(())
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
    /// The private directory's native identity on Windows.
    #[cfg(windows)]
    directory: [u8; 32],
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
        // The forwarder listens in a private per-launch directory: the launch's
        // own when its path fits a local socket address, otherwise a short one
        // under the data home named by the launch.
        #[cfg(windows)]
        {
            const LIMIT: usize = 107;
            let preferred = self
                .directory(&request.identity.session)?
                .join("cx")
                .join("s");
            let selected = if preferred.as_os_str().as_encoded_bytes().len() <= LIMIT {
                preferred
            } else {
                let launch =
                    se_proc::session_launch_id(&request.identity.session).map_err(native_error)?;
                let name = se_types::hex_lower(&Sha256::digest(launch.as_str().as_bytes()));
                self.state_home.join("cx").join(&name[..16]).join("s")
            };
            if selected.as_os_str().as_encoded_bytes().len() > LIMIT {
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
            #[cfg(windows)]
            let _short_root = match parent.parent() {
                // The short fallback lives under the data home's own `cx` root.
                Some(root) if root.file_name().is_some_and(|name| name == "cx") => {
                    Some(se_proc::NativeStateFiles::create(root).map_err(native_error)?)
                }
                _ => None,
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
            let directory_identity = windows::directory_identity(parent)?;
            let value = Record { session, socket: NativePath::from_local(socket)?, #[cfg(unix)] device, #[cfg(unix)] inode, #[cfg(windows)] directory: directory_identity };
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
        windows::retire(&socket, &path, &value)?;
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
