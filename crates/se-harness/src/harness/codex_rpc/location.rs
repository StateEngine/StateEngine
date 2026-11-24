//! Protected per-launch rendezvous, including the short-path fallback. The
//! actual directory incarnation is journaled before the provider can start.
use super::*;
use std::io::Write;
#[cfg(unix)]
mod endpoint;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    session: se_types::SessionId,
    socket: NativePath,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
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
        crate::codex_endpoint::prepare(socket, record, session)?;
        #[cfg(not(any(unix, windows)))]
        let _ = (socket, record, session);
        Ok(())
    }
    pub(super) fn socket(&self, request: &HarnessRequest) -> Result<Option<PathBuf>> {
        let session = &request.identity.session;
        crate::codex_endpoint::socket_path(
            self.directory(session)?,
            &self.socket_root,
            &self.state_home,
            session,
        )
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
        crate::codex_endpoint::recover(&socket, record, session)?;
        Ok(socket)
    }
    pub async fn prepare_socket(&self, request: &HarnessRequest, cx: &CallContext) -> Result<()> {
        let Some(socket) = self.socket(request)? else {
            return Ok(());
        };
        let record = self
            .directory(&request.identity.session)?
            .join("codex-runtime.json");
        let session = request.identity.session.clone();
        let deadline = crate::Deadline::idle()?.stage(cx.timeout)?;
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
            let _short_root = crate::codex_endpoint::hold_short_root(parent)?;
            match std::fs::symlink_metadata(parent) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Ok(_) => return Err(incompatible("the rendezvous directory already exists", "Reconcile its original launch; a new launch never reuses or repairs it.")),
                Err(e) => return Err(se_core::scope::unreadable("Codex rendezvous directory", &e.to_string())),
            }
            let directory = se_proc::NativeStateFiles::create(parent).map_err(native_error)?;
            #[cfg(windows)]
            crate::codex_endpoint::record(&socket, &record, &session)?;
            #[cfg(unix)]
            let (device, inode) = { use std::os::unix::fs::MetadataExt; let metadata = std::fs::symlink_metadata(parent).map_err(|e| se_core::scope::unreadable("Codex socket directory identity", &e.to_string()))?; (metadata.dev(), metadata.ino()) };
            let value = Record { session, socket: NativePath::from_local(socket)?, #[cfg(unix)] device, #[cfg(unix)] inode };
            let bytes = serde_json::to_vec(&value).map_err(|e| se_core::scope::unreadable("Codex runtime record", &e.to_string()))?;
            let parent = record.parent().ok_or_else(|| SeError::invalid("Codex runtime record", "a protected launch directory"))?;
            let files = se_proc::NativeStateFiles::open(parent).map_err(native_error)?;
            let mut staged = files.create_staging(parent).map_err(native_error)?;
            // Publication flushes the staged data before moving its name.
            staged.file.write_all(&bytes).map_err(|e| se_core::scope::unreadable("Codex runtime durability", &e.to_string()))?;
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
    pub fn retire_socket(&self, session: &se_types::SessionId) -> Result<()> {
        let path = self.directory(session)?.join("codex-runtime.json");
        let Some(mut owned) = se_proc::OwnedFile::open(&path).map_err(native_error)? else {
            return self.verify_planned_rendezvous(session);
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
        retire_endpoint(&socket, &path, &value)?;
        #[cfg(windows)]
        crate::codex_endpoint::retire(&socket, &path, session)?;
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
    fn verify_planned_rendezvous(&self, session: &se_types::SessionId) -> Result<()> {
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
            let planned: Planned = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
                .map_err(|e| {
                    se_core::scope::unreadable("Codex planned rendezvous", &e.to_string())
                })?;
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
        Ok(())
    }
}
#[cfg(unix)]
fn retire_endpoint(socket: &Path, path: &Path, value: &Record) -> Result<()> {
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
    endpoint::retire(socket, path, value)?;
    if directory.is_some() {
        match se_proc::remove_empty_directory(parent).map_err(native_error)? {
            se_proc::DirectoryRemoval::Removed | se_proc::DirectoryRemoval::AlreadyAbsent => (),
            _ => {
                return Err(se_core::scope::unreadable(
                    "Codex rendezvous cleanup",
                    "the exact directory remains nonempty",
                ));
            }
        }
    }
    Ok(())
}
