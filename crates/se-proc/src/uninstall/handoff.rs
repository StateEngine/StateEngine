use super::*;

pub struct NativeUninstallHandoff {
    parent: UninstallProcessIdentity,
    helper: UninstallProcessIdentity,
    process: OwnedHandle,
    authorize: File,
    ready: File,
    nonce: [u8; 32],
    deadline: u64,
    ready_seen: bool,
    staged_paths: [PathBuf; 1],
    cleanup: UninstallHelperCleanup,
}
impl NativeUninstallHandoff {
    /// Core must first validate/record the complete plan and human admission.
    /// Native code chooses this process's actual image, never a caller target.
    pub fn start(files: &NativeStateFiles, plan: &[u8], timeout: Duration) -> Result<Self> {
        if !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&timeout) {
            return Err(refuse(
                "prepare uninstall handoff",
                "deadline must be 1 to 300 seconds",
            ));
        }
        let mut pending = Vec::new();
        let result = (|| {
            let parent_pin = native::current_process()?;
            let parent = native::process_identity(&parent_pin)?;
            let mut target = native::open_image(&parent.image, false)?;
            let target_id = native::file_id(&target)?;
            let digest = native::digest(&mut target)?;
            let original_root = files.root().to_owned();
            let staging = if staging::elevated()? {
                Some(staging::Staging::create(files)?)
            } else {
                None
            };
            if let Some(stage) = &staging {
                pending.push(stage.directory.path.clone());
            }
            let stage_directory = staging.as_ref().map(|stage| stage.directory.clone());
            let files = staging.as_ref().map_or(files, |stage| stage.files());
            let mut staged = files.create_staging(files.root()).map_err(custody)?;
            pending.push(staged.path.clone());
            io::copy(&mut target, &mut staged.file)
                .map_err(|e| error("stage uninstall helper image", e))?;
            staged
                .file
                .sync_all()
                .map_err(|e| error("flush staged uninstall helper", e))?;
            if staging.is_some() {
                staging::verify_high(&staged.file, false)?;
            }
            let helper_path = staged.path.with_extension("exe");
            drop(staged.file);
            files
                .publish_no_replace(&staged.path, &helper_path)
                .map_err(custody)?;
            if let Some(last) = pending.last_mut() {
                *last = helper_path.clone();
            }
            // The retained read pin denies write sharing before digest readback,
            // and remains held through CreateProcessW. A raced writer either
            // prevents this open or changes the bytes that this pin verifies.
            let mut helper_pin = native::open_image(&helper_path, false)?;
            if native::digest(&mut helper_pin)? != digest {
                return Err(refuse(
                    "read back staged uninstall helper",
                    "staged image bytes differ from installed image",
                ));
            }
            let helper_file = native::delete_on_close(&helper_pin)?;
            protected(&helper_file, &helper_path)?;
            let helper_id = native::file_id(&helper_file)?;
            let (authorize_read, authorize_write) = native::pipe()?;
            let (ready_read, ready_write) = native::pipe()?;
            let inherited = [
                native::duplicate(
                    parent_pin.as_raw_handle(),
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    true,
                )?,
                native::duplicate(target.as_raw_handle(), FILE_GENERIC_READ, true)?,
                native::duplicate(helper_file.as_raw_handle(), FILE_GENERIC_READ, true)?,
                native::duplicate(authorize_read.as_raw_handle(), FILE_GENERIC_READ, true)?,
                native::duplicate(ready_write.as_raw_handle(), FILE_GENERIC_WRITE, true)?,
            ];
            let (plan_read, mut plan_write) = native::pipe()?;
            let mut nonce = [0; 32];
            crate::fill_entropy(&mut nonce)
                .map_err(|e| error("prepare uninstall handoff", io::Error::other(e)))?;
            let deadline = clock()
                .checked_add(timeout.as_millis() as u64)
                .ok_or_else(|| refuse("prepare uninstall handoff", "deadline overflow"))?;
            let frame = Frame {
                handles: inherited
                    .each_ref()
                    .map(|h| h.as_raw_handle() as usize as u64),
                parent: parent.clone(),
                target: target_id,
                helper: helper_id,
                digest,
                nonce,
                deadline,
                root: files.root().to_owned(),
                cleanup_root: original_root.clone(),
                directory: stage_directory.clone(),
                helper_path: helper_path.clone(),
                plan: plan.to_vec(),
            };
            let encoded = frame.encode()?;
            let stdin = native::duplicate(plan_read.as_raw_handle(), FILE_GENERIC_READ, true)?;
            let mut handles = inherited.each_ref().map(AsRawHandle::as_raw_handle);
            let process = spawn::start(&helper_path, &stdin, &mut handles)?;
            // The child is now reading. Writing before spawning would block
            // once the bounded anonymous pipe fills. Only this parent owns its
            // write end; dropping it supplies EOF to the inherited reader.
            drop(stdin);
            drop(plan_read);
            check_deadline(deadline)?;
            plan_write
                .write_all(&encoded)
                .map_err(|e| error("write private uninstall plan pipe", e))?;
            drop(plan_write);
            check_deadline(deadline)?;
            let helper = native::process_identity(&process)?;
            if native::file_id(&native::open_image(&helper.image, false)?)? != helper_id {
                return Err(refuse(
                    "read back uninstall helper identity",
                    "launched image differs from protected helper",
                ));
            }
            let cleanup = UninstallHelperCleanup::new(
                original_root,
                helper_path.clone(),
                &helper,
                helper_id,
                digest,
                stage_directory,
            );
            Ok(Self {
                parent,
                helper,
                process,
                authorize: authorize_write,
                ready: ready_read,
                nonce,
                deadline,
                ready_seen: false,
                staged_paths: [helper_path],
                cleanup,
            })
        })();
        result.map_err(|mut e: UninstallNativeError| {
            e.pending_paths.extend(pending);
            e
        })
    }
    pub fn helper(&self) -> &UninstallProcessIdentity {
        &self.helper
    }
    pub fn staged_paths(&self) -> [&Path; 1] {
        [&self.staged_paths[0]]
    }
    pub fn staging_directory(&self) -> Option<&Path> {
        self.cleanup.directory_path()
    }
    pub fn poll_ready(&mut self) -> Result<UninstallReady> {
        check_deadline(self.deadline)?;
        if native::exited(&self.process)? {
            return Err(refuse(
                "observe uninstall helper readiness",
                "helper exited before handoff",
            ));
        }
        if self.ready_seen {
            return Ok(UninstallReady::Ready);
        }
        if let Some(frame) = native::poll_frame(&mut self.ready)? {
            if frame[0] != b'R' || frame[1..] != self.nonce {
                return Err(refuse(
                    "authenticate uninstall readiness",
                    "private readiness frame mismatch",
                ));
            }
            self.ready_seen = true;
            Ok(UninstallReady::Ready)
        } else {
            Ok(UninstallReady::Pending)
        }
    }
    pub fn authorize(mut self) -> Result<UninstallHandoffReceipt> {
        check_deadline(self.deadline)?;
        if !self.ready_seen || native::exited(&self.process)? {
            return Err(refuse(
                "authorize uninstall handoff",
                "live authenticated helper readiness required",
            ));
        }
        let mut frame = [0; 33];
        frame[0] = b'G';
        frame[1..].copy_from_slice(&self.nonce);
        self.authorize
            .write_all(&frame)
            .map_err(|e| error("authorize private uninstall handoff", e))?;
        Ok(UninstallHandoffReceipt {
            pending_image: self.parent.image.clone(),
            parent: self.parent,
            pending_helper: self.helper.image.clone(),
            helper: self.helper,
            helper_cleanup: self.cleanup,
        })
    }
}
