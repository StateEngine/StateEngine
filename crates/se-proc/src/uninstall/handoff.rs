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
    staged_paths: [PathBuf; 2],
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
            let mut staged = files.create_staging(files.root()).map_err(custody)?;
            pending.push(staged.path.clone());
            io::copy(&mut target, &mut staged.file)
                .map_err(|e| error("stage uninstall helper image", e))?;
            staged
                .file
                .sync_all()
                .map_err(|e| error("flush staged uninstall helper", e))?;
            if native::digest(&mut staged.file)? != digest {
                return Err(refuse(
                    "read back staged uninstall helper",
                    "staged image bytes differ from installed image",
                ));
            }
            let helper_path = staged.path.with_extension("exe");
            drop(staged.file);
            files
                .publish_no_replace(&staged.path, &helper_path)
                .map_err(custody)?;
            pending[0] = helper_path.clone();
            let helper_file = native::open_image(&helper_path, false)?;
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
            let mut frame_file = files.create_staging(files.root()).map_err(custody)?;
            pending.push(frame_file.path.clone());
            let mut nonce = [0; 32];
            // SAFETY: owned fixed buffer and native system-preferred entropy source.
            if unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    nonce.as_mut_ptr(),
                    nonce.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            } < 0
            {
                return Err(refuse(
                    "prepare uninstall handoff",
                    "native entropy source failed",
                ));
            }
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
                frame: native::file_id(&frame_file.file)?,
                digest,
                nonce,
                deadline,
                root: files.root().to_owned(),
                helper_path: helper_path.clone(),
                frame_path: frame_file.path.clone(),
                plan: plan.to_vec(),
            };
            frame_file
                .file
                .write_all(&frame.encode()?)
                .map_err(|e| error("write protected uninstall plan", e))?;
            frame_file
                .file
                .sync_all()
                .map_err(|e| error("flush protected uninstall plan", e))?;
            drop(frame_file.file);
            let plan_read = files
                .readback(&frame_file.path)
                .map_err(custody)?
                .ok_or_else(|| refuse("read back protected uninstall plan", "plan disappeared"))?;
            let stdin = native::duplicate(plan_read.as_raw_handle(), FILE_GENERIC_READ, true)?;
            let mut handles = inherited.each_ref().map(AsRawHandle::as_raw_handle);
            let process = spawn::start(&helper_path, &stdin, &mut handles)?;
            let helper = native::process_identity(&process)?;
            if native::file_id(&native::open_image(&helper.image, false)?)? != helper_id {
                return Err(refuse(
                    "read back uninstall helper identity",
                    "launched image differs from protected helper",
                ));
            }
            Ok(Self {
                parent,
                helper,
                process,
                authorize: authorize_write,
                ready: ready_read,
                nonce,
                deadline,
                ready_seen: false,
                staged_paths: [helper_path, frame_file.path],
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
    pub fn staged_paths(&self) -> [&Path; 2] {
        [&self.staged_paths[0], &self.staged_paths[1]]
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
            helper: self.helper,
        })
    }
}
