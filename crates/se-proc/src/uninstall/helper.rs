use super::*;

pub struct NativeUninstallHelper {
    frame: Frame,
    parent: OwnedHandle,
    helper: UninstallProcessIdentity,
    target: File,
    helper_file: File,
    frame_file: File,
    authorize: File,
    ready: File,
    ready_sent: bool,
    authorized: bool,
    helper_unlinked: bool,
    frame_unlinked: bool,
    image_unlinked: bool,
}
impl NativeUninstallHelper {
    /// Call only in the reserved private entry, before CLI parsing. No plan,
    /// owner, path or handle number is accepted from argv or environment.
    pub fn from_process_entry() -> Result<Option<Self>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args
            .get(1)
            .is_none_or(|s| s != "--stateengine-private-uninstall-handoff")
        {
            return Ok(None);
        }
        if args.len() != 2 {
            return Err(refuse(
                "authenticate uninstall helper entry",
                "private entry accepts no arguments",
            ));
        }
        // SAFETY: native startup owns this inherited handle; duplicate before
        // reading, so Rust never claims the process's standard-input reference.
        let raw = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut frame_file = File::from(native::inherited(raw as usize as u64)?);
        protected(&frame_file, Path::new("<inherited uninstall plan>"))?;
        let frame_id = native::file_id(&frame_file)?;
        let mut data = Vec::new();
        Read::by_ref(&mut frame_file)
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| error("read inherited uninstall plan", e))?;
        let frame = Frame::decode(&data)?;
        check_deadline(frame.deadline)?;
        if frame.frame != frame_id || frame.deadline.saturating_sub(clock()) > 300000 {
            return Err(refuse(
                "authenticate uninstall envelope",
                "file identity or deadline mismatch",
            ));
        }
        let files = NativeStateFiles::open(&frame.root).map_err(custody)?;
        let published = files
            .readback(&frame.frame_path)
            .map_err(custody)?
            .ok_or_else(|| refuse("authenticate uninstall plan", "protected plan name absent"))?;
        if native::file_id(&published)? != frame_id {
            return Err(refuse(
                "authenticate uninstall plan",
                "inherited plan differs from protected file",
            ));
        }
        let [parent, target, helper_file, authorize, ready] = frame.handles.map(native::inherited);
        let parent = parent?;
        let mut target = File::from(target?);
        let mut helper_file = File::from(helper_file?);
        if native::process_identity(&parent)? != frame.parent
            || native::actual_parent()? != frame.parent.pid
            || native::exited(&parent)?
        {
            return Err(refuse(
                "authenticate uninstall parent",
                "actual creator does not match live pinned parent",
            ));
        }
        let helper = native::process_identity(&native::current_process()?)?;
        if helper.creation_filetime < frame.parent.creation_filetime
            || native::file_id(&target)? != frame.target
            || native::file_id(&helper_file)? != frame.helper
            || native::file_id(&native::open_image(&frame.parent.image, false)?)? != frame.target
            || native::file_id(&native::open_image(&helper.image, false)?)? != frame.helper
            || native::digest(&mut target)? != frame.digest
            || native::digest(&mut helper_file)? != frame.digest
        {
            return Err(refuse(
                "authenticate uninstall images",
                "exact parent/helper image identity or bytes differ",
            ));
        }
        let protected_helper = files
            .readback(&frame.helper_path)
            .map_err(custody)?
            .ok_or_else(|| refuse("authenticate staged helper", "protected helper name absent"))?;
        if native::file_id(&protected_helper)? != frame.helper {
            return Err(refuse(
                "authenticate staged helper",
                "staged helper object changed",
            ));
        }
        Ok(Some(Self {
            frame,
            parent,
            helper,
            target,
            helper_file,
            frame_file,
            authorize: File::from(authorize?),
            ready: File::from(ready?),
            ready_sent: false,
            authorized: false,
            helper_unlinked: false,
            frame_unlinked: false,
            image_unlinked: false,
        }))
    }
    pub fn staged_paths(&self) -> [&Path; 2] {
        [&self.frame.helper_path, &self.frame.frame_path]
    }
    pub fn core_plan(&self) -> &[u8] {
        &self.frame.plan
    }
    pub fn parent(&self) -> &UninstallProcessIdentity {
        &self.frame.parent
    }
    /// After core validates its plan. Prove temporary artifact names removed
    /// before the original parent is allowed to commit its exit/handoff.
    pub fn announce_ready(&mut self) -> Result<()> {
        check_deadline(self.frame.deadline)?;
        if self.ready_sent {
            return Err(refuse(
                "announce uninstall helper readiness",
                "readiness already sent",
            ));
        }
        if !self.helper_unlinked {
            native::unlink(&self.helper_file, true)?;
            self.helper_unlinked = true;
        }
        native::absent_name(&self.frame.helper_path)?;
        if !self.frame_unlinked {
            native::unlink(&self.frame_file, true)?;
            self.frame_unlinked = true;
        }
        native::absent_name(&self.frame.frame_path)?;
        let mut frame = [0; 33];
        frame[0] = b'R';
        frame[1..].copy_from_slice(&self.frame.nonce);
        self.ready
            .write_all(&frame)
            .map_err(|e| error("announce authenticated uninstall readiness", e))?;
        self.ready_sent = true;
        Ok(())
    }
    /// Bounded poll. EOF before explicit authorization refuses and cannot delete.
    pub fn poll_parent_exit(&mut self) -> Result<bool> {
        check_deadline(self.frame.deadline)?;
        if !self.ready_sent {
            return Err(refuse(
                "observe uninstall parent exit",
                "core validation and helper readiness required",
            ));
        }
        if !self.authorized {
            let Some(frame) = native::poll_frame(&mut self.authorize)? else {
                return Ok(false);
            };
            if frame[0] != b'G' || frame[1..] != self.frame.nonce {
                return Err(refuse(
                    "authenticate uninstall authorization",
                    "private authorization frame mismatch",
                ));
            }
            self.authorized = true;
        }
        native::exited(&self.parent)
    }
    /// Only the exact original native file object can be removed. A real kernel
    /// process-exit signal is required; PID absence or exit code 259 is not used.
    pub fn delete_parent_image(&mut self) -> Result<UninstallImageWitness> {
        if !self.poll_parent_exit()? {
            return Err(refuse(
                "remove installed image",
                "authorized exact parent has not exited",
            ));
        }
        if !self.image_unlinked {
            if native::file_id(&self.target)? != self.frame.target {
                return Err(refuse(
                    "remove installed image",
                    "held image identity changed",
                ));
            }
            native::unlink(&self.target, true)?;
            self.image_unlinked = true;
        }
        native::absent_name(&self.frame.parent.image)?;
        Ok(UninstallImageWitness {
            parent: self.frame.parent.clone(),
            helper: self.helper.clone(),
        })
    }
}
