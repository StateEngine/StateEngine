use super::*;

pub struct NativeUninstallHelper {
    frame: Frame,
    parent: OwnedHandle,
    helper: UninstallProcessIdentity,
    target: File,
    helper_file: File,
    authorize: File,
    ready: File,
    ready_sent: bool,
    authorized: bool,
    cleanup: Option<cleanup::Carrier>,
    cleanup_failure: Option<String>,
    helper_cleanup: UninstallHelperCleanup,
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
        let mut frame_pipe = File::from(native::inherited(raw as usize as u64)?);
        native::require_pipe(&frame_pipe)?;
        let mut data = Vec::new();
        Read::by_ref(&mut frame_pipe)
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| error("read inherited uninstall plan", e))?;
        let frame = Frame::decode(&data)?;
        check_deadline(frame.deadline)?;
        if frame.deadline.saturating_sub(clock()) > 300000 {
            return Err(refuse(
                "authenticate uninstall envelope",
                "deadline out of bounds",
            ));
        }
        if let Some(directory) = &frame.directory {
            let _directory_pin = staging::verify_directory(directory)?;
            if directory.path != frame.root {
                return Err(refuse(
                    "authenticate elevated staging",
                    "directory custody differs from held root",
                ));
            }
        } else if frame.root != frame.cleanup_root {
            return Err(refuse(
                "authenticate staging root",
                "unexpected alternate staging root",
            ));
        }
        let files = NativeStateFiles::open(&frame.root).map_err(custody)?;
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
        if frame.directory.is_some() {
            staging::verify_high(&helper_file, false)?;
        }
        let helper_cleanup = UninstallHelperCleanup::new(
            frame.cleanup_root.clone(),
            frame.helper_path.clone(),
            &helper,
            frame.helper,
            frame.digest,
            frame.directory.clone(),
        );
        Ok(Some(Self {
            frame,
            parent,
            helper,
            target,
            helper_file,
            authorize: File::from(authorize?),
            ready: File::from(ready?),
            ready_sent: false,
            authorized: false,
            cleanup: None,
            cleanup_failure: None,
            helper_cleanup,
            image_unlinked: false,
        }))
    }
    pub fn staged_paths(&self) -> [&Path; 1] {
        [&self.frame.helper_path]
    }
    /// A failed carrier does not prevent uninstall. Core must display this
    /// exact path and retain it for the next install/uninstall cleanup attempt.
    pub fn pending_helper(&self) -> Option<(&Path, &str)> {
        self.cleanup_failure
            .as_deref()
            .map(|why| (self.frame.helper_path.as_path(), why))
    }
    pub fn staging_directory(&self) -> Option<&Path> {
        self.frame.directory.as_ref().map(|d| d.path.as_path())
    }
    /// Persist this exact custody under the install claim before announce_ready
    /// and authorization; an image-removal witness is deliberately not required.
    pub fn helper_cleanup(&self) -> &UninstallHelperCleanup {
        &self.helper_cleanup
    }
    pub fn core_plan(&self) -> &[u8] {
        &self.frame.plan
    }
    pub fn parent(&self) -> &UninstallProcessIdentity {
        &self.frame.parent
    }
    /// After core validates its plan, announce readiness. The running helper remains pinned for kernel cleanup at exit;
    /// readiness never claims that its own image has already been removed.
    pub fn announce_ready(&mut self) -> Result<()> {
        check_deadline(self.frame.deadline)?;
        if self.ready_sent {
            return Err(refuse(
                "announce uninstall helper readiness",
                "readiness already sent",
            ));
        }
        if native::file_id(&self.helper_file)? != self.frame.helper {
            return Err(refuse(
                "verify staged helper before readiness",
                "held helper object changed",
            ));
        }
        if self.cleanup.is_none() && self.cleanup_failure.is_none() {
            match cleanup::Carrier::start(
                &self.helper_file,
                self.frame.deadline,
                &self.frame.root,
                self.frame.directory.as_ref(),
            )
            .and_then(|mut carrier| {
                carrier.ensure_ready()?;
                Ok(carrier)
            }) {
                Ok(carrier) => self.cleanup = Some(carrier),
                // CLM/AppLocker/WDAC can forbid the system carrier. Image
                // removal still proceeds; the exact helper remains explicit
                // cleanup debt until an external observer sees it absent.
                Err(cause) => {
                    self.cleanup_failure = Some(if self.frame.directory.is_some() {
                        format!(
                            "{cause}; High staging cleanup requires elevated se install or se uninstall"
                        )
                    } else {
                        cause.to_string()
                    })
                }
            }
        }
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
            cleanup: self.helper_cleanup.clone(),
            pending_helper: self
                .pending_helper()
                .map(|(path, why)| (path.to_owned(), why.to_owned())),
        })
    }
}
