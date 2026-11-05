use super::*;
impl State {
    pub(super) fn work(
        &mut self,
        context: &ExecutionContext,
        owner: &HumanId,
        wake: Wake,
    ) -> Result<Plan> {
        let mut again = false;
        match wake {
            Wake::Core => {
                self.scan = Some(roots::Scan::default());
                for root in &mut self.roots {
                    root.feed_pending = true;
                    root.feed_stalled = false;
                }
            }
            Wake::Source(root) => {
                if let Err(error) = drive_events(
                    &mut self.controller,
                    &root,
                    Instant::now() + Duration::from_millis(100),
                ) {
                    eprintln!("Code index source reconciliation required: {error}");
                }
            }
            Wake::Child | Wake::Scheduled => (),
        }
        if let Some(scan) = &mut self.scan {
            match scan.page(context, owner, &self.home) {
                Ok(false) => again = true,
                Ok(true) => {
                    let selected = self
                        .scan
                        .take()
                        .ok_or_else(|| SeError::invalid("Atlas catalogue", "a completed scan"))?
                        .finish();
                    self.rebind(selected)?;
                }
                Err(error) => {
                    self.scan = None;
                    eprintln!("Code index project registration paused: {error}");
                }
            }
        }
        // The same controller supplies both event and quantum paths; checkout
        // locks discovered by the driver reach the scheduler before publication.
        if self.controller.runtime().child_pid().is_none()
            && let Err(error) = drive_quantum(&mut self.controller, Duration::from_millis(100))
        {
            eprintln!("Code index source work paused: {error}");
        }
        let before = self.controller.runtime().child_pid();
        if let Err(error) = crate::atlas_runtime::drive_child(&mut self.controller) {
            eprintln!("Code index child work paused: {error}");
        }
        let child = self.controller.runtime().child_pid();
        if before.is_some() && child.is_none() {
            for root in &mut self.roots {
                root.feed_pending = true;
                root.feed_stalled = false;
            }
        }
        if child.is_none() {
            for root in &mut self.roots {
                if root.feed_pending
                    && !root.feed_stalled
                    && self.enabled
                    && self
                        .controller
                        .summary(&root.registration.root)?
                        .epoch
                        .is_some()
                {
                    match records::chunk(context, owner, &self.controller, &root.registration.root)
                    {
                        Ok(true) => root.feed_pending = false,
                        Ok(false) => {
                            again |= context.atlas.records.ticket()?.is_some();
                        }
                        Err(error) => {
                            root.feed_stalled = true;
                            eprintln!("Code index record feed paused: {error}");
                        }
                    }
                }
            }
        }
        let (ready, mut delay) = match if child.is_some() {
            NextWork::Park
        } else {
            self.controller.next_work()
        } {
            NextWork::Ready => (true, None),
            NextWork::AfterEventDebounce(wait) => (false, Some(wait)),
            NextWork::Park => (false, None),
        };
        let mut fds = Vec::with_capacity(3);
        if let Some(pid) = child {
            let end = match self.child_deadline {
                Some((old, end)) if old == pid => end,
                _ => {
                    let end = Instant::now() + Duration::from_secs(900);
                    self.child_deadline = Some((pid, end));
                    end
                }
            };
            let wait = end.saturating_duration_since(Instant::now());
            delay = Some(delay.map_or(wait, |old| old.min(wait)));
            if let Some(fd) = self.controller.runtime().child_readiness_fd() {
                fds.push((fd.try_clone_to_owned().map_err(fd_error)?, Wake::Child));
            }
        } else {
            self.child_deadline = None;
            for root in &self.roots {
                if let Some(fd) = self.controller.runtime().event_fd(&root.registration.root) {
                    fds.push((
                        fd.try_clone_to_owned().map_err(fd_error)?,
                        Wake::Source(root.registration.root.clone()),
                    ));
                }
            }
        }
        Ok(Plan {
            ready: again || ready,
            delay,
            fds,
        })
    }
    fn rebind(&mut self, selected: Vec<RootRegistration>) -> Result<()> {
        let old: Vec<_> = self
            .roots
            .iter()
            .filter(|old| {
                !selected.iter().any(|new| {
                    new.root == old.registration.root
                        && new.canonical_source_root == old.registration.canonical_source_root
                })
            })
            .map(|old| old.registration.root.clone())
            .collect();
        for id in old {
            if !matches!(
                self.controller.close(
                    id.clone(),
                    CloseReason::ProjectRemoved,
                    Duration::from_millis(200)
                )?,
                CloseResult::Closed
            ) {
                return Err(SeError::invalid(
                    "Atlas root replacement",
                    "complete close before reusing an active registration slot",
                ));
            }
            self.roots.retain(|old| old.registration.root != id);
        }
        for mut registration in selected {
            if self
                .roots
                .iter()
                .any(|old| old.registration.root == registration.root)
            {
                continue;
            }
            // Native Git lookup happens after readiness. Its failure suspends
            // only this registration; another admitted root may still proceed.
            let metadata = if self.enabled {
                roots::git(&registration.canonical_source_root)
            } else {
                Ok(None)
            };
            if let Ok(value) = &metadata {
                registration.git_metadata = value.clone();
            }
            let policy = roots::policy(self.enabled);
            self.controller
                .register(registration.clone(), policy.clone())?;
            if let Err(error) = metadata {
                self.controller.suspend(&registration.root, error)?;
                self.roots.push(Root {
                    registration,
                    feed_pending: true,
                    feed_stalled: true,
                });
                continue;
            }
            if let Err(error) = self.controller.runtime_mut().prepare_registered(
                &registration,
                &policy,
                Instant::now() + Duration::from_secs(5),
            ) {
                self.controller.suspend(&registration.root, error)?;
                self.roots.push(Root {
                    registration,
                    feed_pending: true,
                    feed_stalled: true,
                });
                continue;
            }
            if self.enabled {
                self.controller
                    .activate(registration.root.clone(), ReconcileReason::HostRestart)?;
            }
            self.roots.push(Root {
                registration,
                feed_pending: true,
                feed_stalled: false,
            });
        }
        Ok(())
    }
}
fn fd_error(error: std::io::Error) -> SeError {
    se_core::scope::unreadable("Atlas native readiness descriptor", &error.to_string())
        .with_cause(error)
}
