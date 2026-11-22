use super::*;
impl State {
    pub(super) fn work(
        &mut self,
        context: &dyn AtlasHost,
        owner: &HumanId,
        wake: Wake,
    ) -> Result<Plan> {
        if matches!(wake, Wake::Core) {
            self.refeed();
        }
        // A native parse deadline takes priority over registry scans and SQL
        // work. The child cannot read source until this owner arms that clock.
        if self.controller.runtime().child_parse_deadline().is_some() {
            if let Err(error) = crate::atlas_runtime::drive_child(&mut self.controller) {
                eprintln!("Code index child cancellation pending: {error}");
            }
            if self.controller.runtime().child_pid().is_none() {
                self.refeed();
            }
            if let Some(plan) = self.parse_plan()? {
                return Ok(plan);
            }
        }
        self.absorb_activity(context, owner)?;
        for id in self.due_sources(wake) {
            self.drive_source(&id)?;
        }
        let mut again = self.scan_page(context, owner);
        again |= self.advance_project(context, owner)?;
        self.drive_work()?;
        let before = self.controller.runtime().child_pid();
        if let Err(error) = crate::atlas_runtime::drive_child(&mut self.controller) {
            eprintln!("Code index child work paused: {error}");
        }
        if let Some(plan) = self.parse_plan()? {
            return Ok(plan);
        }
        let child = self.controller.runtime().child_pid();
        if before.is_some() && child.is_none() {
            self.adopt_exit()?;
        }
        if child.is_none() {
            again |= self.feed_records(context, owner)?;
        }
        self.next_plan(child, again)
    }
    fn refeed(&mut self) {
        for root in &mut self.roots {
            root.feed_pending = true;
            root.feed_stalled = false;
        }
    }
    fn absorb_activity(&mut self, context: &dyn AtlasHost, owner: &HumanId) -> Result<()> {
        if let Some(activity) = context.records().take_activity()? {
            if self.enabled {
                // Revalidate only the bounded live pool on committed activity.
                // Root removal/replacement can cancel its own native custody;
                // an unrelated project's query never cancels a cold worker.
                let mut verify = Vec::new();
                for root in &self.roots {
                    let project = &root.registration.project;
                    if (activity.registry_changed || activity.projects.contains(project))
                        && !verify.contains(project)
                    {
                        verify.push(project.clone());
                    }
                }
                for project in verify {
                    let registrations = self.registrations(context, owner, &project)?;
                    self.close_obsolete(&project, &registrations)?;
                    self.work.register(&project, registrations)?;
                }
                for project in activity.projects {
                    self.work.request(&project)?;
                }
                self.reconcile_all |= activity.overflow;
            }
            self.registry_dirty |= activity.registry_changed;
        }
        if self.scan.is_none() && (self.registry_dirty || self.reconcile_all) {
            self.scan = Some(roots::Scan::new(self.reconcile_all));
            self.registry_dirty = false;
            self.reconcile_all = false;
        }
        Ok(())
    }
    fn due_sources(&self, wake: Wake) -> Vec<RootId> {
        let now = Instant::now();
        let mut sources: Vec<RootId> = self
            .roots
            .iter()
            .filter(|root| root.event_retry.is_some_and(|(at, _, _)| at <= now))
            .map(|root| root.registration.root.clone())
            .collect();
        match wake {
            #[cfg(target_os = "linux")]
            Wake::Source(root)
                if self
                    .roots
                    .iter()
                    .find(|item| item.registration.root == root)
                    .is_some_and(|item| item.event_retry.is_none_or(|(at, _, _)| at <= now))
                    && !sources.contains(&root) =>
            {
                sources.push(root);
            }
            #[cfg(windows)]
            Wake::Sources => {
                for root in &self.roots {
                    if root.event_retry.is_none_or(|(at, _, _)| at <= now)
                        && !sources.contains(&root.registration.root)
                    {
                        sources.push(root.registration.root.clone());
                    }
                }
            }
            _ => (),
        }
        sources
    }
    fn drive_source(&mut self, id: &RootId) -> Result<()> {
        let previous = self
            .roots
            .iter()
            .find(|root| root.registration.root == *id)
            .and_then(|root| root.event_retry);
        let result = drive_events(
            &mut self.controller,
            id,
            Instant::now() + Duration::from_millis(100),
        );
        let pending = self.controller.watch_pending(id);
        let drain =
            result.is_ok() && !pending && previous.is_some_and(|(_, _, draining)| !draining);
        if drain {
            self.controller.set_watch_pending(id, true)?;
        }
        if let Some(root) = self
            .roots
            .iter_mut()
            .find(|root| root.registration.root == *id)
        {
            root.event_retry = match result {
                Ok(_) if pending || drain => Some((
                    Instant::now() + Duration::from_millis(1),
                    Duration::from_millis(1),
                    drain,
                )),
                Ok(_) => None,
                Err(error) if pending => {
                    eprintln!("Code index source event delayed: {error}");
                    let delay = previous.map_or(Duration::from_millis(50), |(_, delay, _)| {
                        (delay * 2).clamp(Duration::from_millis(50), Duration::from_secs(1))
                    });
                    Some((Instant::now() + delay, delay, false))
                }
                Err(error) => {
                    eprintln!("Code index source reconciliation required: {error}");
                    None
                }
            };
        }
        Ok(())
    }
    fn scan_page(&mut self, context: &dyn AtlasHost, owner: &HumanId) -> bool {
        let Some(scan) = &mut self.scan else {
            return false;
        };
        match scan.page(context, owner, &self.home, &self.work) {
            Ok(false) => true,
            Ok(true) => {
                self.scan = None;
                true
            }
            Err(error) => {
                self.scan = None;
                eprintln!("Code index project registration paused: {error}");
                false
            }
        }
    }
    fn drive_work(&mut self) -> Result<()> {
        // The same controller supplies both event and quantum paths; checkout
        // locks discovered by the driver reach the scheduler before publication.
        if self.controller.runtime().child_pid().is_some() || self.retry_wait().is_some() {
            return Ok(());
        }
        self.work_retry_after = None;
        match drive_quantum(&mut self.controller, MAX_WORK_QUANTUM) {
            Ok(Some(report))
                if self
                    .controller
                    .summary(&report.root)?
                    .coverage
                    .reasons
                    .contains(&CoverageReason::SchedulingStall) =>
            {
                self.work_retry_after = Some(Instant::now() + Duration::from_secs(1));
            }
            Ok(_) => (),
            Err(error) => eprintln!("Code index source work paused: {error}"),
        }
        Ok(())
    }
    fn retry_wait(&self) -> Option<Duration> {
        self.work_retry_after
            .and_then(|end| end.checked_duration_since(Instant::now()))
    }
    fn adopt_exit(&mut self) -> Result<()> {
        for root in &mut self.roots {
            root.feed_pending = true;
            root.feed_stalled = false;
            if self
                .controller
                .summary(&root.registration.root)?
                .coverage
                .reasons
                .contains(&CoverageReason::SchedulingStall)
            {
                self.work_retry_after = Some(Instant::now() + Duration::from_secs(1));
            }
        }
        Ok(())
    }
    fn feed_records(&mut self, context: &dyn AtlasHost, owner: &HumanId) -> Result<bool> {
        let mut again = false;
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
                match records::chunk(context, owner, &self.controller, &root.registration.root) {
                    Ok(true) => root.feed_pending = false,
                    Ok(false) => again |= context.records().ticket()?.is_some(),
                    Err(error) => {
                        root.feed_stalled = true;
                        eprintln!("Code index record feed paused: {error}");
                    }
                }
            }
        }
        Ok(again)
    }
    fn next_plan(&mut self, child: Option<u32>, again: bool) -> Result<Plan> {
        let (ready, mut delay) = match if child.is_some() {
            NextWork::Park
        } else {
            self.controller.next_work()
        } {
            NextWork::Ready => match self.retry_wait() {
                Some(wait) => (false, Some(wait)),
                None => (true, None),
            },
            NextWork::AfterEventDebounce(wait) => (false, Some(wait)),
            NextWork::Park => (false, None),
        };
        for root in &self.roots {
            if let Some((at, _, _)) = root.event_retry {
                let wait = at.saturating_duration_since(Instant::now());
                delay = Some(delay.map_or(wait, |old| old.min(wait)));
            }
        }
        #[cfg(target_os = "linux")]
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
            let end = self
                .controller
                .runtime()
                .child_deadline()
                .map_or(end, |phase| end.min(phase));
            let wait = end.saturating_duration_since(Instant::now());
            delay = Some(delay.map_or(wait, |old| old.min(wait)));
            #[cfg(target_os = "linux")]
            if let Some(fd) = self.controller.runtime().child_readiness_fd() {
                fds.push((fd.try_clone_to_owned().map_err(fd_error)?, Wake::Child));
            }
            #[cfg(windows)]
            {
                delay = Some(delay.map_or(Duration::from_millis(20), |old| {
                    old.min(Duration::from_millis(20))
                }));
            }
        } else {
            self.child_deadline = None;
            #[cfg(target_os = "linux")]
            for root in &self.roots {
                if root.event_retry.is_none()
                    && let Some(fd) = self.controller.runtime().event_fd(&root.registration.root)
                {
                    fds.push((
                        fd.try_clone_to_owned().map_err(fd_error)?,
                        Wake::Source(root.registration.root.clone()),
                    ));
                }
            }
        }
        // Finishing a queued project/root advances the disk FIFO without a
        // timer. A cold worker keeps its live slot until exact exit and adoption.
        let advance = self.finish_root()?;
        Ok(Plan {
            ready: again || ready || advance,
            delay,
            #[cfg(windows)]
            listen_sources: child.is_none(),
            #[cfg(target_os = "linux")]
            fds,
        })
    }
    fn parse_plan(&self) -> Result<Option<Plan>> {
        let Some(end) = self.controller.runtime().child_parse_deadline() else {
            return Ok(None);
        };
        #[cfg(target_os = "linux")]
        let mut fds = Vec::with_capacity(1);
        #[cfg(target_os = "linux")]
        if let Some(fd) = self.controller.runtime().child_readiness_fd() {
            fds.push((fd.try_clone_to_owned().map_err(fd_error)?, Wake::Child));
        }
        Ok(Some(Plan {
            ready: false,
            #[cfg(windows)]
            listen_sources: false,
            // After a failed bounded reap, retain custody and wait for native
            // exit readiness rather than spinning on an already expired timer.
            delay: {
                let remaining = end.checked_duration_since(Instant::now());
                #[cfg(windows)]
                let remaining = Some(remaining.map_or(Duration::from_millis(20), |value| {
                    value.min(Duration::from_millis(20))
                }));
                remaining
            },
            #[cfg(target_os = "linux")]
            fds,
        }))
    }
    fn advance_project(&mut self, context: &dyn AtlasHost, owner: &HumanId) -> Result<bool> {
        if self.active_project.is_none() {
            if self.queue_scan.is_none() {
                self.queue_scan = self.work.scan()?;
            }
            if let Some(scan) = &mut self.queue_scan {
                match scan.page()? {
                    None => return Ok(true),
                    Some(ticket) => {
                        self.queue_scan = None;
                        self.active_project = ticket.map(|ticket| ActiveProject {
                            ticket,
                            after: None,
                            root: None,
                        });
                    }
                }
            }
        }
        let Some(active) = &self.active_project else {
            return Ok(false);
        };
        if active.root.is_some() {
            return Ok(false);
        }
        let project = active.ticket.project.clone();
        let after = active.after.clone();
        let registrations = self.registrations(context, owner, &project)?;
        self.close_obsolete(&project, &registrations)?;
        self.work.register(&project, registrations.clone())?;
        let next = registrations
            .into_iter()
            .filter(|root| {
                after
                    .as_ref()
                    .is_none_or(|after| root.root.as_str() > after.as_str())
            })
            .min_by(|a, b| a.root.as_str().cmp(b.root.as_str()));
        if let Some(next) = next {
            let id = next.root.clone();
            if self.roots.iter().any(|root| root.registration.root == id)
                && matches!(
                    self.controller.summary(&id)?.state,
                    IndexState::Suspended { .. } | IndexState::Unreadable { .. }
                )
                && !writer_busy(&self.controller.summary(&id)?.state)
            {
                self.close_root(id.clone())?;
            }
            // Vec order is recent use. Recycle only the oldest live resource,
            // never the active cold job, and retain its disk index and summary.
            let mut selected: Vec<_> = self
                .roots
                .iter()
                .filter(|root| root.registration.root != id)
                .map(|root| root.registration.clone())
                .collect();
            let interests = context.records().interests()?;
            selected.sort_by_key(|root| {
                interests
                    .iter()
                    .position(|project| project == &root.project)
            });
            if selected.len() >= 2 {
                selected.remove(0);
            }
            selected.push(next);
            self.rebind(selected)?;
            let state = self.controller.summary(&id)?.state;
            if writer_busy(&state)
                || !matches!(
                    state,
                    IndexState::Suspended { .. } | IndexState::Unreadable { .. }
                )
            {
                self.controller
                    .activate(id.clone(), ReconcileReason::HostRestart)?;
                if let Some(root) = self
                    .roots
                    .iter_mut()
                    .find(|root| root.registration.root == id)
                {
                    root.feed_pending = true;
                    root.feed_stalled = false;
                }
            }
            if let Some(active) = &mut self.active_project {
                active.root = Some(id);
            }
            Ok(true)
        } else {
            let active = self
                .active_project
                .take()
                .ok_or_else(|| SeError::invalid("Atlas queue", "the selected project"))?;
            self.work.complete(&active.ticket)?;
            Ok(true)
        }
    }
    fn registrations(
        &self,
        context: &dyn AtlasHost,
        owner: &HumanId,
        project: &ProjectId,
    ) -> Result<Vec<RootRegistration>> {
        let admitted = admission(context, owner, Scope::Project(project.clone()));
        let phase = context.checked_read_phase()?;
        let mut snapshot = phase
            .into_snapshot(se_core::admission::read_scope(&admitted))
            .map_err(|error| store_error(&error))?;
        let read = snapshot
            .project(project.clone())
            .map_err(|error| store_error(&error));
        let read = close_read(read, snapshot.close())?;
        let registrations = match read {
            se_types::Read::Present { value } => match value.current.body {
                se_store::EventBody::ProjectRegistered { project, roots, .. }
                | se_store::EventBody::ProjectUpdated { project, roots, .. } => {
                    roots::registrations(&project, &roots, &self.home)?
                }
                se_store::EventBody::ProjectRemoved { .. } => Vec::new(),
                _ => {
                    return Err(SeError::invalid(
                        "Atlas project registration",
                        "a registered or removed project head",
                    ));
                }
            },
            se_types::Read::Absent { .. } => Vec::new(),
            se_types::Read::Unreadable { reason, .. }
            | se_types::Read::Unknown { what: reason } => {
                return Err(se_core::scope::unreadable("queued Atlas project", &reason));
            }
        };
        Ok(registrations)
    }
    fn close_obsolete(
        &mut self,
        project: &ProjectId,
        registrations: &[RootRegistration],
    ) -> Result<()> {
        let obsolete: Vec<_> = self
            .roots
            .iter()
            .filter(|root| {
                &root.registration.project == project
                    && !registrations.iter().any(|new| {
                        new.root == root.registration.root
                            && new.canonical_source_root == root.registration.canonical_source_root
                    })
            })
            .map(|root| root.registration.root.clone())
            .collect();
        for root in obsolete {
            self.close_root(root)?;
        }
        Ok(())
    }
    fn close_root(&mut self, id: RootId) -> Result<()> {
        let publication = self
            .roots
            .iter()
            .find(|root| root.registration.root == id)
            .map(|root| {
                self.controller
                    .summary(&id)
                    .map(|summary| (root.registration.clone(), summary))
            })
            .transpose()?;
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
                "complete native close before recycling its live resource slot",
            ));
        }
        if let Some((registration, summary)) = publication {
            self.work.publish(&registration, summary)?;
        }
        self.roots.retain(|root| root.registration.root != id);
        if let Some(active) = &mut self.active_project
            && active.root.as_ref() == Some(&id)
        {
            active.root = None;
            active.after = None;
        }
        Ok(())
    }
    fn finish_root(&mut self) -> Result<bool> {
        let Some(active) = &self.active_project else {
            return Ok(false);
        };
        let Some(id) = &active.root else {
            return Ok(false);
        };
        if self.controller.runtime().child_pid().is_some() {
            return Ok(false);
        }
        if self.controller.work_pending(id) {
            return Ok(false);
        }
        let summary = self.controller.summary(id)?;
        let unfinished = match summary.state {
            IndexState::Dormant | IndexState::Opening | IndexState::ColdIndexing { .. } => true,
            IndexState::Updating {
                pending_files,
                discovery_complete,
                ..
            } => pending_files != 0 || !discovery_complete,
            _ => false,
        };
        if unfinished {
            return Ok(false);
        }
        // A settled source pass need not hold the project FIFO behind the
        // ten-second change-batch publication clock. The scheduler retains
        // that publication while hot; eviction flushes it during native close.
        // Reads still expose Updating until actual publication, never Current.
        if self.enabled
            && summary.epoch.is_some()
            && self.roots.iter().any(|root| {
                &root.registration.root == id && root.feed_pending && !root.feed_stalled
            })
        {
            return Ok(false);
        }
        if let Some(active) = &mut self.active_project {
            active.after = active.root.take();
        }
        Ok(true)
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
            self.close_root(id)?;
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
            let prepared = metadata.and_then(|_| {
                self.controller.runtime_mut().prepare_registered(
                    &registration,
                    &policy,
                    // Activation checks the whole retained graph in owned
                    // background work, just as post-reap cold adoption does.
                    Instant::now() + Duration::from_secs(900),
                )
            });
            let feed_stalled = if let Err(error) = prepared {
                self.controller.suspend(&registration.root, error)?;
                true
            } else {
                if self.enabled {
                    self.controller
                        .activate(registration.root.clone(), ReconcileReason::HostRestart)?;
                }
                false
            };
            self.roots.push(Root {
                registration,
                feed_pending: true,
                feed_stalled,
                event_retry: None,
            });
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn fd_error(error: std::io::Error) -> SeError {
    se_core::scope::unreadable("Atlas native readiness descriptor", &error.to_string())
        .with_cause(error)
}

fn writer_busy(state: &IndexState) -> bool {
    matches!(state, IndexState::Suspended { reason }
        if matches!(reason.detail(), se_types::Detail::AtlasResourceBudget(detail) if detail.resource == "Atlas home writer lease"))
}
