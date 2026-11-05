//! Host-driven lifecycle. The runtime port owns native watch/discovery, scoped
//! cache handles and the single cold child; no thread or timer is created here.
use crate::{
    errors::{AtlasResult, capacity},
    lifecycle::*,
    model::*,
    scheduler::{Scheduled, Scheduler},
};
use std::time::{Duration, Instant};
/// Native effects supplied by A08/A09. Each step must respect the supplied
/// deadline, retain unfinished IO as Pending, and commit only verified files.
/// Typed SQL/source quantum expiry remains pending; other errors suspend the root.
pub trait Runtime {
    type Source: AtlasSource;
    /// Retained observations only; no cache open or activation on status reads.
    fn observed_summary(&self, _root: &RootId) -> AtlasResult<Option<IndexSummary>> {
        Ok(None)
    }
    fn step(
        &mut self,
        root: &RootRegistration,
        policy: &AtlasPolicy,
        work: &Scheduled,
        deadline: Instant,
    ) -> AtlasResult<Step>;
    fn publish(
        &mut self,
        root: &RootId,
        serial: u64,
        deadline: Instant,
    ) -> AtlasResult<IndexSummary>;
    fn captured(&mut self, root: &RootId, evidence: EditEvidence) -> AtlasResult<()>;
    fn with_reader<T>(
        &self,
        root: &RootId,
        read: impl FnOnce(
            &crate::cache::connection::CacheConnection<'_>,
            &Self::Source,
        ) -> AtlasResult<T>,
    ) -> AtlasResult<T>;
    fn close(
        &mut self,
        root: &RootId,
        reason: CloseReason,
        deadline: Instant,
    ) -> AtlasResult<CloseResult>;
    fn remove(&mut self, root: &RootId) -> AtlasResult<CacheRemoval>;
    fn forget(&mut self, root: &RootId, events: &[se_types::EventId]) -> AtlasResult<CacheRemoval>;
    fn child_request(&mut self) -> AtlasResult<Option<WorkerRequest>>;
    fn child_event(&mut self, event: WorkerEvent) -> AtlasResult<(RootId, ScheduleReceipt)>;
}
pub struct Step {
    pub report: WorkReport,
    pub summary: IndexSummary,
    pub complete: bool,
}
struct Root {
    registration: RootRegistration,
    policy: AtlasPolicy,
    summary: IndexSummary,
}
pub struct Controller<R> {
    runtime: R,
    roots: Vec<Root>,
    scheduler: Scheduler,
    in_flight: Option<Scheduled>,
}
impl<R: Runtime> Controller<R> {
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            roots: Vec::new(),
            scheduler: Scheduler::default(),
            in_flight: None,
        }
    }
    pub fn runtime(&self) -> &R {
        &self.runtime
    }
    pub fn runtime_mut(&mut self) -> &mut R {
        &mut self.runtime
    }
    /// Keep a live slot while a finite quantum still owns unfinished source IO.
    pub fn work_pending(&self, root: &RootId) -> bool {
        self.in_flight
            .as_ref()
            .is_some_and(|work| &work.root == root)
            || self.scheduler.pending(root)
    }
    /// Lookup only: never registers or activates a root on a query path.
    pub fn registered_root(
        &self,
        project: &se_types::ProjectId,
        selected: Option<&RootId>,
    ) -> AtlasResult<RootId> {
        let mut roots = self.roots.iter().filter(|r| {
            &r.registration.project == project
                && selected.is_none_or(|id| id == &r.registration.root)
        });
        let first = roots.next().ok_or_else(|| {
            se_types::SeError::invalid(
                "Atlas query root",
                "a registered root of the admitted project",
            )
        })?;
        if roots.next().is_some() {
            return Err(se_types::SeError::invalid(
                "Atlas query root",
                "an explicit root when the admitted project has several worktrees",
            ));
        }
        Ok(first.registration.root.clone())
    }
    pub fn summary(&self, id: &RootId) -> AtlasResult<IndexSummary> {
        let root = self.root(id)?;
        let mut summary = self
            .runtime
            .observed_summary(id)?
            .unwrap_or_else(|| root.summary.clone());
        // Writer contention must not hide a published file failure. Other
        // suspensions, such as a corrupt cache pointer, still take precedence.
        let writer_busy = matches!(&root.summary.state, IndexState::Suspended { reason }
            if matches!(reason.detail(), se_types::Detail::AtlasResourceBudget(d)
                if d.resource == "Atlas home writer lease"));
        let retain_failure = matches!(summary.state, IndexState::Partial { .. })
            && (writer_busy
                || matches!(
                    root.summary.state,
                    IndexState::Current
                        | IndexState::Updating { .. }
                        | IndexState::VerificationNeeded { .. }
                ));
        let native_progress = matches!((&summary.state, &root.summary.state),
            (IndexState::ColdIndexing { job: observed, .. }, IndexState::ColdIndexing { job: published, .. }) if observed == published);
        if !retain_failure && !native_progress {
            summary.state = root.summary.state.clone();
        }
        Ok(summary)
    }
    pub fn git_lock(&mut self, root: &RootId, held: bool) -> AtlasResult<()> {
        self.scheduler.git_lock(root, held, Instant::now())
    }
    /// Preserve a named native admission failure for status without turning an
    /// unavailable root into an empty or disabled index.
    pub fn suspend(&mut self, id: &RootId, error: se_types::SeError) -> AtlasResult<()> {
        self.root(id)?;
        self.scheduler.finished(id, 0, false);
        if self.in_flight.as_ref().is_some_and(|work| &work.root == id) {
            self.in_flight = None;
        }
        if let Some(root) = self
            .roots
            .iter_mut()
            .find(|root| &root.registration.root == id)
        {
            root.summary.state = IndexState::Suspended { reason: error.body };
        }
        Ok(())
    }
    fn root(&self, id: &RootId) -> AtlasResult<&Root> {
        self.roots
            .iter()
            .find(|r| &r.registration.root == id)
            .ok_or_else(|| {
                se_types::SeError::invalid("Atlas root", "a registered project/worktree root")
            })
    }
}
impl<R: Runtime> AtlasController for Controller<R> {
    type Source = R::Source;
    fn register(
        &mut self,
        registration: RootRegistration,
        policy: AtlasPolicy,
    ) -> AtlasResult<IndexSummary> {
        crate::policy::validate(&policy)?;
        if !registration.canonical_source_root.is_absolute()
            || !registration.cache.directory.is_absolute()
        {
            return Err(se_types::SeError::invalid(
                "Atlas registration",
                "host-verified absolute roots",
            ));
        }
        if self.roots.iter().any(|r| {
            r.registration.root == registration.root
                && !matches!(r.summary.state, IndexState::Closed)
        }) {
            return Err(se_types::SeError::invalid(
                "Atlas registration",
                "close an existing root before rebinding",
            ));
        }
        self.roots
            .retain(|r| r.registration.root != registration.root);
        // Closed summaries are bounded metadata, never active admission slots.
        // Retain them while space permits; evict only a fully closed record.
        if self.roots.len() >= 2 {
            let closed = self
                .roots
                .iter()
                .position(|r| matches!(r.summary.state, IndexState::Closed))
                .ok_or_else(|| capacity("Atlas live resource slots", 1, 0))?;
            self.roots.remove(closed);
        }
        let summary = IndexSummary {
            memory: None,
            project: registration.project.clone(),
            root: registration.root.clone(),
            epoch: None,
            generation: None,
            state: if policy.enabled {
                IndexState::Dormant
            } else {
                IndexState::Disabled
            },
            coverage: empty_coverage(),
        };
        self.roots.push(Root {
            registration,
            policy,
            summary: summary.clone(),
        });
        Ok(summary)
    }
    fn activate(&mut self, id: RootId, reason: ReconcileReason) -> AtlasResult<ScheduleReceipt> {
        let root = self.root(&id)?;
        if !root.policy.enabled {
            return Ok(ScheduleReceipt::Disabled);
        }
        if matches!(
            root.summary.state,
            IndexState::Closed | IndexState::Draining
        ) {
            return Ok(ScheduleReceipt::Closing);
        }
        self.scheduler.admit(id.clone())?;
        self.enqueue(id, SourceHint::Reconcile(reason))
    }
    fn enqueue(&mut self, id: RootId, hint: SourceHint) -> AtlasResult<ScheduleReceipt> {
        let root = self.root(&id)?;
        if !root.policy.enabled {
            return Ok(ScheduleReceipt::Disabled);
        }
        if matches!(
            root.summary.state,
            IndexState::Draining | IndexState::Closed
        ) {
            return Ok(ScheduleReceipt::Closing);
        }
        let receipt = self.scheduler.enqueue(&id, hint, Instant::now())?;
        if let Some(root) = self.roots.iter_mut().find(|r| r.registration.root == id) {
            root.summary.state = IndexState::Updating {
                pending_files: 1,
                pending_change_batches: 1,
                discovery_complete: false,
            };
        }
        Ok(receipt)
    }
    fn captured_edit(
        &mut self,
        id: RootId,
        evidence: EditEvidence,
    ) -> AtlasResult<ScheduleReceipt> {
        self.root(&id)?;
        if evidence.before.is_none() && evidence.after.is_none() {
            return Err(se_types::SeError::invalid(
                "Atlas edit evidence",
                "before or after contains witnessed bytes",
            ));
        }
        let path = evidence.path.clone();
        let receipt = self.enqueue(id.clone(), SourceHint::FileChanged(path))?;
        if matches!(
            receipt,
            ScheduleReceipt::Disabled | ScheduleReceipt::Closing
        ) {
            return Ok(receipt);
        }
        self.runtime.captured(&id, evidence)?;
        Ok(receipt)
    }
    fn work_quantum(&mut self, allowance: Duration) -> AtlasResult<Option<WorkReport>> {
        if allowance.is_zero() || allowance > Duration::from_millis(200) {
            return Err(se_types::SeError::invalid("Atlas quantum", "1 ns..200 ms"));
        }
        let now = Instant::now();
        let deadline = now + allowance;
        if self.in_flight.is_none() {
            self.in_flight = self.scheduler.take(now)
        }
        if let Some(work) = self.in_flight.take() {
            let root = self
                .roots
                .iter_mut()
                .find(|r| r.registration.root == work.root)
                .ok_or_else(|| {
                    se_types::SeError::invalid("Atlas scheduled root", "a retained registration")
                })?;
            match self
                .runtime
                .step(&root.registration, &root.policy, &work, deadline)
            {
                Ok(step) => {
                    root.summary = step.summary;
                    if step.complete {
                        self.scheduler.finished(&work.root, work.serial, true)
                    } else {
                        self.in_flight = Some(work)
                    }
                    return Ok(Some(step.report));
                }
                Err(error) if quantum_expired(&error) => {
                    // Expiry ends this quantum, not ownership of the unfinished
                    // source work. Keep the error visible and retry on the next
                    // host work turn with a fresh, finite allowance.
                    root.summary.state = IndexState::VerificationNeeded {
                        reason: CoverageReason::TimeLimit,
                    };
                    self.in_flight = Some(work);
                    return Err(error);
                }
                Err(error) => {
                    root.summary.state = IndexState::Suspended {
                        reason: error.body.clone(),
                    };
                    self.scheduler.finished(&work.root, work.serial, false);
                    return Err(error);
                }
            }
        }
        for root in &mut self.roots {
            if self
                .scheduler
                .publication_ready(&root.registration.root, now)
            {
                root.summary = self.runtime.publish(
                    &root.registration.root,
                    self.scheduler.serial(&root.registration.root)?,
                    deadline,
                )?;
                self.scheduler.published(&root.registration.root);
                return Ok(Some(WorkReport {
                    root: root.registration.root.clone(),
                    phase: WorkPhase::Commit,
                    completed_files: 0,
                    remaining_known: 0,
                    generation: root.summary.generation,
                    state: root.summary.state.clone(),
                }));
            }
        }
        Ok(None)
    }
    fn next_work(&self) -> NextWork {
        if self.in_flight.is_some() {
            NextWork::Ready
        } else {
            self.scheduler.next_work(Instant::now())
        }
    }
    fn with_reader<T>(
        &self,
        id: RootId,
        read: impl FnOnce(
            &crate::cache::connection::CacheConnection<'_>,
            &Self::Source,
        ) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        let root = self.root(&id)?;
        if !root.policy.enabled
            || matches!(
                root.summary.state,
                IndexState::Closed | IndexState::Draining
            )
        {
            return Err(se_types::SeError::invalid(
                "Atlas reader",
                "an enabled, open registered root; disabled caches are preserved without lending SQL",
            ));
        }
        self.runtime.with_reader(&id, read)
    }
    fn close(
        &mut self,
        id: RootId,
        reason: CloseReason,
        deadline: Duration,
    ) -> AtlasResult<CloseResult> {
        if matches!(self.root(&id)?.summary.state, IndexState::Closed) {
            return Ok(CloseResult::Closed);
        }
        if let Some(root) = self.roots.iter_mut().find(|r| r.registration.root == id) {
            root.summary.state = IndexState::Draining;
        }
        let result = self.runtime.close(&id, reason, Instant::now() + deadline)?;
        if matches!(result, CloseResult::Closed) {
            self.scheduler.remove(&id);
            if self.in_flight.as_ref().is_some_and(|w| w.root == id) {
                self.in_flight = None
            }
            if let Some(root) = self.roots.iter_mut().find(|r| r.registration.root == id) {
                root.summary.state = IndexState::Closed;
            }
        }
        Ok(result)
    }
    fn remove_cache(&mut self, id: RootId) -> AtlasResult<CacheRemoval> {
        if !matches!(
            self.root(&id)?.summary.state,
            IndexState::Closed | IndexState::Disabled
        ) {
            return Err(se_types::SeError::invalid(
                "Atlas cache removal",
                "close native handles before removal",
            ));
        }
        self.runtime.remove(&id)
    }
    fn forget_evidence(
        &mut self,
        id: RootId,
        events: &[se_types::EventId],
    ) -> AtlasResult<CacheRemoval> {
        self.root(&id)?;
        if events.len() > 256 {
            return Err(capacity(
                "Atlas forgotten evidence batch",
                events.len() as u64,
                256,
            ));
        }
        self.runtime.forget(&id, events)
    }
    fn take_child_request(&mut self) -> AtlasResult<Option<WorkerRequest>> {
        self.runtime.child_request()
    }
    fn child_event(&mut self, event: WorkerEvent) -> AtlasResult<ScheduleReceipt> {
        let failed = match &event {
            WorkerEvent::Exited {
                outcome: WorkerExit::Failed { error },
                ..
            } => Some(IndexState::Suspended {
                reason: error.clone(),
            }),
            WorkerEvent::Exited {
                outcome: WorkerExit::Cancelled | WorkerExit::Lost,
                ..
            } => Some(IndexState::VerificationNeeded {
                reason: CoverageReason::StaleSnapshot,
            }),
            _ => None,
        };
        let (id, receipt) = self.runtime.child_event(event)?;
        self.root(&id)?;
        if let Some(state) = failed {
            self.scheduler.finished(&id, 0, false);
            if self.in_flight.as_ref().is_some_and(|w| w.root == id) {
                self.in_flight = None;
            }
            if let Some(root) = self.roots.iter_mut().find(|r| r.registration.root == id) {
                root.summary.state = state;
            }
            return Ok(receipt);
        }
        if matches!(
            receipt,
            ScheduleReceipt::Queued | ScheduleReceipt::ReconciliationRequired
        ) {
            self.enqueue(id, SourceHint::Reconcile(ReconcileReason::HostRestart))?;
        }
        Ok(receipt)
    }
}
fn empty_coverage() -> Coverage {
    Coverage {
        discovered_files: 0,
        indexed_files: 0,
        partial_files: 0,
        deferred_files: 0,
        failed_files: 0,
        discovery_complete: false,
        stale_files: 0,
        resolved_references: 0,
        name_only_references: 0,
        watched_directories: 0,
        unwatched_directories: 0,
        watch_discovery_complete: false,
        watch_stats_started: None,
        watch_activation_attempts: 0,
        watch_limited_activations: 0,
        history_unavailable: None,
        reasons: Vec::new(),
    }
}

fn quantum_expired(error: &se_types::SeError) -> bool {
    match error.body.detail() {
        se_types::Detail::DeadlineExceeded(detail) => {
            matches!(detail.op.as_str(), "Atlas SQL" | "Atlas source read")
        }
        se_types::Detail::AtlasResourceBudget(detail) => {
            detail.resource == "renewal work deadline" && detail.available == 0
        }
        _ => false,
    }
}
