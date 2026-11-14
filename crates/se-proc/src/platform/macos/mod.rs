pub(crate) mod attach;
mod group;
mod spawn;
mod watch;
use crate::{
    platform::{Progress, empty},
    runtime::notify::Hub,
    support::*,
    *,
};
use std::{io, path::PathBuf, sync::Arc};

pub(crate) struct Driver {
    reactor: Arc<dyn NativeReactor>,
    helper: PathBuf,
}
pub(crate) struct Scope {
    image_custody: Option<NativeExecutableInvocation>,
    child: Option<spawn::Child>,
    recovered: Option<ProcessIdentity>,
    tracked: Vec<ProcessIdentity>,
    group: Option<ProcessId>,
    registrations: Vec<Box<dyn NativeRegistration>>,
    watch: watch::Watch,
    pub scope: ScopeIdentity,
    pub guarantee: ContainmentGuarantee,
    pub entry: EntryMethod,
    max_members: usize,
    max_bytes: u64,
    escaped: bool,
    exec_seen: bool,
    executable: PathBuf,
}
fn guarantee() -> ContainmentGuarantee {
    ContainmentGuarantee::TrackedTree {
        atomic_signal: false,
        escape_prevented: false,
    }
}
impl Driver {
    pub fn new(config: &HostConfig) -> ProcResult<Self> {
        if !config.helper_executable.is_absolute() {
            return Err(input("attach helper", "installed absolute image required"));
        }
        Ok(Self {
            reactor: config.reactor.clone(),
            helper: config.helper_executable.clone(),
        })
    }
    pub fn capabilities(&self) -> PlatformCapabilities {
        let unavailable = || Capability::Unavailable {
            error: Box::new(unsupported(
                "Darwin supports headless tracked groups; strict kernel containment and terminal windows are not implemented",
            )),
        };
        PlatformCapabilities {
            headless: Capability::Supported,
            window: unavailable(),
            kernel_scope: unavailable(),
            tracked_tree: Capability::Supported,
            kernel_exit_notification: Capability::Supported,
            safe_forced_stop: Capability::Supported,
        }
    }
    pub fn prepare(
        &self,
        reservation: &LaunchReservation,
        spec: &LaunchSpec,
        limits: ResourceLimits,
        _hub: &Arc<Hub>,
    ) -> ProcResult<Scope> {
        if spec.mode != LaunchMode::Headless
            || spec.policy.containment == ContainmentRequirement::KernelScope
        {
            return Err(unsupported(
                "Darwin currently supports only headless tracked-tree creation; strict kernel scope and windows remain unavailable",
            ));
        }
        if reservation.parent != ReservationParent::MacOs {
            return Err(input(
                "reservation.parent",
                "native MacOs reservation required",
            ));
        }
        Ok(Scope {
            image_custody: None,
            child: None,
            recovered: None,
            tracked: Vec::new(),
            group: None,
            registrations: Vec::new(),
            watch: watch::Watch::new(limits.max_diagnostic_members as usize)?,
            scope: ScopeIdentity::MacOsPrepared {
                nonce: reservation.scope_nonce,
            },
            guarantee: guarantee(),
            entry: EntryMethod::MacOsSpawn,
            max_members: limits.max_diagnostic_members as usize,
            max_bytes: limits.max_observation_bytes,
            escaped: false,
            exec_seen: false,
            executable: spec.executable.clone(),
        })
    }
    pub fn begin(&self, scope: &mut Scope, mut spec: LaunchSpec, hub: &Arc<Hub>) -> ProcResult<()> {
        scope.image_custody = spec.executable_custody.take();
        scope.child = Some(spawn::begin(spec, &self.helper)?);
        let child = scope
            .child
            .as_mut()
            .ok_or_else(|| input("child", "native custody missing"))?;
        // Publish native custody before frame delivery, identity or registration.
        child.arm()?;
        scope.registrations.push(
            self.reactor.register(
                child
                    .events
                    .try_clone()
                    .map_err(|e| native(ProcErrorCode::LaunchFailed, "clone attach results", e))?,
                NativeInterest::Readable,
                hub.clone(),
            )?,
        );
        scope.registrations.push(
            self.reactor.register(
                scope
                    .watch
                    .file
                    .try_clone()
                    .map_err(|e| native(ProcErrorCode::LaunchFailed, "clone process queue", e))?,
                NativeInterest::Readable,
                hub.clone(),
            )?,
        );
        Ok(())
    }
    fn recorded(&self, record: &ProcessRecord, limits: ResourceLimits) -> ProcResult<Scope> {
        let ScopeIdentity::MacOsTracked {
            process_group,
            root,
        } = &record.scope
        else {
            return Err(input(
                "cold recovery",
                "protected Darwin tracked record required",
            ));
        };
        let boot = crate::owner_probe::macos::boot()
            .map_err(|e| native(ProcErrorCode::IdentityUnreadable, e.operation, e.source))?;
        if root != &record.root
            || root.machine != record.owner.machine
            || root.boot != boot
            || process_group.0 == 0
            || process_group.0 > i32::MAX as u32
        {
            return Err(changed(&record.root, None));
        }
        if record.guarantee != guarantee() {
            return Err(input(
                "cold guarantee",
                "record does not carry the implemented Darwin tracked-tree bound",
            ));
        }
        let history = record.tracked_obligations.as_ref().ok_or_else(|| {
            error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Input {
                field: "cold tracking history".into(),
                reason: "record has no retained original members or escape history; retain custody as unproved".into(),
            })
        })?;
        if history.members.len() > limits.max_diagnostic_members as usize {
            return Err(capacity(
                "retained tracked identities",
                limits.max_diagnostic_members as u64,
            ));
        }
        Ok(Scope {
            image_custody: None,
            child: None,
            recovered: Some(root.clone()),
            tracked: history.members.clone(),
            group: Some(*process_group),
            registrations: Vec::new(),
            watch: watch::Watch::new(limits.max_diagnostic_members as usize)?,
            scope: record.scope.clone(),
            guarantee: record.guarantee,
            entry: record.entry,
            max_members: limits.max_diagnostic_members as usize,
            max_bytes: limits.max_observation_bytes,
            escaped: history.escaped,
            exec_seen: false,
            executable: root.image.clone(),
        })
    }
    pub fn recover(
        &self,
        record: &ProcessRecord,
        limits: ResourceLimits,
        hub: &Arc<Hub>,
    ) -> ProcResult<Scope> {
        let mut scope = self.recorded(record, limits)?;
        let root = &record.root;
        if !matches!(scope.root()?, Some(ProcessObservation::Live(_)))
            || !group::in_group(
                root,
                scope
                    .group
                    .ok_or_else(|| input("cold group", "native group absent"))?,
            )?
        {
            return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Input {
                field: "cold recovery".into(), reason: "live original root and recorded group continuity are required; no replacement PID is adopted".into() }));
        }
        scope.watch.track(root)?;
        scope.registrations.push(self.reactor.register(
            scope.watch.file.try_clone().map_err(|e| {
                native(
                    ProcErrorCode::IdentityUnreadable,
                    "clone recovered process queue",
                    e,
                )
            })?,
            NativeInterest::Readable,
            hub.clone(),
        )?);
        scope.observe()?;
        Ok(scope)
    }
    pub fn reconcile(
        &self,
        record: &ProcessRecord,
        limits: ResourceLimits,
    ) -> ProcResult<Option<StopWitness>> {
        let mut scope = self.recorded(record, limits)?;
        let Some(ProcessObservation::Exited {
            expected,
            evidence,
            status,
            ..
        }) = scope.root()?
        else {
            return Ok(None);
        };
        let observed = scope.observe()?;
        if observed.remaining.population != Population::Empty
            || observed.exit_basis.is_none()
            || observed.remaining.extent != EnumerationExtent::Complete
        {
            return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Input {
                field: "cold recovery".into(), reason: "root exit is known but tracked group exit remains unproved; retain its record without signalling replacement PIDs".into() }));
        }
        Ok(Some(StopWitness {
            lifecycle: record.lifecycle.clone(),
            root: RootWitness::Identified {
                expected,
                evidence: Box::new(evidence),
                status,
            },
            scope: record.scope.clone(),
            scope_exit: observed,
            guarantee: record.guarantee,
            observed_at_unix_ns: now()?,
        }))
    }
}

impl Scope {
    pub fn retained_obligations(&self) -> TrackedObligations {
        TrackedObligations {
            members: self.tracked.clone(),
            escaped: self.escaped,
        }
    }
    fn drain_watch(&mut self) -> ProcResult<()> {
        let executed = self.watch.drain()?;
        if self
            .child
            .as_ref()
            .is_some_and(|child| child.authorized && executed.contains(&child.pid))
        {
            self.exec_seen = true;
        }
        Ok(())
    }
    fn refresh_exec(&mut self) -> ProcResult<()> {
        self.drain_watch()?;
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        if !child.authorized || !self.exec_seen || child.root.is_some() {
            return Ok(());
        }
        let pre = child
            .pre_exec
            .as_ref()
            .ok_or_else(|| input("exec observation", "root checkpoint absent"))?;
        if let ProcessRead::Present(live) = crate::read_process(pre.machine.clone(), child.pid)? {
            if live.identity.boot != pre.boot || live.identity.start != pre.start {
                return Err(changed(pre, Some(&live.identity)));
            }
            child.root = Some(live.identity.clone());
            self.scope = ScopeIdentity::MacOsTracked {
                process_group: child.pid,
                root: live.identity.clone(),
            };
            self.tracked.retain(|p| p.pid != child.pid);
            self.tracked.push(live.identity);
        }
        Ok(())
    }
    pub fn parent(&self) -> ReservationParent {
        ReservationParent::MacOs
    }
    pub fn intended_executable(&self) -> PathBuf {
        self.executable.clone()
    }
    pub fn child_created(&self) -> bool {
        self.child.is_some() || self.recovered.is_some()
    }
    pub fn root_identity(&self) -> Option<ProcessIdentity> {
        self.child
            .as_ref()
            .and_then(|child| child.root.clone().or_else(|| child.pre_exec.clone()))
            .or_else(|| self.recovered.clone())
    }
    pub fn unpublished_exit(&mut self) -> ProcResult<Option<(ProcessId, ExitStatus)>> {
        self.child
            .as_mut()
            .map(|child| {
                child
                    .peek_status()
                    .map(|s| s.map(|status| (child.pid, status)))
            })
            .unwrap_or(Ok(None))
    }
    pub fn root_exit_ready(&mut self) -> ProcResult<bool> {
        self.child
            .as_mut()
            .map(|child| child.peek_status().map(|s| s.is_some()))
            .unwrap_or(Ok(true))
    }
    pub fn root(&mut self) -> ProcResult<Option<ProcessObservation>> {
        self.refresh_exec()?;
        let Some(expected) = self.root_identity() else {
            return Ok(None);
        };
        if let Some(child) = &mut self.child
            && let Some(status) = child.peek_status()?
        {
            return Ok(Some(ProcessObservation::Exited {
                expected,
                evidence: ExitEvidence::NativeExitedRecord {
                    state: NativeState::Exited,
                },
                status,
                observed_at_unix_ns: now()?,
            }));
        }
        observe(&expected).map(Some)
    }
    pub fn poll(&mut self, machine: &MachineId) -> ProcResult<Progress> {
        self.drain_watch()?;
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("launch", "native child missing"))?;
        child.read_events()?;
        if !child.eof
            && let Some(registration) = self.registrations.first()
        {
            registration.rearm();
        }
        let offset = usize::from(child.protocol.first() == Some(&b'R'));
        if child.protocol.get(offset) == Some(&b'E') {
            if child.protocol.len() < offset + 5 {
                return Ok(Progress::Pending);
            }
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&child.protocol[offset + 1..offset + 5]);
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "Darwin attach/execve",
                io::Error::from_raw_os_error(i32::from_le_bytes(bytes)),
            ));
        }
        if offset == 0 {
            if child.eof {
                return Err(input("launch", "helper exited before native readiness"));
            }
            return Ok(Progress::Pending);
        }
        if child.pre_exec.is_none() {
            let ProcessRead::Present(live) = crate::read_process(machine.clone(), child.pid)?
            else {
                return Err(input("launch", "helper exited before root checkpoint"));
            };
            if !group::in_group(&live.identity, child.pid)? {
                return Err(changed(&live.identity, None));
            }
            self.watch.track(&live.identity)?;
            self.tracked.push(live.identity.clone());
            child.pre_exec = Some(live.identity.clone());
            self.group = Some(child.pid);
            self.scope = ScopeIdentity::MacOsTracked {
                process_group: child.pid,
                root: live.identity,
            };
        }
        let pre = child
            .pre_exec
            .clone()
            .ok_or_else(|| input("launch", "pre-exec identity missing"))?;
        if !child.authorized {
            return Ok(Progress::Root(pre));
        }
        if !child.eof || !self.exec_seen {
            if child.peek_status()?.is_some() {
                return Err(input(
                    "launch",
                    "child exited before native exec could be proved",
                ));
            }
            return Ok(Progress::Pending);
        }
        let ProcessRead::Present(live) = crate::read_process(machine.clone(), child.pid)? else {
            return Err(input(
                "launch",
                "child exited before final executable could be observed; retain checkpoint for cleanup",
            ));
        };
        if live.identity.boot != pre.boot || live.identity.start != pre.start {
            return Err(changed(&pre, Some(&live.identity)));
        }
        child.root = Some(live.identity.clone());
        self.scope = ScopeIdentity::MacOsTracked {
            process_group: child.pid,
            root: live.identity.clone(),
        };
        self.tracked.retain(|p| p.pid != child.pid);
        self.tracked.push(live.identity.clone());
        // Retain the actual child before a refusal so stop/recovery can still
        // observe it. Darwin's readback detects drift, not an atomic exec proof.
        if let Some(image) = &self.image_custody {
            image
                .validate()
                .map_err(|e| input("qualified image readback", &e.to_string()))?;
        }
        self.image_custody = None;
        Ok(Progress::Executed(
            live.identity.clone(),
            Box::new(ProcessObservation::Live(live)),
        ))
    }
    pub fn authorize(&mut self) -> ProcResult<()> {
        if let Some(image) = &self.image_custody {
            image
                .validate()
                .map_err(|e| input("qualified image authorization", &e.to_string()))?;
        }
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("exec authorization", "native child absent"))?;
        let pre = child
            .pre_exec
            .as_ref()
            .ok_or_else(|| input("exec authorization", "root checkpoint absent"))?;
        if !matches!(observe(pre)?, ProcessObservation::Live(_)) {
            return Err(changed(pre, None));
        }
        child.authorize()
    }
}
pub(crate) fn observe(expected: &ProcessIdentity) -> ProcResult<ProcessObservation> {
    let unavailable = ExitStatus::Unavailable {
        reason: ExitStatusUnavailable::NotOurChild,
    };
    let (evidence, status, at) = match crate::read_process(expected.machine.clone(), expected.pid)?
    {
        ProcessRead::Present(live) if live.identity == *expected => {
            return Ok(ProcessObservation::Live(live));
        }
        ProcessRead::Present(live)
            if live.identity.boot != expected.boot || live.identity.start != expected.start =>
        {
            (
                ExitEvidence::Replaced {
                    observed: live.identity,
                },
                unavailable,
                live.observed_at_unix_ns,
            )
        }
        ProcessRead::Present(live) => return Err(changed(expected, Some(&live.identity))),
        ProcessRead::Absent {
            observed_at_unix_ns,
            ..
        } => (ExitEvidence::Absent, unavailable, observed_at_unix_ns),
        ProcessRead::ExitedRecord {
            boot,
            start,
            state,
            status,
            observed_at_unix_ns,
            ..
        } => {
            if boot != expected.boot || start != expected.start {
                return Err(changed(expected, None));
            }
            (
                ExitEvidence::NativeExitedRecord { state },
                status,
                observed_at_unix_ns,
            )
        }
    };
    Ok(ProcessObservation::Exited {
        expected: expected.clone(),
        evidence,
        status,
        observed_at_unix_ns: at,
    })
}
pub(crate) fn uncreated_scope(
    reservation: &LaunchReservation,
) -> ProcResult<(ScopeObservation, ContainmentGuarantee)> {
    Ok((
        empty(ScopeIdentity::MacOsPrepared {
            nonce: reservation.scope_nonce,
        })?,
        guarantee(),
    ))
}
pub fn process_attach_entry(args: &[std::ffi::OsString]) -> Option<ProcResult<()>> {
    if args.get(1).is_none_or(|arg| arg != attach::ENTRY) {
        return None;
    }
    Some(if args.len() == 2 {
        attach::entry()
    } else {
        Err(input(
            "process attach entry",
            "no public arguments accepted",
        ))
    })
}
