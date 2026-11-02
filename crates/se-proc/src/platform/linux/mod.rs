mod group;
mod identity;
mod spawn;
use crate::platform::{Progress, empty};
use crate::runtime::notify::Hub;
use crate::support::*;
use crate::*;
pub(crate) use identity::{read_process, verify_live_identity};
use std::{io, os::fd::AsRawFd, sync::Arc};

pub(crate) struct Driver {
    reactor: Arc<dyn NativeReactor>,
}
pub(crate) struct Scope {
    child: Option<spawn::Child>,
    recovered: Option<ProcessIdentity>,
    tracked: Vec<ProcessIdentity>,
    registrations: Vec<Box<dyn NativeRegistration>>,
    group: Option<ProcessId>,
    pub scope: ScopeIdentity,
    pub guarantee: ContainmentGuarantee,
    pub entry: EntryMethod,
    max_members: usize,
    escaped: bool,
    executable: std::path::PathBuf,
}
impl Driver {
    pub fn new(config: &HostConfig) -> ProcResult<Self> {
        Ok(Self {
            reactor: config.reactor.clone(),
        })
    }
    pub fn capabilities(&self) -> PlatformCapabilities {
        let unavailable = || Capability::Unavailable {
            error: Box::new(unsupported(
                "trusted delegated-scope creator is unavailable in wave 1; Linux owns an explicitly uncontained tracked process group until wave 4",
            )),
        };
        let notification = match spawn::pidfd(ProcessId(std::process::id())) {
            Ok(Some(_)) => Capability::Supported,
            Ok(None) => Capability::Unavailable {
                error: Box::new(unsupported(
                    "pidfd_open unavailable; reads and host deadlines retain the identity-recheck bound",
                )),
            },
            Err(e) => Capability::Unavailable { error: Box::new(e) },
        };
        PlatformCapabilities {
            headless: Capability::Supported,
            window: Capability::Unavailable {
                error: Box::new(unsupported("Unix terminal attach joins before alpha")),
            },
            kernel_scope: unavailable(),
            tracked_tree: Capability::Supported,
            kernel_exit_notification: notification,
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
        if spec.policy.containment == ContainmentRequirement::KernelScope {
            return Err(unsupported(
                "strict kernel scope requested; Linux scopes join in wave 4",
            ));
        }
        if spec.mode != LaunchMode::Headless {
            return Err(unsupported("Unix terminal attach is not yet available"));
        }
        if !matches!(
            reservation.parent,
            ReservationParent::LinuxTracked | ReservationParent::LinuxUserManager
        ) {
            return Err(input(
                "reservation.parent",
                "wave 1 requires LinuxTracked or unresolved LinuxUserManager",
            ));
        }
        Ok(Scope {
            child: None,
            recovered: None,
            tracked: Vec::new(),
            registrations: Vec::new(),
            group: None,
            scope: ScopeIdentity::LinuxPrepared {
                nonce: reservation.scope_nonce,
            },
            // Wave 1 has no trusted delegated-scope creator. This is the
            // NoDelegation classification's unavailable-helper case, not an
            // assertion that this machine has no cgroup hierarchy or manager.
            guarantee: ContainmentGuarantee::Uncontained {
                reason: UncontainedReason::NoDelegation,
            },
            entry: EntryMethod::LinuxProcessGroup,
            max_members: limits.max_diagnostic_members as usize,
            escaped: false,
            executable: spec.executable.clone(),
        })
    }
    pub fn begin(&self, scope: &mut Scope, spec: LaunchSpec, hub: &Arc<Hub>) -> ProcResult<()> {
        scope.child = Some(spawn::begin(spec)?);
        // Creation is already in the arena. No query/registration failure can
        // discard the child or its authorization endpoint.
        let child = scope
            .child
            .as_mut()
            .ok_or_else(|| input("child", "creation did not retain custody"))?;
        child.arm()?;
        let registration = self.reactor.register(
            child
                .events
                .try_clone()
                .map_err(|e| native(ProcErrorCode::LaunchFailed, "clone exec channel", e))?,
            NativeInterest::Readable,
            hub.clone(),
        )?;
        scope.registrations.push(registration);
        if let Some(pin) = &child.pin {
            scope.registrations.push(
                self.reactor.register(
                    pin.try_clone()
                        .map_err(|e| native(ProcErrorCode::LaunchFailed, "clone root pidfd", e))?,
                    NativeInterest::Readable,
                    hub.clone(),
                )?,
            );
        }
        Ok(())
    }
    pub fn recover(
        &self,
        record: &ProcessRecord,
        limits: ResourceLimits,
        hub: &Arc<Hub>,
    ) -> ProcResult<Scope> {
        let ScopeIdentity::LinuxTracked {
            process_group,
            root,
        } = &record.scope
        else {
            return Err(unsupported(
                "only tracked Linux groups are recoverable in wave 1",
            ));
        };
        if root != &record.root
            || root.machine != record.owner.machine
            || root.boot != identity::boot()?
        {
            return Err(changed(&record.root, None));
        }
        let mut scope = Scope {
            child: None,
            recovered: Some(root.clone()),
            tracked: vec![root.clone()],
            registrations: Vec::new(),
            group: Some(*process_group),
            scope: record.scope.clone(),
            guarantee: record.guarantee,
            entry: record.entry,
            max_members: limits.max_diagnostic_members as usize,
            escaped: false,
            executable: record.root.image.clone(),
        };
        // A protected record and a matching original live member establish this
        // lower-bound recovery. A name/group number by itself never does.
        let observation = scope.root()?;
        if !matches!(observation, Some(ProcessObservation::Live(_))) {
            return Err(error(
                ProcErrorCode::RecoveryUnproved,
                ProcErrorDetail::Scope {
                    lifecycle: Some(record.lifecycle.clone()),
                    path: None,
                    reason: "original tracked root no longer proves group custody after host loss"
                        .into(),
                },
            ));
        }
        if identity::stat(root.pid)?.is_none_or(|s| s.group != *process_group) {
            return Err(changed(root, None));
        }
        if let Some(pin) = spawn::pidfd(root.pid)? {
            scope.registrations.push(self.reactor.register(
                pin,
                NativeInterest::Readable,
                hub.clone(),
            )?);
        }
        // Post-arm reread closes exit/registration races; custody is still
        // tied to the protected original start and group before any signal.
        scope.observe()?;
        Ok(scope)
    }
    pub fn reconcile(
        &self,
        record: &ProcessRecord,
        limits: ResourceLimits,
    ) -> ProcResult<Option<StopWitness>> {
        let ScopeIdentity::LinuxTracked {
            process_group,
            root,
        } = &record.scope
        else {
            return Err(input(
                "cold Linux recovery",
                "wave 1 requires the protected tracked-group record",
            ));
        };
        if root != &record.root || root.boot != identity::boot()? {
            return Err(changed(&record.root, None));
        }
        let ProcessObservation::Exited {
            expected,
            evidence,
            status,
            ..
        } = identity::observe(root)?
        else {
            return Ok(None);
        };
        let mut scope = Scope {
            child: None,
            recovered: Some(root.clone()),
            tracked: vec![root.clone()],
            registrations: Vec::new(),
            group: Some(*process_group),
            scope: record.scope.clone(),
            guarantee: record.guarantee,
            entry: record.entry,
            max_members: limits.max_diagnostic_members as usize,
            escaped: false,
            executable: root.image.clone(),
        };
        let observed = scope.observe()?;
        if observed.remaining.population != Population::Empty
            || observed.exit_basis.is_none()
            || !matches!(observed.remaining.extent, EnumerationExtent::Complete)
        {
            return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Input {
                    field: "cold Linux recovery".into(), reason: "original root exited but tracked group exit remains unproved; preserve the record without attaching replacement PIDs".into() }));
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
    pub fn intended_executable(&self) -> std::path::PathBuf {
        self.executable.clone()
    }
    pub fn child_created(&self) -> bool {
        self.child.is_some() || self.recovered.is_some()
    }
    pub fn unpublished_exit(&mut self) -> ProcResult<Option<(ProcessId, ExitStatus)>> {
        if let Some(child) = &mut self.child {
            return Ok(child.peek_status()?.map(|s| (child.pid, s)));
        }
        Ok(None)
    }
    pub fn parent(&self) -> ReservationParent {
        ReservationParent::LinuxTracked
    }
    pub fn root_identity(&self) -> Option<ProcessIdentity> {
        self.child
            .as_ref()
            .and_then(|c| c.root.clone().or_else(|| c.pre_exec.clone()))
            .or_else(|| self.recovered.clone())
    }
    pub fn poll(&mut self, machine: &MachineId) -> ProcResult<Progress> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("launch", "child not created"))?;
        child.drain()?;
        let offset = usize::from(child.protocol.first() == Some(&b'R'));
        if child.protocol.get(offset) == Some(&b'E') {
            if child.protocol.len() < offset + 5 {
                return Ok(Progress::Pending);
            }
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&child.protocol[offset + 1..offset + 5]);
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "tracked helper/execve",
                io::Error::from_raw_os_error(i32::from_le_bytes(bytes)),
            ));
        }
        if offset == 0 {
            if child.eof {
                return Err(input(
                    "launch",
                    "helper died before reporting group readiness",
                ));
            }
            return Ok(Progress::Pending);
        }
        if child.pre_exec.is_none() {
            let ProcessRead::Present(live) = read_process(machine.clone(), child.pid)? else {
                return Err(input(
                    "launch",
                    "pre-exec helper exited before root checkpoint",
                ));
            };
            if identity::stat(child.pid)?.is_none_or(|s| s.group != child.pid) {
                return Err(changed(&live.identity, None));
            }
            child.pre_exec = Some(live.identity.clone());
            self.tracked.push(live.identity.clone());
            self.group = Some(child.pid);
            self.scope = ScopeIdentity::LinuxTracked {
                process_group: child.pid,
                root: live.identity.clone(),
            };
        }
        let pre = child
            .pre_exec
            .clone()
            .ok_or_else(|| input("launch", "missing pre-exec identity"))?;
        if !child.authorized {
            return Ok(Progress::Root(pre));
        }
        if !child.eof {
            return Ok(Progress::Pending);
        }
        match read_process(machine.clone(), child.pid)? {
            ProcessRead::Present(live) => {
                if live.identity.start != pre.start || live.identity.boot != pre.boot {
                    return Err(changed(&pre, Some(&live.identity)));
                }
                // The close-on-exec error channel plus fresh executable and
                // known child state proves exec; EOF alone never does.
                child.root = Some(live.identity.clone());
                self.scope = ScopeIdentity::LinuxTracked {
                    process_group: child.pid,
                    root: live.identity.clone(),
                };
                self.tracked.retain(|p| p.pid != child.pid);
                self.tracked.push(live.identity.clone());
                Ok(Progress::Executed(
                    live.identity.clone(),
                    Box::new(ProcessObservation::Live(live)),
                ))
            }
            _ => {
                // A normal child exit following an empty exec-error channel
                // proves exec, but does not supply its possibly interpreted
                // image. Keep the checkpoint and return an honest failed start.
                let _status = child.peek_status()?;
                Err(input(
                    "launch",
                    "child exited before its executable could be observed; retain root checkpoint for cleanup",
                ))
            }
        }
    }
    pub fn authorize(&mut self) -> ProcResult<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("authorize exec", "missing child"))?;
        let expected = child
            .pre_exec
            .as_ref()
            .ok_or_else(|| input("authorize exec", "root checkpoint not available"))?;
        if !matches!(identity::observe(expected)?, ProcessObservation::Live(_)) {
            return Err(changed(expected, None));
        }
        child.authorize()
    }
    pub fn root_exit_ready(&mut self) -> ProcResult<bool> {
        // procfs may mark our retained child a zombie just before waitid
        // exposes its status. Preserve that observation as pending, then use
        // the cached native status for every complete witness and release.
        match &mut self.child {
            Some(child) => Ok(child.peek_status()?.is_some()),
            None => Ok(true),
        }
    }
    pub fn root(&mut self) -> ProcResult<Option<ProcessObservation>> {
        let Some(expected) = self.root_identity() else {
            return Ok(None);
        };
        if let Some(child) = &mut self.child
            && let Some(status) = child.peek_status()?
        {
            return Ok(Some(ProcessObservation::Exited {
                expected,
                evidence: ExitEvidence::NativeExitedRecord {
                    state: NativeState::ExitedAwaitingReap,
                },
                status,
                observed_at_unix_ns: now()?,
            }));
        }
        identity::observe(&expected).map(Some)
    }
}

pub(crate) fn uncreated_scope(
    reservation: &LaunchReservation,
) -> ProcResult<(ScopeObservation, ContainmentGuarantee)> {
    Ok((
        empty(ScopeIdentity::LinuxPrepared {
            nonce: reservation.scope_nonce,
        })?,
        ContainmentGuarantee::Uncontained {
            reason: UncontainedReason::NoDelegation,
        },
    ))
}

pub(crate) fn runtime_cgroup() -> ProcResult<bool> {
    let bytes = identity::bytes(std::path::Path::new("/proc/self/cgroup"), 65536)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| input("runtime cgroup", "malformed native hierarchy"))?;
    let mut found = false;
    let mut inherited = false;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let _number = fields
            .next()
            .ok_or_else(|| input("runtime cgroup", "missing hierarchy number"))?;
        let _controllers = fields
            .next()
            .ok_or_else(|| input("runtime cgroup", "missing controllers"))?;
        let path = fields
            .next()
            .ok_or_else(|| input("runtime cgroup", "missing native path"))?;
        if !path.starts_with('/') {
            return Err(input(
                "runtime cgroup",
                "absolute native cgroup path required",
            ));
        }
        found = true;
        inherited |= path != "/";
    }
    if !found {
        return Err(input("runtime cgroup", "empty native hierarchy fact"));
    }
    Ok(inherited)
}

pub(crate) fn runtime_boot_id() -> ProcResult<se_types::BootId> {
    let BootIdentity::Linux { boot_id } = identity::boot()? else {
        return Err(input("runtime boot", "native Linux UUID required"));
    };
    let text: String = se_types::hex_lower(&boot_id);
    se_types::BootId::new(format!("linux:{text}"))
        .map_err(|e| input("runtime boot", &e.to_string()))
}
