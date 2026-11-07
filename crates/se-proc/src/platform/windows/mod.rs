mod console;
mod identity;
mod notify;
mod recovery;
pub use recovery::observe_prepared_scope_exit;
pub(crate) use recovery::uncreated_scope;
mod security;
mod spawn;
mod stdio;
use crate::platform::{Progress, empty};
use crate::runtime::notify::Hub;
use crate::support::*;
use crate::*;
use identity::*;
pub(crate) use identity::{read_process, read_process_until, verify_live_identity};
use std::{mem::zeroed, ptr, sync::Arc};
pub(crate) use stdio::NativeStdio;
use windows_sys::Win32::{Foundation::*, System::JobObjects::*};

pub(crate) struct Driver {
    collector: notify::Collector,
    stdio_budget: Arc<stdio::Budget>,
}
pub(crate) struct Scope {
    job: Handle,
    child: Option<spawn::Child>,
    console_host: Option<console::ConsoleHost>,
    window: bool,
    pub scope: ScopeIdentity,
    pub guarantee: ContainmentGuarantee,
    pub entry: EntryMethod,
    max_members: usize,
    _notification: notify::Registration,
}
const LIMITS: JOB_OBJECT_LIMIT = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
impl Driver {
    pub fn new(config: &HostConfig) -> ProcResult<Self> {
        Ok(Self {
            collector: notify::Collector::new()?,
            stdio_budget: stdio::Budget::new(config.limits.max_stdio_buffer_bytes),
        })
    }
    pub fn create_stdio(&self, config: &StdioConfig) -> ProcResult<Arc<NativeStdio>> {
        NativeStdio::create(&self.collector, self.stdio_budget.clone(), config)
    }
    pub fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            headless: Capability::Supported,
            window: Capability::Supported,
            kernel_scope: Capability::Supported,
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
        hub: &Arc<Hub>,
    ) -> ProcResult<Scope> {
        if !matches!(reservation.parent, ReservationParent::Windows) {
            return Err(input(
                "reservation.parent",
                "Windows job reservation required",
            ));
        }
        if spec.mode == LaunchMode::Window && spec.window != Some(WindowSpec::WindowsConsole) {
            return Err(input("window", "WindowsConsole required"));
        }
        let name = recovery::job_name(reservation)?;
        let security = security::Security::owner_only()?;
        let attributes = security.attributes();
        // SAFETY: descriptor and name backing live through CreateJobObjectW;
        // noninheritable private job ownership is immediately RAII-held.
        let raw =
            unsafe { CreateJobObjectW(&attributes, wide(std::ffi::OsStr::new(&name)).as_ptr()) };
        let job = Handle::new(raw, "CreateJobObjectW")?;
        // SAFETY: thread-local error of the immediately preceding native creation.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Err(input(
                "job",
                "native job name already exists; do not adopt or modify it",
            ));
        }
        // SAFETY: initialized native POD policy output/input with all optional fields zero.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags = LIMITS;
        // SAFETY: retained original job and exact aligned policy/association bytes.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(last(
                ProcErrorCode::ContainmentUnavailable,
                "SetInformationJobObject",
            ));
        }
        let notification = self.collector.register(hub)?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: notification.key as *mut _,
            CompletionPort: self.collector.handle.0,
        };
        // SAFETY: retained original job and exact aligned policy/association bytes.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectAssociateCompletionPortInformation,
                (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                size_of_val(&association) as u32,
            )
        } == 0
        {
            return Err(last(
                ProcErrorCode::ContainmentUnavailable,
                "associate job IOCP",
            ));
        }
        let scope = Scope {
            job,
            child: None,
            console_host: None,
            window: spec.mode == LaunchMode::Window,
            scope: ScopeIdentity::WindowsJob {
                host: reservation.host,
                name,
            },
            guarantee: ContainmentGuarantee::KernelScope {
                explicit_breakaway: true,
            },
            entry: EntryMethod::WindowsJobList,
            max_members: limits.max_diagnostic_members as usize,
            _notification: notification,
        };
        security::verify_job(&scope.job)?;
        scope.verify_limits()?;
        Ok(scope)
    }
    pub fn begin(&self, scope: &mut Scope, spec: LaunchSpec, _hub: &Arc<Hub>) -> ProcResult<()> {
        scope.verify_limits()?;
        scope.child = Some(spawn::create(spec, &scope.job)?);
        Ok(())
    }
}
impl Scope {
    fn verify_limits(&self) -> ProcResult<()> {
        // SAFETY: initialized native POD policy output/input with all optional fields zero.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        // SAFETY: live query-capable job and exact aligned writable native output.
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&info) as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last(
                ProcErrorCode::ContainmentChanged,
                "query pinned job limits",
            ));
        }
        if info.BasicLimitInformation.LimitFlags != LIMITS {
            return Err(input("job policy", "pinned job limits changed"));
        }
        Ok(())
    }
    pub fn parent(&self) -> ReservationParent {
        ReservationParent::Windows
    }
    pub fn child_created(&self) -> bool {
        self.child.is_some()
    }
    pub fn unpublished_exit(&mut self) -> ProcResult<Option<(ProcessId, ExitStatus)>> {
        let Some(child) = &self.child else {
            return Ok(None);
        };
        Ok(exit_status(&child.pin)?.map(|status| (child.pid, status)))
    }
    pub fn poll(&mut self, machine: &MachineId) -> ProcResult<Progress> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("launch", "no child"))?;
        if child.identity.is_none() {
            child.identity = Some(identity(machine.clone(), child.pid, &child.pin)?);
        }
        let root = child
            .identity
            .clone()
            .ok_or_else(|| input("launch", "root identity unavailable"))?;
        let observation = observe(&root, &child.pin)?;
        let mut member = 0;
        // SAFETY: original retained process/job and initialized writable membership output.
        if unsafe { IsProcessInJob(child.pin.0, self.job.0, &mut member) } == 0 {
            return Err(last(ProcErrorCode::ContainmentChanged, "IsProcessInJob"));
        }
        if member == 0 && matches!(observation, ProcessObservation::Live(_)) {
            return Err(input(
                "root membership",
                "created root is outside its pinned job",
            ));
        }
        Ok(Progress::Executed(root, Box::new(observation)))
    }
    pub fn authorize(&mut self) -> ProcResult<()> {
        Err(input(
            "authorize_exec",
            "Windows job-list launch needs no additional root barrier",
        ))
    }
    pub fn root_exit_ready(&mut self) -> ProcResult<bool> {
        Ok(true)
    }
    pub fn root(&mut self) -> ProcResult<Option<ProcessObservation>> {
        let Some(child) = self.child.as_ref() else {
            return Ok(None);
        };
        let Some(expected) = child.identity.as_ref() else {
            // Retain an unpublished exact child pin; witness_stop separately
            // joins its signalled exit to independently empty job accounting.
            return Ok(None);
        };
        observe(expected, &child.pin).map(Some)
    }
    pub fn observe(&mut self) -> ProcResult<ScopeObservation> {
        self.verify_limits()?;
        // SAFETY: accounting output is native POD with initialized optional fields.
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        // SAFETY: live query-capable job and exact aligned writable native output.
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of_val(&accounting) as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last(
                ProcErrorCode::ScopeUnreadable,
                "read pinned job accounting",
            ));
        }
        if accounting.ActiveProcesses == 0 {
            return empty(self.scope.clone());
        }
        let (known_live, extent) = match self.members() {
            Ok(members) => (members, EnumerationExtent::Complete),
            Err(e) => (
                Vec::new(),
                EnumerationExtent::Partial {
                    reason: format!("job diagnostic enumeration failed: {:?}", e.code),
                    omitted: None,
                },
            ),
        };
        Ok(ScopeObservation {
            scope: self.scope.clone(),
            remaining: RemainingScope {
                population: Population::Populated,
                known_live,
                extent,
                observed_at_unix_ns: now()?,
            },
            exit_basis: None,
        })
    }
    fn members(&self) -> ProcResult<Vec<ProcessIdentity>> {
        let Some(child) = &self.child else {
            return Err(input("job diagnostics", "no published root identity"));
        };
        let machine = child
            .identity
            .as_ref()
            .ok_or_else(|| input("job diagnostics", "no root identity"))?
            .machine
            .clone();
        let mut cap = 16usize.min(self.max_members);
        loop {
            let mut buffer = vec![0usize; cap + 2];
            // SAFETY: aligned variable-length native buffer; at most cap PID
            // entries are read after validating both native counts below.
            let ok = unsafe {
                QueryInformationJobObject(
                    self.job.0,
                    JobObjectBasicProcessIdList,
                    buffer.as_mut_ptr().cast(),
                    std::mem::size_of_val(buffer.as_slice()) as u32,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: thread-local error from the immediately preceding query.
                if unsafe { GetLastError() } != ERROR_MORE_DATA {
                    return Err(last(
                        ProcErrorCode::ScopeUnreadable,
                        "query job PID diagnostics",
                    ));
                }
            } else {
                // SAFETY: successful query filled the aligned buffer with this native header.
                let list = unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
                let count = list.NumberOfProcessIdsInList as usize;
                if count <= cap && list.NumberOfAssignedProcesses as usize <= count {
                    // SAFETY: both native counts were validated against allocated PID capacity.
                    let pids =
                        unsafe { std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), count) };
                    let mut members = Vec::new();
                    for &pid in pids {
                        let pid = ProcessId(
                            u32::try_from(pid).map_err(|_| input("job PID", "overflow"))?,
                        );
                        let Some(handle) = lookup(pid)? else {
                            continue;
                        };
                        let mut yes = 0;
                        // SAFETY: retained query-only candidate and original job, writable membership output.
                        if unsafe { IsProcessInJob(handle.0, self.job.0, &mut yes) } == 0 {
                            return Err(last(
                                ProcErrorCode::ScopeUnreadable,
                                "verify diagnostic job member",
                            ));
                        }
                        if yes != 0 {
                            match identity(machine.clone(), pid, &handle) {
                                Ok(member) => members.push(member),
                                Err(original) => {
                                    // Diagnostic enumeration races process exit.
                                    // Skip only an independently signalled original
                                    // kernel object; unreadable live members refuse.
                                    if exit_status(&handle)?.is_none() {
                                        return Err(original);
                                    }
                                }
                            }
                        }
                    }
                    return Ok(members);
                }
            }
            if cap >= self.max_members {
                return Err(capacity("job diagnostic members", self.max_members as u64));
            }
            cap = (cap * 2).min(self.max_members);
        }
    }
    pub fn stop(&mut self, deadline: std::time::Instant) -> ProcResult<StopDispatch> {
        self.verify_limits()?;
        check_stop_deadline(deadline)?;
        // SAFETY: held original job, never a PID/name lookup or replacement job.
        if unsafe { TerminateJobObject(self.job.0, 1) } == 0 {
            return Err(last(
                ProcErrorCode::StopDispatchFailed,
                "TerminateJobObject",
            ));
        }
        Ok(StopDispatch::Requested)
    }
    pub fn release(&mut self, witnessed: bool) -> ProcResult<()> {
        if !witnessed {
            return Err(input(
                "release",
                "Windows jobs require an outside exit witness",
            ));
        }
        if self.observe()?.remaining.population != Population::Empty {
            return Err(input("release", "pinned job is still populated"));
        }
        if let Some(child) = &mut self.child {
            child.pin.close()?;
        }
        self.child = None;
        self.console_host = None;
        self.job.close()?;
        // The slot's final Drop closes this witnessed-empty job. No raw handle
        // is returned to another layer and no provider endpoint is closed here.
        Ok(())
    }
}
