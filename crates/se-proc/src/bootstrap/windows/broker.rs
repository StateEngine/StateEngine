//! A same-user native parent supplies job detachment without a service or shell.
//! Only our explicit startup handles enter its handle table; it executes no code.
//! https://devblogs.microsoft.com/oldnewthing/20260511-00/?p=112313
use super::*;
use windows_sys::Win32::System::JobObjects::IsProcessInJob;

fn in_job(process: HANDLE) -> ProcResult<bool> {
    let mut member = 0;
    // SAFETY: retained query-capable process and writable BOOL; null means any job.
    if unsafe { IsProcessInJob(process, ptr::null_mut(), &mut member) } == 0 {
        return Err(last("observe detached runtime job membership"));
    }
    Ok(member != 0)
}
pub(super) fn outside_job(process: HANDLE) -> ProcResult<()> {
    if in_job(process)? {
        return Err(error(
            ProcErrorCode::BreakawayDenied,
            ProcErrorDetail::Input {
                field: "runtime detachment".into(),
                reason: "native process is still inside a Windows job".into(),
            },
        ));
    }
    Ok(())
}

mod token;
pub(super) use token::{Context, context};

pub(super) struct Broker {
    process: OwnedHandle,
    pub identity: ProcessIdentity,
    pub context: Context,
}
impl Broker {
    pub fn find(machine: &MachineId, deadline: Instant) -> ProcResult<Self> {
        // SAFETY: immutable current-process pseudo handle.
        let caller = context(unsafe { GetCurrentProcess() }).map_err(|error| {
            native(
                ProcErrorCode::BreakawayDenied,
                "verify caller security context for detached broker",
                io::Error::other(format!(
                    "{error:?}; open a normal terminal directly from Start using this account"
                )),
            )
        })?;
        let processes =
            crate::windows_native::parents().map_err(|e| fail(e.operation, e.source))?;
        let mut unreadable = 0;
        let mut examined = 0;
        for pid in processes
            .keys()
            .copied()
            .filter(|pid| *pid != std::process::id())
        {
            check(deadline)?;
            examined += 1;
            // SAFETY: read/query/duplicate/create-child rights only; native validates PID.
            let process = match handle(
                unsafe {
                    OpenProcess(
                        PROCESS_CREATE_PROCESS
                            | PROCESS_DUP_HANDLE
                            | PROCESS_QUERY_LIMITED_INFORMATION
                            | SYNCHRONIZE,
                        0,
                        pid,
                    )
                },
                "open detached broker candidate",
            ) {
                Ok(process) => process,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            // SAFETY: retained synchronize handle, no wait or mutation.
            if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
                continue;
            }
            let candidate = match context(process.as_raw_handle()) {
                Ok(value) => value,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            if candidate != caller {
                continue;
            }
            match in_job(process.as_raw_handle()) {
                Ok(false) => (),
                Ok(true) => continue,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            }
            let identity = match crate::read_process(machine.clone(), ProcessId(pid))? {
                ProcessRead::Present(live) => live.identity,
                _ => continue,
            };
            // The open handle pins the birth; do not trust a second PID-only read after reuse.
            let start = crate::windows_native::process_start(process.as_raw_handle())
                .map_err(|e| fail(e.operation, e.source))?;
            if identity.start
                != (StartIdentity::Windows {
                    creation_filetime: start,
                })
            {
                continue;
            }
            return Ok(Self {
                process,
                identity,
                context: caller,
            });
        }
        Err(native(
            ProcErrorCode::BreakawayDenied,
            "find same-user detached broker",
            io::Error::other(format!(
                "no verified broker among {examined} processes; {unreadable} contexts unreadable; open a normal terminal directly from Start using this account"
            )),
        ))
    }
    pub fn handle(&self) -> HANDLE {
        self.process.as_raw_handle()
    }
    pub fn duplicate<'a>(&'a self, sources: &[HANDLE]) -> ProcResult<RemoteHandles<'a>> {
        let mut result = RemoteHandles {
            broker: self,
            values: Vec::new(),
        };
        for source in sources {
            let mut target = ptr::null_mut();
            // SAFETY: source is our retained handle; broker handle pins its native table.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    *source,
                    self.handle(),
                    &mut target,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(last(
                    "duplicate private startup handle into detached broker",
                ));
            }
            result.values.push(target);
        }
        Ok(result)
    }
}
pub(super) struct RemoteHandles<'a> {
    broker: &'a Broker,
    pub values: Vec<HANDLE>,
}
impl RemoteHandles<'_> {
    pub fn close(&mut self) -> ProcResult<()> {
        let mut failure = None;
        for source in self.values.drain(..) {
            let mut local = ptr::null_mut();
            // SAFETY: closes only our exact duplicate in the retained broker table.
            // CLOSE_SOURCE closes the source even if duplicating it fails.
            let closed = unsafe {
                DuplicateHandle(
                    self.broker.handle(),
                    source,
                    GetCurrentProcess(),
                    &mut local,
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
                )
            };
            if closed == 0 {
                failure.get_or_insert_with(|| last("close private broker handle"));
            } else {
                drop(handle(local, "own returned broker handle")?);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for RemoteHandles<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("private detached broker handle cleanup failed: {error:?}");
        }
    }
}
