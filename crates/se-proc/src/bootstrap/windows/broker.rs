//! A same-user native parent supplies job detachment without a service or shell.
//! Only our explicit startup handles enter its handle table; it executes no code.
//! https://devblogs.microsoft.com/oldnewthing/20260511-00/?p=112313
use super::*;
use windows_sys::Win32::{Security::*, System::JobObjects::IsProcessInJob};

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
        return Err(input(
            "runtime detachment",
            "native process is still inside a Windows job",
        ));
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct Context {
    sid: String,
    logon: (u32, i32),
    session: u32,
    elevation: i32,
    integrity: String,
}
// Token queries use aligned owned buffers and bounded resizing: a token's
// variable data may change after the sizing probe. Never decode a short value.
fn token_buffer(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    minimum: usize,
) -> ProcResult<Vec<usize>> {
    let mut needed = 0;
    // SAFETY: documented null sizing probe with retained token and writable length.
    unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed);
    }
    for _ in 0..3 {
        let capacity = (needed as usize).max(minimum).saturating_add(256);
        if capacity > 65536 {
            return Err(input(
                "detached broker token",
                "native token buffer exceeds 64 KiB",
            ));
        }
        let mut storage = vec![0usize; capacity.div_ceil(size_of::<usize>())];
        let mut returned = 0;
        // SAFETY: aligned initialized allocation of at least capacity bytes;
        // the token and output length remain retained throughout this query.
        let ok = unsafe {
            GetTokenInformation(
                token,
                class,
                storage.as_mut_ptr().cast(),
                capacity as u32,
                &mut returned,
            )
        };
        if ok != 0 {
            if (returned as usize) < minimum || returned as usize > capacity {
                return Err(input(
                    "detached broker token",
                    &format!(
                        "class {class}: returned {returned} bytes, minimum {minimum}, capacity {capacity}"
                    ),
                ));
            }
            return Ok(storage);
        }
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(fail("read detached broker token context", cause));
        }
        needed = returned;
    }
    Err(input(
        "detached broker token",
        &format!("class {class}: size did not stabilize after three native reads"),
    ))
}
// Private callers instantiate this only with fixed-size, pointer-free native token POD.
fn token_value<T: Copy>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> ProcResult<T> {
    let storage = token_buffer(token, class, size_of::<T>())?;
    // SAFETY: successful native query initialized at least sizeof(T) bytes;
    // usize allocation aligns every fixed token POD used by these private callers.
    Ok(unsafe { *storage.as_ptr().cast::<T>() })
}
fn context(process: HANDLE) -> ProcResult<Context> {
    let sid =
        crate::windows_native::process_sid(process).map_err(|e| fail(e.operation, e.source))?;
    let mut raw = ptr::null_mut();
    // SAFETY: retained process and writable owned token output, query access only.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open detached broker token"));
    }
    let token = handle(raw, "own detached broker token")?;
    let token = token.as_raw_handle();
    // A broker must never remove a restricted-token or app-container boundary.
    // The native payload is BOOLEAN although the published enum page says DWORD;
    // token_buffer preserves DWORD alignment and only this initialized byte is read.
    // https://github.com/microsoft/win32metadata/discussions/2308
    if token_value::<u8>(token, TokenHasRestrictions)? != 0
        || token_value::<u32>(token, TokenIsAppContainer)? != 0
    {
        return Err(input(
            "detached broker token",
            "restricted and app-container tokens cannot use a native parent broker",
        ));
    }
    let stats: TOKEN_STATISTICS = token_value(token, TokenStatistics)?;
    let buffer = token_buffer(
        token,
        TokenIntegrityLevel,
        size_of::<TOKEN_MANDATORY_LABEL>(),
    )?;
    // SAFETY: successful aligned label output remains retained through SID conversion.
    let integrity = crate::windows_native::sid_text(unsafe {
        (*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid
    })
    .map_err(|e| fail(e.operation, e.source))?;
    Ok(Context {
        sid,
        logon: (
            stats.AuthenticationId.LowPart,
            stats.AuthenticationId.HighPart,
        ),
        session: token_value(token, TokenSessionId)?,
        elevation: token_value(token, TokenElevationType)?,
        integrity,
    })
}

pub(super) struct Broker {
    process: OwnedHandle,
    pub identity: ProcessIdentity,
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
            return Ok(Self { process, identity });
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
