//! Private native pipe and atomically assigned job; no provider or host runtime.
use super::*;
use crate::native_ipc::{IpcIoBound, NativePipeStream};
use std::{
    mem::zeroed,
    os::windows::{
        io::{AsRawHandle, OwnedHandle},
        process::ExitStatusExt,
    },
    process::ExitStatus,
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    System::{JobObjects::*, ProcessStatus::*, Threading::*},
};
mod channel;
mod limits;
mod spawn;
pub use channel::WorkerChannel;
fn native_error(e: crate::windows_native::Error) -> io::Error {
    io::Error::new(e.source.kind(), format!("{}: {}", e.operation, e.source))
}
fn last(operation: &'static str) -> io::Error {
    native_error(crate::windows_native::Error {
        operation,
        source: io::Error::last_os_error(),
    })
}
fn owned(raw: HANDLE, op: &'static str) -> io::Result<OwnedHandle> {
    crate::windows_native::handle(raw, op).map_err(native_error)
}
fn closed_pipe(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == ERROR_BROKEN_PIPE as i32
        || code == ERROR_PIPE_NOT_CONNECTED as i32 || code == ERROR_HANDLE_EOF as i32)
}
fn bound(deadline: Instant) -> IpcIoBound {
    IpcIoBound {
        deadline,
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    parent: u32,
    birth: u64,
    image: se_types::NativePath,
    payload: serde_json::Value,
}
static CHILD_ACTIVE: AtomicBool = AtomicBool::new(false);
struct Lease(bool);
impl Drop for Lease {
    fn drop(&mut self) {
        if self.0 {
            CHILD_ACTIVE.store(false, Ordering::Release);
        }
    }
}
pub struct AtlasWorker {
    process: OwnedHandle,
    job: OwnedHandle,
    channel: NativePipeStream,
    stderr: std::fs::File,
    tail: super::stderr::StderrTail,
    deadline: Instant,
    incoming: Vec<u8>,
    reaped: bool,
    peak: u64,
    lease: Lease,
}
impl AtlasWorker {
    pub fn spawn(image: &Path, payload: &[u8], deadline: Instant) -> io::Result<Self> {
        if !image.is_absolute()
            || payload.len() > FRAME_BYTES
            || deadline <= Instant::now()
            || deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(900)
        {
            return Err(invalid(
                "absolute image, bounded frame and <=15 minute deadline required",
            ));
        }
        if CHILD_ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(invalid("previous Atlas child has not been reaped"));
        }
        let lease = Lease(true);
        let peer = crate::native_ipc::observe_ipc_self_bounded(&bound(
            Instant::now() + Duration::from_secs(2),
        ))
        .map_err(io::Error::other)?;
        let se_types::StartIdentity::Windows { creation_filetime } = peer.started() else {
            return Err(invalid("Windows parent creation time absent"));
        };
        let envelope = Envelope {
            parent: std::process::id(),
            birth: creation_filetime.get(),
            image: peer.image().clone(),
            payload: serde_json::from_slice(payload)
                .map_err(|_| invalid("cold input is not JSON"))?,
        };
        let encoded = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
        if encoded.len() > FRAME_BYTES {
            return Err(invalid("cold envelope exceeds 65536 bytes"));
        }
        let job = limits::create()?;
        let (channel, child_channel) =
            NativePipeStream::worker_pair(bound(Instant::now() + Duration::from_secs(2)))
                .map_err(io::Error::other)?;
        let (stderr, child_stderr) = NativePipeStream::worker_stderr().map_err(io::Error::other)?;
        let process = spawn::start(image, &job, &child_channel, &child_stderr)?;
        // Child-table references are independent after successful creation.
        // Close parent duplicates without a fallible post-spawn API before
        // transferring exact process/job custody into the worker below.
        drop(child_channel);
        drop(child_stderr);
        let mut worker = Self {
            process,
            job,
            channel,
            stderr,
            tail: super::stderr::StderrTail::new(),
            deadline,
            incoming: Vec::with_capacity(FRAME_BYTES + 4),
            reaped: false,
            peak: 0,
            lease,
        };
        write_frame(&mut worker.channel, &encoded)
            .map_err(|e| io::Error::new(e.kind(), format!("write Atlas parent envelope: {e}")))?;
        Ok(worker)
    }
    pub fn pid(&self) -> u32 {
        // SAFETY: retained process handle; GetProcessId reads its immutable PID.
        unsafe { GetProcessId(self.process.as_raw_handle()) }
    }
    pub fn peak_observed_bytes(&self) -> u64 {
        self.peak
    }
    pub fn observe_memory(&mut self) -> io::Result<u64> {
        // SAFETY: native memory-counter POD output with exact size and retained process.
        let mut info: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
        info.cb = size_of_val(&info) as u32;
        // SAFETY: exact initialized writable counter structure and original process handle.
        if unsafe {
            K32GetProcessMemoryInfo(
                self.process.as_raw_handle(),
                &mut info,
                size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(last("K32GetProcessMemoryInfo(Atlas child peak)"));
        }
        self.peak = self.peak.max(info.PeakWorkingSetSize as u64);
        if self.peak > MEMORY_BYTES {
            self.cancel()?;
            return Err(invalid("Atlas child exceeded 64 MB peak resident memory"));
        }
        Ok(self.peak)
    }
    pub fn wait_ready(&mut self, deadline: Instant) -> io::Result<bool> {
        match self.channel.readable_bytes() {
            Ok(n) if n > 0 => return Ok(true),
            Err(e) if closed_pipe(&e) => return Ok(true),
            Err(e) => return Err(e),
            _ => (),
        }
        self.channel.set_bound(bound(deadline.min(self.deadline)));
        let mut byte = [0];
        match self.channel.read(&mut byte) {
            Ok(0) => Ok(true),
            Ok(_) => {
                self.incoming.push(byte[0]);
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(false),
            Err(e) if closed_pipe(&e) => Ok(true),
            Err(e) => Err(e),
        }
    }
    pub fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.drain_stderr()?;
        if Instant::now() >= self.deadline {
            self.cancel()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Atlas cold deadline elapsed",
            ));
        }
        let mut bytes = [0; 4096];
        loop {
            if self.incoming.len() >= 4 {
                let length = u32::from_le_bytes(
                    self.incoming[..4]
                        .try_into()
                        .map_err(|_| invalid("frame header"))?,
                ) as usize;
                if length > FRAME_BYTES {
                    self.cancel()?;
                    return Err(invalid("malformed Atlas child frame"));
                }
                if self.incoming.len() >= length + 4 {
                    let frame = self.incoming[4..length + 4].to_vec();
                    self.incoming.drain(..length + 4);
                    return Ok(Some(frame));
                }
            }
            let available = match self.channel.readable_bytes() {
                Ok(n) => n,
                Err(e) if closed_pipe(&e) => 0,
                Err(e) => return Err(e),
            };
            if available == 0 {
                if self.try_reap()?.is_some() && !self.incoming.is_empty() {
                    return Err(invalid("truncated Atlas child frame"));
                }
                return Ok(None);
            }
            let length = available
                .min(bytes.len())
                .min((FRAME_BYTES + 4).saturating_sub(self.incoming.len()));
            if length == 0 {
                self.cancel()?;
                return Err(invalid("Atlas frame buffer exhausted"));
            }
            self.channel.set_bound(bound(
                self.deadline
                    .min(Instant::now() + Duration::from_millis(200)),
            ));
            let count = self.channel.read(&mut bytes[..length])?;
            self.incoming.extend_from_slice(&bytes[..count]);
        }
    }
    pub fn acknowledge_completion(&mut self) -> io::Result<()> {
        self.observe_memory()?;
        self.channel.set_bound(bound(
            self.deadline
                .min(Instant::now() + Duration::from_millis(200)),
        ));
        write_frame(&mut self.channel, b"reap")
    }
    pub fn try_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: original retained kernel process handle; no PID lookup or reuse.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                self.drain_stderr()?;
                let mut code = 0;
                // SAFETY: signalled original process and exact writable exit-code output.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(last("GetExitCodeProcess(Atlas child)"));
                }
                self.reaped = true;
                Ok(Some(ExitStatus::from_raw(code)))
            }
            _ => Err(last("WaitForSingleObject(Atlas child reap)")),
        }
    }
    pub fn failure_diagnostic(&mut self) -> io::Result<String> {
        self.drain_stderr()?;
        Ok(self.tail.diagnostic())
    }
    fn drain_stderr(&mut self) -> io::Result<()> {
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        let mut bytes = [0; 4096];
        let mut consumed = 0;
        while consumed < FRAME_BYTES {
            let mut available = 0;
            // SAFETY: one retained synchronous byte pipe and exact count output.
            if unsafe {
                PeekNamedPipe(
                    self.stderr.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if closed_pipe(&error) {
                    break;
                }
                return Err(io::Error::new(
                    error.kind(),
                    format!("PeekNamedPipe(Atlas stderr): {error}"),
                ));
            }
            if available == 0 {
                break;
            }
            let length = (available as usize)
                .min(bytes.len())
                .min(FRAME_BYTES - consumed);
            let count = self.stderr.read(&mut bytes[..length])?;
            if count == 0 {
                break;
            }
            consumed += count;
            self.tail.push(&bytes[..count]);
        }
        Ok(())
    }
    pub fn cancel(&mut self) -> io::Result<()> {
        if self.try_reap()?.is_none() {
            // SAFETY: this unique job contains only the atomically assigned cold child.
            if unsafe { TerminateJobObject(self.job.as_raw_handle(), 137) } == 0 {
                return Err(last("TerminateJobObject(Atlas child cancellation)"));
            }
            // SAFETY: retained exact process and finite termination grace.
            if unsafe { WaitForSingleObject(self.process.as_raw_handle(), 200) } == WAIT_FAILED {
                return Err(last("WaitForSingleObject(Atlas child cancellation)"));
            }
            if self.try_reap()?.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Atlas termination pending; retain exact child custody",
                ));
            }
        }
        Ok(())
    }
}
impl Drop for AtlasWorker {
    fn drop(&mut self) {
        if !self.reaped && self.cancel().is_err() {
            self.lease.0 = false;
        }
    }
}

pub(super) fn committed_bytes() -> io::Result<u64> {
    // SAFETY: initialized native counter output with the exact extended size.
    let mut info: PROCESS_MEMORY_COUNTERS_EX = unsafe { zeroed() };
    info.cb = size_of_val(&info) as u32;
    // SAFETY: current-process pseudo handle and retained aligned writable POD.
    if unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&mut info as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
            size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info.PrivateUsage as u64)
}
