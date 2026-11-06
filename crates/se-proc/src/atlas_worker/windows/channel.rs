//! The stdin marker is inert without the inherited owner-only duplex pipe.
use super::*;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
pub struct WorkerChannel(NativePipeStream);
impl WorkerChannel {
    pub fn receive() -> io::Result<(Self, Vec<u8>)> {
        // SAFETY: borrowed current-process/stdio handles; only a duplicate is owned.
        let current = unsafe { GetCurrentProcess() };
        // SAFETY: retrieves the borrowed current standard-input handle.
        let raw = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut duplicate = ptr::null_mut();
        // SAFETY: duplicates the borrowed handle once without inheriting it further.
        if unsafe {
            DuplicateHandle(
                current,
                raw,
                current,
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(last("DuplicateHandle(Atlas inherited input)"));
        }
        let handle = owned(duplicate, "own inherited Atlas channel")?;
        let limit = bound(Instant::now() + Duration::from_secs(2));
        let mut stream =
            NativePipeStream::worker_inherited(handle, limit.clone()).map_err(io::Error::other)?;
        let peer = crate::native_ipc::observe_ipc_peer_bounded(
            stream.channel(),
            crate::native_ipc::IpcPeerSide::Server,
            &limit,
        )
        .map_err(io::Error::other)?;
        let actual_parent = crate::windows_native::parent(current, std::process::id())
            .map_err(native_error)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Atlas parent-process query primitive unavailable",
                )
            })?;
        if peer.pid() != actual_parent {
            return Err(invalid("Atlas pipe is not owned by the exact parent"));
        }
        let envelope: Envelope = serde_json::from_slice(&read_frame(&mut stream)?)
            .map_err(|_| invalid("malformed Atlas parent envelope"))?;
        let se_types::StartIdentity::Windows { creation_filetime } = peer.started() else {
            return Err(invalid("Atlas parent creation time absent"));
        };
        if envelope.parent != actual_parent
            || envelope.birth != creation_filetime.get()
            || &envelope.image != peer.image()
        {
            return Err(invalid("Atlas parent birth/image differs"));
        }
        // Background mode lowers CPU and I/O priority for the entire cold process.
        // SAFETY: current-process pseudo handle and documented mode constant.
        if unsafe { SetPriorityClass(current, PROCESS_MODE_BACKGROUND_BEGIN) } == 0 {
            return Err(last(
                "SetPriorityClass(Atlas PROCESS_MODE_BACKGROUND_BEGIN)",
            ));
        }
        // SAFETY: POD job policy output; membership is read back before source access.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        // SAFETY: null job selects this process's assigned job, exact initialized output.
        if unsafe {
            QueryInformationJobObject(
                ptr::null_mut(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last(
                "QueryInformationJobObject(Atlas inherited extended limits)",
            ));
        }
        let required = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_TIME;
        if limits.BasicLimitInformation.LimitFlags & required != required
            || limits.BasicLimitInformation.ActiveProcessLimit != 1
            || limits.ProcessMemoryLimit != MEMORY_BYTES as usize
            || limits.JobMemoryLimit != MEMORY_BYTES as usize
            || limits.BasicLimitInformation.PerProcessUserTimeLimit != 900 * 10_000_000
        {
            return Err(invalid(
                "Atlas job memory/CPU/process/parent-death limits differ",
            ));
        }
        let payload = serde_json::to_vec(&envelope.payload).map_err(io::Error::other)?;
        Ok((Self(stream), payload))
    }
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0
            .set_bound(bound(Instant::now() + Duration::from_secs(2)));
        write_frame(&mut self.0, bytes)
    }
    pub fn await_reap(&mut self) -> io::Result<()> {
        self.0
            .set_bound(bound(Instant::now() + Duration::from_secs(2)));
        if read_frame(&mut self.0)? != b"reap" {
            return Err(invalid("parent reap acknowledgment absent"));
        }
        Ok(())
    }
}
