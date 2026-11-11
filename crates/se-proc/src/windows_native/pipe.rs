//! Query retained pipe facts without an unbounded FlushFileBuffers call.
use super::{Error, Result, invalid};
use std::{
    io,
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, BorrowedHandle},
};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FILE_PIPE_CONNECTED_STATE, FILE_PIPE_LOCAL_INFORMATION, FILE_PIPE_SERVER_END,
        FilePipeLocalInformation, NtQueryInformationFile,
    },
    Win32::{Foundation::RtlNtStatusToDosError, System::IO::IO_STATUS_BLOCK},
};

/// On the server end, consumed bytes restore the available outbound quota.
/// This synchronous information query does not wait for client consumption.
pub(crate) fn write_drained(channel: BorrowedHandle<'_>) -> Result<bool> {
    // SAFETY: these native result records contain only scalar values.
    let (mut status, mut info): (IO_STATUS_BLOCK, FILE_PIPE_LOCAL_INFORMATION) =
        unsafe { zeroed() };
    // SAFETY: the borrowed server and exact output records live through this
    // synchronous information query, including on an overlapped pipe handle.
    let result = unsafe {
        NtQueryInformationFile(
            channel.as_raw_handle(),
            &mut status,
            (&mut info as *mut FILE_PIPE_LOCAL_INFORMATION).cast(),
            size_of::<FILE_PIPE_LOCAL_INFORMATION>() as u32,
            FilePipeLocalInformation,
        )
    };
    if result != 0 {
        // SAFETY: converts the returned status, without sampling last-error.
        let code = unsafe { RtlNtStatusToDosError(result) };
        return Err(Error {
            operation: "observe IPC write consumption",
            source: io::Error::from_raw_os_error(code as i32),
        });
    }
    if status.Information != size_of::<FILE_PIPE_LOCAL_INFORMATION>()
        || info.NamedPipeEnd != FILE_PIPE_SERVER_END
        || info.OutboundQuota == 0
        || info.WriteQuotaAvailable > info.OutboundQuota
    {
        return Err(invalid(
            "observe IPC write consumption",
            "invalid server write quota",
        ));
    }
    if info.WriteQuotaAvailable == info.OutboundQuota {
        Ok(true)
    } else if info.NamedPipeState == FILE_PIPE_CONNECTED_STATE {
        Ok(false)
    } else {
        Err(Error {
            operation: "observe IPC write consumption",
            source: io::ErrorKind::BrokenPipe.into(),
        })
    }
}
