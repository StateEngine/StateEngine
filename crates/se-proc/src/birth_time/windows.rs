use super::*;
use crate::{StartIdentity, support::native};
use std::{
    io,
    os::windows::io::{AsRawHandle, OwnedHandle},
};
use windows_sys::Win32::{Foundation::*, System::Threading::*};
pub(super) struct Pin(OwnedHandle);
impl Pin {
    pub(super) fn open(expected: &ProcessIdentity) -> ProcResult<Self> {
        // SAFETY: positive validated selector, query/synchronize access only;
        // no inheritance, process mutation or numeric-PID signal is requested.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                expected.pid.0,
            )
        };
        crate::windows_native::handle(raw, "pin native process birth")
            .map(Self)
            .map_err(|e| native(ProcErrorCode::IdentityUnreadable, e.operation, e.source))
    }
    pub(super) fn live(&self, expected: &ProcessIdentity) -> ProcResult<()> {
        // SAFETY: exact retained native instance, zero-timeout query cannot block.
        match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err(crate::support::changed(expected, None)),
            _ => Err(native(
                ProcErrorCode::IdentityUnreadable,
                "query birth-time process pin",
                io::Error::last_os_error(),
            )),
        }
    }
    pub(super) fn birth(
        &self,
        expected: &ProcessIdentity,
        deadline: Instant,
    ) -> ProcResult<ProcessBirthTime> {
        bound(deadline)?;
        let actual = crate::windows_native::process_start(self.0.as_raw_handle())
            .map_err(|e| native(ProcErrorCode::IdentityUnreadable, e.operation, e.source))?;
        if expected.start
            != (StartIdentity::Windows {
                creation_filetime: actual,
            })
        {
            return Err(crate::support::changed(expected, None));
        }
        // FILETIME's exact epoch is 1601-01-01 UTC, in 100ns units. Public Time
        // uses Unix microseconds; floor sub-microsecond values without a clock sample.
        const UNIX_EPOCH_FILETIME: i128 = 116_444_736_000_000_000;
        let micros = (i128::from(actual) - UNIX_EPOCH_FILETIME).div_euclid(10);
        let unix_micros = i64::try_from(micros).map_err(|_| {
            failure(
                ProcErrorCode::IdentityUnreadable,
                "native birth exceeds the Unix microsecond range",
            )
        })?;
        bound(deadline)?;
        Ok(ProcessBirthTime {
            unix_micros,
            precision: Duration::from_micros(1),
        })
    }
}
