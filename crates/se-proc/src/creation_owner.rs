//! Startup only, before file/store work or worker creation. Windows elevated
//! tokens can default new file ownership to Administrators; SQLite inherits
//! that default even when its directory DACL is correctly owner-only.
use std::io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileOwnerInitialization {
    NotRequired,
    AlreadyUser { sid: String },
    Changed { sid: String },
}
#[derive(Debug)]
pub struct FileOwnerError {
    pub operation: &'static str,
    pub source: io::Error,
}
crate::native_error::native_error!(FileOwnerError, |error, out| {
    write!(out, "{}: {}", error.operation, error.source)
}; source Some(&error.source));
/// Call first in the CLI and host entry points. This changes only the Windows
/// process token's default owner to its actual user; no DACL, privilege, existing
/// file owner, Unix uid or process umask changes. Every native failure refuses.
pub fn initialize_file_creation_owner() -> Result<FileOwnerInitialization, FileOwnerError> {
    #[cfg(windows)]
    {
        windows::initialize()
    }
    #[cfg(not(windows))]
    {
        Ok(FileOwnerInitialization::NotRequired)
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::*,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    fn last(operation: &'static str) -> FileOwnerError {
        FileOwnerError {
            operation,
            source: io::Error::last_os_error(),
        }
    }
    fn refuse(reason: &'static str) -> FileOwnerError {
        FileOwnerError {
            operation: "initialize file creation owner",
            source: io::Error::other(reason),
        }
    }
    fn information(
        token: &OwnedHandle,
        class: TOKEN_INFORMATION_CLASS,
        minimum: usize,
    ) -> Result<Vec<usize>, FileOwnerError> {
        let mut bytes = 0;
        // SAFETY: documented sizing query on a live token with writable length.
        let status = unsafe {
            GetTokenInformation(token.as_raw_handle(), class, ptr::null_mut(), 0, &mut bytes)
        };
        // SAFETY: reads the immediately preceding native query's error.
        if status != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(last("size token ownership information"));
        }
        if bytes < minimum as u32 || bytes > 65536 {
            return Err(refuse("invalid native token ownership size"));
        }
        let mut storage = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
        let capacity = bytes;
        // SAFETY: aligned owned storage meets the native reported byte capacity.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                storage.as_mut_ptr().cast(),
                capacity,
                &mut bytes,
            )
        } == 0
        {
            return Err(last("read token ownership information"));
        }
        if bytes < minimum as u32 || bytes > capacity {
            return Err(refuse("native token ownership size changed"));
        }
        Ok(storage)
    }
    fn text(sid: PSID) -> Result<String, FileOwnerError> {
        crate::windows_native::sid_text(sid).map_err(|e| FileOwnerError {
            operation: "encode initialized owner SID",
            source: e.source,
        })
    }
    pub(super) fn initialize() -> Result<FileOwnerInitialization, FileOwnerError> {
        let mut raw = ptr::null_mut();
        // SAFETY: current-process pseudo handle, requested query/default-adjust
        // rights and writable owned token handle output; no privilege adjustment.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                &mut raw,
            )
        } == 0
        {
            return Err(last("open process token for file ownership initialization"));
        }
        // SAFETY: successful OpenProcessToken supplies one uniquely owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let user = information(&token, TokenUser, size_of::<TOKEN_USER>())?;
        let owner = information(&token, TokenOwner, size_of::<TOKEN_OWNER>())?;
        // SAFETY: exact successful native structures in aligned retained buffers;
        // embedded SID pointers remain valid while both allocations are held.
        let user_sid = unsafe { (&*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: successful aligned TOKEN_OWNER output remains retained below.
        let owner_sid = unsafe { (&*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner };
        // SAFETY: retained token buffers provide native SID pointers.
        if user_sid.is_null()
            || owner_sid.is_null()
            // SAFETY: preceding short-circuit checks exclude null; both native
            // SID pointers remain in their successful retained token buffers.
            || unsafe { IsValidSid(user_sid) == 0 || IsValidSid(owner_sid) == 0 }
        {
            return Err(refuse("invalid native token owner/user SID"));
        }
        let sid = text(user_sid)?;
        // SAFETY: both valid SIDs remain inside their retained token buffers.
        if unsafe { EqualSid(owner_sid, user_sid) } != 0 {
            return Ok(FileOwnerInitialization::AlreadyUser { sid });
        }
        let replacement = TOKEN_OWNER { Owner: user_sid };
        // SAFETY: actual TokenUser is a valid default owner; retained SID and
        // correctly sized TOKEN_OWNER outlive this synchronous kernel capture.
        if unsafe {
            SetTokenInformation(
                token.as_raw_handle(),
                TokenOwner,
                (&replacement as *const TOKEN_OWNER).cast(),
                size_of::<TOKEN_OWNER>() as u32,
            )
        } == 0
        {
            return Err(last("set process default file owner to actual user"));
        }
        let observed = information(&token, TokenOwner, size_of::<TOKEN_OWNER>())?;
        // SAFETY: independent successful native readback in retained aligned storage.
        let observed_sid = unsafe { (&*observed.as_ptr().cast::<TOKEN_OWNER>()).Owner };
        // SAFETY: retained original user SID and independent native owner readback.
        if observed_sid.is_null() || unsafe { EqualSid(observed_sid, user_sid) } == 0 {
            return Err(refuse("process default file owner failed native readback"));
        }
        Ok(FileOwnerInitialization::Changed { sid })
    }
}
