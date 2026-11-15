//! Only a complete fresh observation can resolve a settling native image.
use crate::{ProcError, ProcErrorCode, ProcessIdentity};

pub(super) fn settling(cause: &ProcError, root: &ProcessIdentity) -> bool {
    if cfg!(windows)
        && cause.code == ProcErrorCode::IdentityUnreadable
        && cause.native.as_ref().is_some_and(|failure| {
            failure.api == "QueryFullProcessImageNameW" && failure.code == Some(5)
        })
    {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        let crate::ProcErrorDetail::Identity {
            pid,
            expected_start,
            found_start,
            expected,
            found,
        } = cause.detail.as_ref()
        else {
            return false;
        };
        if *pid == root.pid || expected_start.is_none() || expected_start != found_start {
            return false;
        }
        match cause.code {
            ProcErrorCode::IdentityUnreadable => cause.native.as_ref().is_some_and(|failure| {
                failure.api == "proc_pidpath" && failure.code == Some(i64::from(libc::ESRCH))
            }),
            ProcErrorCode::IdentityChanged => {
                matches!((expected, found), (Some(before), Some(after))
                    if before.pid == *pid && after.pid == *pid
                        && before.machine == root.machine && after.machine == root.machine
                        && before.boot == root.boot && after.boot == root.boot
                        && before.start == after.start && before.image != after.image)
            }
            _ => false,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = root;
        false
    }
}
