//! The Atlas home writer lease, ended explicitly rather than by close.
//!
//! On Unix the lock belongs to the open file description, and a child forked on
//! another thread inherits a duplicate of that description until it execs.
//! Ending the lease by close alone therefore leaves it held by the child's
//! duplicate, and the next step in this process is refused with a spurious
//! "Atlas home writer lease" busy. `se_proc::advisory_lock::AdvisoryLock`
//! releases with an explicit unlock first, which clears the lock on the shared
//! description.
//!
//! Windows takes no advisory descriptor lock here: the exclusive open itself is
//! the exclusion, and it is released when the handle closes. There is no
//! inherited-descriptor window to fix, so the plain descriptor remains.
use std::fs::File;

#[cfg(unix)]
pub(super) type WriterLease = se_proc::advisory_lock::AdvisoryLock;
#[cfg(not(unix))]
pub(super) type WriterLease = File;

/// The descriptor the lease holds, whichever platform form it takes.
pub(super) fn opened(lease: &WriterLease) -> &File {
    #[cfg(unix)]
    {
        lease.file()
    }
    #[cfg(not(unix))]
    {
        lease
    }
}
