//! An exclusive advisory file lock that ends explicitly, not by close.
//!
//! This is the general primitive shared by protected state-file effects and the
//! Atlas cache writer. It lives outside `state_files` so it is not charged
//! against that directory's structure budget.
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// How a guard's lock ends when the guard goes away.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseMode {
    /// Clear the lock with `LOCK_UN` before the descriptor closes, so a
    /// duplicate a child inherited between fork and exec cannot keep it.
    Unlock,
    /// Leave the lock to the last duplicate of this description closing.
    CloseOnly,
}

/// An exclusive advisory lock that is released explicitly rather than by the
/// descriptor closing.
///
/// `flock` belongs to the open file description, and a spawned child inherits
/// duplicates of every descriptor between fork and exec. Closing this process's
/// duplicate while such a child is alive therefore leaves the lock held by the
/// child's copy, and a concurrent writer in this process is refused. Releasing
/// with `LOCK_UN` first clears the lock on the shared description, so no
/// inherited copy can outlive the release. Every holding site keeps one of
/// these for as long as it intends to hold the lock.
///
/// The rule has one deliberate exception. The account-wide installation claim
/// shares its description with the installer worker by design: the worker
/// inherits it across exec and may still be changing files after the shell
/// stops waiting for it. A `child::wait` error path can drop the claim while
/// that worker lives, so `LOCK_UN` there would release a live holder's claim.
/// That one guard ends by close only (`end_by_close`), and the lock then clears
/// when the worker's own duplicate closes. Every other site keeps `Unlock`,
/// because a child must never be able to keep an abandoned lock alive.
#[must_use = "dropping the guard releases the lock when its last duplicate closes"]
pub struct AdvisoryLock {
    file: File,
    release: ReleaseMode,
}
impl AdvisoryLock {
    /// Take the exclusive nonblocking lock on a descriptor this process alone
    /// opened. A descriptor shared with a child or another process must not be
    /// passed: `LOCK_UN` acts on the whole description.
    pub fn acquire(file: File) -> std::io::Result<Self> {
        // SAFETY: advisory exclusive lock on a retained descriptor, nonblocking.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            release: ReleaseMode::Unlock,
        })
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    /// Release early while keeping the descriptor, for a holder that
    /// deliberately narrows what it keeps locked. Returns the native failure
    /// rather than swallowing it: a lock that did not release is a fact the
    /// caller must be able to report.
    pub fn release(&mut self) -> std::io::Result<()> {
        // SAFETY: release this guard's own cooperating description; the
        // descriptor stays open and owned by the guard.
        if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    /// End the lock by close only: every duplicate of this description, even
    /// one a long-lived child inherited across exec, must close before the lock
    /// frees. Only a holder whose worker deliberately inherits the description
    /// uses this; a `LOCK_UN` there would release the claim of a worker that is
    /// still changing files.
    pub fn end_by_close(&mut self) {
        self.release = ReleaseMode::CloseOnly;
    }
}
impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        if self.release == ReleaseMode::CloseOnly {
            // Closing the last duplicate releases the lock. An explicit
            // `LOCK_UN` would free it under an inherited holder still at work.
            return;
        }
        // A failed unlock is not actionable during drop, but it must not vanish:
        // the lock stays held by this description until it closes.
        if let Err(error) = self.release() {
            eprintln!("advisory lock release failed: {error}");
        }
    }
}
