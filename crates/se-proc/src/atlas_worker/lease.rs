//! Parser and Git history are sequential phases of the same cold allocation.
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};

static ACTIVE: AtomicBool = AtomicBool::new(false);
pub struct Lease(bool);
impl Lease {
    pub fn acquire() -> io::Result<Self> {
        if ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous Atlas parser/Git phase has not been exactly reaped",
            ));
        }
        Ok(Self(true))
    }
    /// A failed native reap retains the reservation, even after Rust custody
    /// drops. It must never admit another independently capped child.
    pub fn retain_on_failed_reap(&mut self) {
        self.0 = false;
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.0 {
            ACTIVE.store(false, Ordering::Release);
        }
    }
}
