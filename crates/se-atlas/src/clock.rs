//! Monotonic time for synchronous Atlas work budgets.
//! Debug fixtures may freeze only their calling thread. Builds without debug
//! assertions always use system time, even when Cargo unifies test-clock.
use std::time::Instant;

#[inline]
pub fn now() -> Instant {
    #[cfg(all(feature = "test-clock", debug_assertions))]
    if let Some(now) = manual::current() {
        return now;
    }
    Instant::now()
}

// A thread blocked in an OS wait cannot advance its manual clock. Translate
// only that wait's remaining allowance so admission still has a finite bound.
pub(crate) fn wait_deadline(deadline: Instant) -> Instant {
    #[cfg(all(feature = "test-clock", debug_assertions))]
    if let Some(now) = manual::current() {
        return Instant::now() + deadline.saturating_duration_since(now);
    }
    deadline
}

#[cfg(all(feature = "test-clock", debug_assertions))]
pub use manual::{Paused, advance, pause};

#[cfg(all(feature = "test-clock", debug_assertions))]
mod manual {
    use std::{
        cell::Cell,
        marker::PhantomData,
        rc::Rc,
        time::{Duration, Instant},
    };

    thread_local! {
        static CURRENT: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    pub(super) fn current() -> Option<Instant> {
        CURRENT.with(Cell::get)
    }

    /// Restores real time on drop, including an unwinding test. The guard cannot
    /// move to a different thread or affect another test running in parallel.
    #[must_use]
    pub struct Paused(PhantomData<Rc<()>>);

    /// Freeze the calling thread's Atlas budgets until explicitly advanced.
    /// Admission waits and unrelated threads continue to use real time.
    pub fn pause() -> Paused {
        CURRENT.with(|clock| {
            assert!(clock.get().is_none(), "Atlas clock is already paused");
            clock.set(Some(Instant::now()));
        });
        Paused(PhantomData)
    }

    /// Expire a slice at a specific native operation instead of sleeping and
    /// racing the scheduler. A paused clock must be active on this thread.
    pub fn advance(duration: Duration) {
        CURRENT.with(|clock| {
            let Some(now) = clock.get() else {
                panic!("Atlas clock must be paused before advancing");
            };
            clock.set(Some(now + duration));
        });
    }

    impl Drop for Paused {
        fn drop(&mut self) {
            CURRENT.with(|clock| clock.set(None));
        }
    }
}
