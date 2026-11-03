//! Coalesced native nudges on the host's supplied reactor. Native state remains
//! authoritative; a wake is never an exit, exec or process-count witness.
use se_proc::{ExitNotice, ExitSink};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Wake {
    pub event: Arc<Notify>,
}
impl ExitSink for Wake {
    fn notify(&self, _notice: ExitNotice) {
        self.event.notify_waiters();
        self.event.notify_one();
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use se_proc::{
        NativeInterest, NativeReactor, NativeReadiness, NativeRegistration, ProcError,
        ProcErrorCode, ProcErrorDetail, ProcResult,
    };
    use std::{
        fs::File,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicBool, Ordering},
    };
    use tokio::{
        io::{Interest, unix::AsyncFd},
        runtime::Handle,
        task::JoinHandle,
    };

    pub(crate) struct Reactor {
        pub runtime: Handle,
    }
    struct Registration {
        active: Arc<AtomicBool>,
        arm: Arc<Notify>,
        task: JoinHandle<()>,
    }
    impl NativeRegistration for Registration {
        fn rearm(&self) {
            self.arm.notify_one();
        }
        fn cancel(&mut self) {
            self.active.store(false, Ordering::Release);
            self.task.abort();
        }
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            self.cancel();
        }
    }
    impl NativeReactor for Reactor {
        fn register(
            &self,
            source: File,
            interest: NativeInterest,
            sink: Arc<dyn NativeReadiness>,
        ) -> ProcResult<Box<dyn NativeRegistration>> {
            let interest = match interest {
                NativeInterest::Readable => Interest::READABLE,
                NativeInterest::Priority => Interest::PRIORITY,
            };
            let entered = self.runtime.enter();
            #[expect(
                deprecated,
                reason = "The reactor exclusively owns this File until AsyncFd drops it; its descriptor cannot change, unlike a generic AsRawFd value. No unsafe registration crosses into se-host."
            )]
            let fd = AsyncFd::with_interest(source, interest).map_err(|error| ProcError {
                code: ProcErrorCode::ContainmentUnavailable,
                detail: Box::new(ProcErrorDetail::Input {
                    field: "native reactor".into(),
                    reason: error.to_string(),
                }),
                native: None,
            })?;
            drop(entered);
            let active = Arc::new(AtomicBool::new(true));
            let arm = Arc::new(Notify::new());
            arm.notify_one();
            let (enabled, armed) = (active.clone(), arm.clone());
            let task = self.runtime.spawn(async move {
                loop {
                    armed.notified().await;
                    if !enabled.load(Ordering::Acquire) {
                        break;
                    }
                    let ready = fd.ready(interest).await;
                    if !enabled.load(Ordering::Acquire) {
                        break;
                    }
                    match ready {
                        Ok(mut ready) => ready.clear_ready(),
                        Err(_) => {
                            let _ = catch_unwind(AssertUnwindSafe(|| sink.ready()));
                            break;
                        }
                    }
                    // One notification per explicit native re-arm prevents a
                    // terminal pidfd or EOF from turning into an idle spin loop.
                    if catch_unwind(AssertUnwindSafe(|| sink.ready())).is_err() {
                        break;
                    }
                }
            });
            Ok(Box::new(Registration { active, arm, task }))
        }
    }
}
#[cfg(unix)]
pub(crate) use unix::Reactor;
