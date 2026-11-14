//! Unix reactor registered into the native runtime. Each registered
//! source's descriptor is owned by its AsyncFd until it is dropped; a
//! readiness nudge never witnesses an exit, exec or process count.

use se_proc::{
    NativeInterest, NativeReactor, NativeReadiness, NativeRegistration, ProcError, ProcErrorCode,
    ProcErrorDetail, ProcResult,
};
use std::{
    fs::File,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    runtime::Handle,
    sync::Notify,
    task::AbortHandle,
};

pub(crate) struct Reactor {
    pub runtime: Handle,
    pub fault: Arc<crate::runtime::tasks::OwnershipFault>,
    pub fence: Arc<AtomicBool>,
}
struct Registration {
    active: Arc<AtomicBool>,
    arm: Arc<Notify>,
    task: AbortHandle,
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
            #[cfg(target_os = "linux")]
            NativeInterest::Priority => Interest::PRIORITY,
            #[cfg(not(target_os = "linux"))]
            NativeInterest::Priority => {
                return Err(ProcError {
                    code: ProcErrorCode::ContainmentUnavailable,
                    detail: Box::new(ProcErrorDetail::Input {
                        field: "native reactor".into(),
                        reason: "priority readiness is unavailable on this platform".into(),
                    }),
                    native: None,
                });
            }
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
        let (fault, fence) = (self.fault.clone(), self.fence.clone());
        let task = self.runtime.spawn(async move {
            let result = crate::runtime::tasks::caught(
                async {
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
                                fence.store(true, Ordering::Release);
                                fault.poison();
                                break;
                            }
                        }
                        // One notification per explicit native re-arm prevents a
                        // terminal pidfd or EOF from turning into an idle spin loop.
                        if catch_unwind(AssertUnwindSafe(|| sink.ready())).is_err() {
                            fence.store(true, Ordering::Release);
                            fault.poison();
                            break;
                        }
                    }
                },
                false,
            )
            .await;
            if result.is_err() {
                fence.store(true, Ordering::Release);
                fault.poison();
            }
        });
        let task = self.fault.retain_native(task).map_err(|error| {
            self.fault.poison();
            ProcError {
                code: ProcErrorCode::ContainmentUnavailable,
                detail: Box::new(ProcErrorDetail::Input {
                    field: "native collector join registry".into(),
                    reason: error.to_string(),
                }),
                native: None,
            }
        })?;
        Ok(Box::new(Registration { active, arm, task }))
    }
}
