//! Panic boundaries retain lifecycle custody; ordinary route faults stay local.
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind},
    task::Poll,
    time::{Duration, Instant},
};
#[derive(Default)]
pub(crate) struct OwnershipFault {
    pub(crate) failed: std::sync::atomic::AtomicBool,
    changed: tokio::sync::Notify,
    native_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    joining: tokio::sync::Mutex<()>,
}
impl OwnershipFault {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn retain_native(
        &self,
        task: tokio::task::JoinHandle<()>,
    ) -> se_types::Result<tokio::task::AbortHandle> {
        let abort = task.abort_handle();
        let mut tasks = self.native_tasks.lock().map_err(|_| {
            se_core::scope::unreadable(
                "native collector tasks",
                "retained join registry is poisoned",
            )
        })?;
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(abort)
    }
    pub(crate) async fn join_native(
        &self,
        deadline: &crate::client::lease::Deadline,
    ) -> se_types::Result<()> {
        let _joining = super::pool::within(deadline, self.joining.lock()).await?;
        loop {
            let task = {
                let mut tasks = self.native_tasks.lock().map_err(|_| {
                    se_core::scope::unreadable(
                        "native collector tasks",
                        "retained join registry is poisoned",
                    )
                })?;
                for task in tasks.iter() {
                    task.abort();
                }
                tasks.pop()
            };
            let Some(mut task) = task else {
                return Ok(());
            };
            match super::pool::within(deadline, &mut task).await {
                Ok(Ok(())) => (),
                Ok(Err(error)) if error.is_cancelled() => (),
                Ok(Err(error)) => {
                    self.poison();
                    return Err(se_core::scope::unreadable(
                        "native collector join",
                        &error.to_string(),
                    ));
                }
                Err(error) => {
                    self.native_tasks
                        .lock()
                        .map_err(|_| {
                            se_core::scope::unreadable(
                                "native collector tasks",
                                "retained join registry is poisoned",
                            )
                        })?
                        .push(task);
                    return Err(error);
                }
            }
        }
    }
    pub(crate) fn poison(&self) {
        self.failed
            .store(true, std::sync::atomic::Ordering::Release);
        self.changed.notify_waiters();
    }
    pub(crate) async fn wait(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.failed.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
    pub(crate) fn observe_writer(&self, error: &se_store::StoreError) {
        if matches!(
            error.code,
            se_store::StoreErrorCode::WriterClosed | se_store::StoreErrorCode::GenerationChanged
        ) {
            self.poison();
        }
    }
}
#[derive(Default)]
pub(crate) struct FaultBudget {
    failures: VecDeque<Instant>,
}
impl FaultBudget {
    pub(crate) fn available(&mut self, now: Instant) -> bool {
        while self
            .failures
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= Duration::from_secs(60))
        {
            self.failures.pop_front();
        }
        self.failures.len() < 3
    }
    pub(crate) fn failed(&mut self, now: Instant) {
        if self.available(now) {
            self.failures.push_back(now);
        }
    }
}
pub(crate) async fn caught<F: Future>(
    future: F,
    retain_on_panic: bool,
) -> std::result::Result<F::Output, ()> {
    let mut future = Some(Box::pin(future));
    poll_fn(|cx| {
        match catch_unwind(AssertUnwindSafe(|| match future.as_mut() {
            Some(future) => future.as_mut().poll(cx),
            None => Poll::Pending,
        })) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => {
                if retain_on_panic {
                    // A poisoned lifecycle may own an in-flight writer or native
                    // custody. Quarantine its finite future until process exit;
                    // recovery must not claim those resources joined or closed.
                    std::mem::forget(future.take());
                }
                Poll::Ready(Err(()))
            }
        }
    })
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_join_waits_for_actual_future_resource_drop() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Resource(Arc<AtomicBool>);
        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let dropped = Arc::new(AtomicBool::new(false));
            let resource = Resource(dropped.clone());
            let fault = OwnershipFault::default();
            fault.retain_native(tokio::spawn(async move {
                let _resource = resource;
                std::future::pending::<()>().await;
            }))?;
            let deadline =
                crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                    expected_generation: None,
                    timeout: Duration::from_secs(2),
                    cancelled: Arc::new(AtomicBool::new(false)),
                })?;
            fault.join_native(&deadline).await?;
            assert!(dropped.load(Ordering::Acquire));
            assert!(!fault.failed.load(Ordering::Acquire));
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
    #[test]
    fn route_restart_budget_is_rolling_and_bounded() {
        let now = Instant::now();
        let mut budget = FaultBudget::default();
        for seconds in [0, 10, 20] {
            let at = now + Duration::from_secs(seconds);
            assert!(budget.available(at));
            budget.failed(at);
        }
        assert!(!budget.available(now + Duration::from_secs(59)));
        assert!(budget.available(now + Duration::from_secs(60)));
    }
    #[test]
    fn polling_panic_returns_a_fault() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let result = runtime.block_on(caught(async { panic!("owned test route") }, false));
        assert!(result.is_err());
        Ok(())
    }
}
