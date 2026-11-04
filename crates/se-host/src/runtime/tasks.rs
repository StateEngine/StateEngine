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
}
impl OwnershipFault {
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
