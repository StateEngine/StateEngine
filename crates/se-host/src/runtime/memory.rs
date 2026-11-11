//! Standalone glibc maintenance after a burst, never a periodic idle wakeup:
//! the allocator trim and the read-only code-page release each follow a 1 s
//! quiescence after the completed work burst, so the idle RSS floor lands a
//! couple of seconds after startup. A longer release window is not safer:
//! the measured re-fault cost of a request after a short gap is within noise.
//! The quiescence is additionally capped by an absolute deadline per pass:
//! periodic low-cost connection activity on a shared box (probes of the
//! loopback listen port, dials of the runtime socket) resets the quiescence
//! windows without doing work, and an uncapped window lets that activity
//! defer the first release past the 60 s idle measurement.
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Notify;

/// Quiescence required before the allocator trim and the read-only code-page
/// release each run, after a completed work burst.
const IDLE_QUIESCENCE: Duration = Duration::from_secs(1);

/// Cap on how long a trim-and-release pass may be deferred after it starts.
/// See the module docs for the shared-box activity that motivates the cap;
/// the measured re-fault cost after a release is within noise, so the cap
/// bounds the deferral without hurting a request.
const PASS_MAX_DEFER: Duration = Duration::from_secs(30);

#[derive(Clone, Default)]
pub(super) struct MemoryReclaim(Arc<Notify>);

pub(super) struct CompletedWork<'a>(&'a MemoryReclaim);

impl MemoryReclaim {
    pub(super) fn after_work(&self) -> CompletedWork<'_> {
        CompletedWork(self)
    }

    pub(super) fn completed(&self) {
        self.0.notify_one();
    }

    async fn run(self, trim: impl FnMut(), release: impl FnMut()) {
        self.run_with(IDLE_QUIESCENCE, PASS_MAX_DEFER, trim, release)
            .await
    }

    async fn run_with(
        self,
        quiescence: Duration,
        max_defer: Duration,
        mut trim: impl FnMut(),
        mut release: impl FnMut(),
    ) {
        // Reclaim bootstrap scratch once too. A new completion restarts the
        // one-shot delay; sustained traffic does not pay a trim per request.
        self.completed();
        loop {
            self.0.notified().await;
            // One pass per burst: trim, then release, each after quiescence.
            // The deadline caps the deferral of the whole pass, so
            // shared-box connection activity that keeps resetting the
            // quiescence windows cannot defer the idle floor indefinitely.
            let deadline = tokio::time::Instant::now() + max_defer;
            self.quiesce_before(deadline, quiescence).await;
            trim();
            self.quiesce_before(deadline, quiescence).await;
            release();
            // No timer remains armed until the next completed work burst.
        }
    }

    /// Wait for `quiescence` without a completion, or until `deadline`.
    async fn quiesce_before(&self, deadline: tokio::time::Instant, quiescence: Duration) {
        loop {
            let window_end = (tokio::time::Instant::now() + quiescence).min(deadline);
            if tokio::time::timeout_at(window_end, self.0.notified())
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

impl Drop for CompletedWork<'_> {
    fn drop(&mut self) {
        self.0.completed();
    }
}

pub(super) async fn while_serving(
    mut stop: Pin<Box<dyn Future<Output = ()> + Send>>,
    memory: Option<MemoryReclaim>,
) {
    let reclaim = async move {
        match memory {
            Some(memory) => {
                memory
                    .run(
                        || {
                            // Best effort: false is a normal no-pages-released
                            // result.
                            se_proc::reclaim_unused_allocator_pages();
                        },
                        || {
                            // Demand-paged code pages stay resident until
                            // the kernel's own reclaim; the idle budget
                            // cannot wait for that on a loaded box.
                            se_proc::release_read_only_mapped_pages();
                        },
                    )
                    .await;
            }
            None => std::future::pending().await,
        }
    };
    let mut reclaim = std::pin::pin!(reclaim);
    std::future::poll_fn(|cx| {
        // This future is owned by serve, so shutdown drops it rather than
        // leaving a maintenance task or timer in the embedder's runtime.
        let _ = reclaim.as_mut().poll(cx);
        stop.as_mut().poll(cx)
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }

    #[test]
    fn quiet_box_runs_one_pass_after_quiescence() -> std::io::Result<()> {
        let rt = runtime()?;
        rt.block_on(async {
            let reclaim = MemoryReclaim::default();
            let trims = Arc::new(AtomicUsize::new(0));
            let releases = Arc::new(AtomicUsize::new(0));
            let trims_task = Arc::clone(&trims);
            let releases_task = Arc::clone(&releases);
            tokio::spawn(reclaim.run_with(
                Duration::from_millis(20),
                Duration::from_millis(500),
                move || {
                    trims_task.fetch_add(1, Ordering::SeqCst);
                },
                move || {
                    releases_task.fetch_add(1, Ordering::SeqCst);
                },
            ));
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(trims.load(Ordering::SeqCst), 1);
            assert_eq!(releases.load(Ordering::SeqCst), 1);
        });
        Ok(())
    }

    #[test]
    fn sustained_activity_cannot_defer_the_pass_past_the_cap() -> std::io::Result<()> {
        let rt = runtime()?;
        rt.block_on(async {
            let reclaim = MemoryReclaim::default();
            let releases = Arc::new(AtomicUsize::new(0));
            let releases_task = Arc::clone(&releases);
            let churn = reclaim.clone();
            tokio::spawn(reclaim.run_with(
                Duration::from_millis(50),
                Duration::from_millis(120),
                || {},
                move || {
                    releases_task.fetch_add(1, Ordering::SeqCst);
                },
            ));
            // Connection-churn stand-in: a completion every 5 ms, far
            // denser than the 50 ms quiescence, for the whole test.
            tokio::spawn(async move {
                loop {
                    churn.completed();
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            let started = tokio::time::Instant::now();
            while releases.load(Ordering::SeqCst) == 0 {
                assert!(
                    started.elapsed() < Duration::from_millis(500),
                    "release deferred past 500 ms by sustained activity (cap is 120 ms)"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        Ok(())
    }
}
