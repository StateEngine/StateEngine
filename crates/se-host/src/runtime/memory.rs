//! Standalone glibc maintenance after a burst, never a periodic idle wakeup:
//! the allocator trim and the read-only code-page release each follow a 1 s
//! quiescence after the completed work burst, so the idle RSS floor lands a
//! couple of seconds after startup. A longer release window is not safer:
//! the measured re-fault cost of a request after a short gap is within noise,
//! while a long window lets periodic low-cost connection activity on a shared
//! box keep resetting the window and defer the release past the 60 s idle
//! measurement.
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Notify;

/// Quiescence required before the read-only code pages are released, on top
/// of the 1 s trim window. One second keeps the idle floor deterministic on a
/// shared box: any connection activity spaced further apart than a second can
/// only defer the release by seconds, never past the 60 s idle measurement.
const CODE_RELEASE_IDLE: Duration = Duration::from_secs(1);

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

    async fn run(self, mut trim: impl FnMut(), mut release: impl FnMut()) {
        // Reclaim bootstrap scratch once too. A new completion restarts the
        // one-shot delay; sustained traffic does not pay a trim per request.
        self.completed();
        loop {
            self.0.notified().await;
            while tokio::time::timeout(Duration::from_secs(1), self.0.notified())
                .await
                .is_ok()
            {}
            trim();
            while tokio::time::timeout(CODE_RELEASE_IDLE, self.0.notified())
                .await
                .is_ok()
            {}
            release();
            // No timer remains armed until the next completed work burst.
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
                            // Demand-paged code pages stay resident until the
                            // kernel's own reclaim; the idle budget cannot
                            // wait for that on a loaded box.
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
