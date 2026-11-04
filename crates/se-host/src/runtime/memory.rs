//! Standalone glibc maintenance after a burst, never a periodic idle wakeup.
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Notify;

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

    async fn run(self, mut reclaim: impl FnMut()) {
        // Reclaim bootstrap scratch once too. A new completion restarts the
        // one-shot delay; sustained traffic does not pay a trim per request.
        self.completed();
        loop {
            self.0.notified().await;
            while tokio::time::timeout(Duration::from_secs(1), self.0.notified())
                .await
                .is_ok()
            {}
            reclaim();
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
                    .run(|| {
                        // Best effort: false is a normal no-pages-released result.
                        se_proc::reclaim_unused_allocator_pages();
                    })
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
