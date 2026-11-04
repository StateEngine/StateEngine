//! One live-work timer per host. Zero activity disarms it; missed ticks coalesce.
use std::{future::Future, pin::Pin, time::Duration};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::watch;
pub(super) type Timer = Pin<Box<dyn Future<Output = ()> + Send>>;
pub(super) enum Tick {
    Idle,
    CatchUp,
    OwnershipFault,
}
pub(super) struct Timers {
    pub idle: Timer,
    pub catch_up: Timer,
    pub fault: Timer,
}
impl Timers {
    pub(super) fn new(
        idle: Timer,
        activity: Option<watch::Receiver<u32>>,
        fault: Arc<super::tasks::OwnershipFault>,
    ) -> Self {
        Self {
            idle,
            catch_up: timer(activity),
            fault: Box::pin(async move { fault.wait().await }),
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Tick> {
        if self.fault.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Tick::OwnershipFault);
        }
        if self.idle.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Tick::Idle);
        }
        if self.catch_up.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Tick::CatchUp);
        }
        Poll::Pending
    }
}
pub(super) fn timer(activity: Option<watch::Receiver<u32>>) -> Timer {
    with_window(activity, Duration::from_secs(15 * 60))
}
fn with_window(activity: Option<watch::Receiver<u32>>, window: Duration) -> Timer {
    Box::pin(async move {
        let Some(mut activity) = activity else {
            return std::future::pending().await;
        };
        loop {
            if activity.wait_for(|count| *count > 0).await.is_err() {
                return std::future::pending().await;
            }
            let ended = tokio::time::timeout(window, async {
                activity.wait_for(|count| *count == 0).await.map(|_| ())
            })
            .await;
            match ended {
                Err(_) => return,
                Ok(Ok(())) => (),
                Ok(Err(_)) => return std::future::pending().await,
            }
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_timer_disarms_at_zero_and_never_treats_a_closed_source_as_a_tick()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (activity, read) = watch::channel(0);
            let mut tick = with_window(Some(read.clone()), Duration::ZERO);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut tick)
                    .await
                    .is_err()
            );
            activity.send_replace(1);
            tokio::time::timeout(Duration::from_secs(2), tick).await?;
            activity.send_replace(0);
            let mut disarmed = with_window(Some(read), Duration::ZERO);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut disarmed)
                    .await
                    .is_err()
            );
            drop(activity);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), disarmed)
                    .await
                    .is_err()
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
