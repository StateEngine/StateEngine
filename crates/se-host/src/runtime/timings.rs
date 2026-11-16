//! Same-call timing around the existing bounded jobs; no worker or authority cache.
use super::BlockingPool;
use crate::client::lease::Deadline;
use se_core::ops::HostPhaseSpan;
use se_types::Result;
use std::{
    num::NonZeroU32,
    time::{Duration, Instant},
};
pub(super) enum Mode {
    Finite,
    Owned,
}
pub(super) fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}
pub(super) async fn blocking<T, F>(
    pool: &BlockingPool,
    mode: Mode,
    deadline: &Deadline,
    work: F,
) -> Result<(T, HostPhaseSpan)>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let enabled =
        *ENABLED.get_or_init(|| std::env::var("SE_OBSERVE_WORKER_STEPS").as_deref() == Ok("1"));
    let queued = Instant::now();
    let measured = move || {
        let entered = Instant::now();
        if enabled {
            se_proc::worker_observer::begin();
            se_store::worker_observer::begin();
        }
        let result = work();
        let collect = Instant::now();
        let detail = if enabled {
            Some(serde_json::json!({
                "host_native":se_proc::worker_observer::finish(),
                "store":se_store::worker_observer::finish()
            }))
        } else {
            None
        };
        let collect_us = micros(collect.elapsed());
        Ok((result?, entered, Instant::now(), detail, collect_us))
    };
    let ((result, entered, finished, detail, collect_us), admitted) = pool
        .run_observed(matches!(mode, Mode::Owned), deadline, measured)
        .await?;
    let returned = Instant::now();
    Ok((
        result,
        HostPhaseSpan {
            jobs: NonZeroU32::MIN,
            queue_us: micros(entered.duration_since(queued)),
            work_us: micros(finished.duration_since(entered)),
            resume_us: micros(returned.duration_since(finished)),
            semaphore_us: micros(admitted.duration_since(queued)),
            dispatch_us: micros(entered.duration_since(admitted)),
            observer_collect_us: collect_us,
            detail,
        },
    ))
}
