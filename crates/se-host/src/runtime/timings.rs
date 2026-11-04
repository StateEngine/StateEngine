//! Same-call timing around the existing bounded jobs; no worker or authority cache.
use super::{BlockingClass, BlockingPool};
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
    let queued = Instant::now();
    let measured = move || {
        let entered = Instant::now();
        let result = work()?;
        Ok((result, entered, Instant::now()))
    };
    let (result, entered, finished) = match mode {
        Mode::Finite => {
            pool.run(BlockingClass::Foreground, deadline, measured)
                .await?
        }
        Mode::Owned => pool.run_owned(deadline, measured).await?,
    };
    let returned = Instant::now();
    Ok((
        result,
        HostPhaseSpan {
            jobs: NonZeroU32::MIN,
            queue_us: micros(entered.duration_since(queued)),
            work_us: micros(finished.duration_since(entered)),
            resume_us: micros(returned.duration_since(finished)),
        },
    ))
}
