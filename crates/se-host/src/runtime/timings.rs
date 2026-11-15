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
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_micros());
        let result = work();
        let finished = Instant::now();
        eprintln!(
            "blocking-native-timing {}",
            serde_json::json!({
                "pid":std::process::id(),"thread":format!("{:?}",std::thread::current().id()),
                "start_us":wall,"end_us":wall.map(|s|s+finished.duration_since(entered).as_micros()),
                "elapsed_us":finished.duration_since(entered).as_micros(),"ok":result.is_ok()
            })
        );
        result.map(|result| (result, entered, finished))
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
