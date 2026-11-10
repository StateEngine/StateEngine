//! A monotonic clock bracket includes buffered pages without synchronized clocks.
use super::*;

pub(super) struct Bracket {
    epoch: [u8; 16],
    host_us: i64,
    opened_at: Instant,
    width_us: u64,
}

pub(super) fn release(
    saved: &mut Option<Bracket>,
    opened_at: Instant,
    page: &mut RemoteWatchBatch,
) -> Result<()> {
    let Some(clock) = &mut page.observation_clock else {
        if page
            .records
            .iter()
            .any(|record| matches!(record, RemoteWatchRecord::Provisional { .. }))
        {
            return Err(refused(
                "this peer did not supply the requested observation clock; timing is unqualified",
            ));
        }
        return Ok(());
    };
    if saved
        .as_ref()
        .is_none_or(|saved| saved.epoch != clock.epoch)
    {
        *saved = Some(Bracket {
            epoch: clock.epoch,
            host_us: clock.sampled_at_us,
            opened_at,
            width_us: micros(opened_at.elapsed())?,
        });
    }
    let bracket = saved.as_ref().ok_or_else(poisoned)?;
    clock.source_bracket_us = Some(bracket.width_us);
    let elapsed = i128::from(micros(bracket.opened_at.elapsed())?);
    for record in &mut page.records {
        if let RemoteWatchRecord::Provisional { observation, .. } = record {
            let observation = observation.as_mut().ok_or_else(|| {
                refused("the peer omitted this item's observation time; timing is unqualified")
            })?;
            // Request start is no later than the host clock sample. Translating
            // a producer stamp using that lower offset estimates an origin no
            // later than reality, even if the page waited in a stream queue.
            let since_sample = i128::from(observation.at_us) - i128::from(bracket.host_us);
            // Two microseconds cover the two rounded host stamps. This is an
            // upper bound, so quantization must never make it optimistic.
            let age = elapsed - since_sample + 2;
            observation.age_upper_bound_us = Some(u64::try_from(age).map_err(|_| refused(
                "the peer's monotonic observation interval is inconsistent; timing is unqualified"))?);
        }
    }
    Ok(())
}
fn micros(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_micros().saturating_add(1))
        .map_err(|_| refused("observation clock interval exceeds its representable bound"))
}
