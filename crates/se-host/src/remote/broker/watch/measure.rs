//! An unsynchronized monotonic estimate includes buffered pages, not clock drift or suspend.
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
    // Sample before calculating age: the terminal includes all subsequent
    // work, IPC, rendering and flush without charging an earlier long poll.
    clock.source_released_at_us = Some(se_proc::monotonic_micros().map_err(|cause| {
        refused(&format!(
            "native observation clock unavailable: {cause}; timing is unqualified"
        ))
    })?);
    let elapsed = i128::from(micros(bracket.opened_at.elapsed())?);
    for record in &mut page.records {
        if let RemoteWatchRecord::Provisional { observation, .. } = record {
            let observation = observation.as_mut().ok_or_else(|| {
                refused("the peer omitted this item's observation time; timing is unqualified")
            })?;
            // This assumes comparable clock rates over this subscription. It
            // is an estimate only: drift and independent suspend are unbounded.
            let since_sample = i128::from(observation.at_us) - i128::from(bracket.host_us);
            // Round away the two host stamps; this is not a drift allowance.
            let age = elapsed - since_sample + 2;
            observation.age_estimate_us = u64::try_from(age).ok();
        }
    }
    Ok(())
}
fn micros(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_micros().saturating_add(1))
        .map_err(|_| refused("observation clock interval exceeds its representable bound"))
}
