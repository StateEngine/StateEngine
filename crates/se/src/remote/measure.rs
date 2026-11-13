//! Observe the real shared renderer after stdout flush, not packet receipt.
use se_core::ops::RemoteWatchOutput;
use se_types::remote::RemoteWatchRecord;
use std::{
    io::{self, Write},
    time::Instant,
};

pub(super) fn flushed(
    page: &RemoteWatchOutput,
    started: Instant,
    out: &mut impl Write,
) -> io::Result<()> {
    let request_us = u64::try_from(started.elapsed().as_micros().saturating_add(1))
        .map_err(|_| io::Error::other("terminal measurement interval overflow"))?;
    let after_release = page
        .observation_clock
        .as_ref()
        .and_then(|clock| clock.source_released_at_us)
        .map(|released| {
            se_proc::monotonic_micros()?
                .checked_sub(released)
                .and_then(|elapsed| elapsed.checked_add(2))
                .ok_or_else(|| {
                    io::Error::other("native terminal observation clock is inconsistent")
                })
        })
        .transpose()?;
    let header = serde_json::json!({
        "schema":"stateengine.client-flush/v1","boundary":"stdout_flushed",
        "request_elapsed_us":request_us,"clock":page.observation_clock,
        "snapshot":page.records.iter().any(|r|matches!(r,RemoteWatchRecord::Snapshot{..})),
        "complete":page.complete,"reset_required":page.reset_required,
        "omitted_records":page.omitted_records,
    });
    line(&header, out)?;
    for record in &page.records {
        if let RemoteWatchRecord::Provisional {
            target,
            cursor,
            item,
            observation,
            ..
        } = record
        {
            let estimate = observation
                .as_ref()
                .and_then(|v| v.age_estimate_us)
                .zip(after_release)
                .map(|(age, elapsed)| {
                    age.checked_add(elapsed)
                        .ok_or_else(|| io::Error::other("terminal observation estimate overflow"))
                })
                .transpose()?;
            line(
                &serde_json::json!({
                    "schema":"stateengine.client-flush/v1","boundary":"provisional_flushed",
                    "target":target,"cursor":cursor,"item_id":item.item_id,
                    "producer_to_flush_estimate_us":estimate,
                    "clock_estimate_available":estimate.is_some(),
                    "clock_model":"unsynchronized_monotonic_estimate",
                    "qualification":"unqualified",
                }),
                out,
            )?;
        }
    }
    out.flush()
}
fn line(value: &serde_json::Value, out: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}
