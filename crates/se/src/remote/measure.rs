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
            item,
            observation,
            ..
        } = record
        {
            let upper = observation
                .as_ref()
                .and_then(|v| v.age_upper_bound_us)
                .map(|age| {
                    age.checked_add(request_us).ok_or_else(|| {
                        io::Error::other("terminal observation upper bound overflow")
                    })
                })
                .transpose()?;
            line(
                &serde_json::json!({
                    "schema":"stateengine.client-flush/v1","boundary":"provisional_flushed",
                    "target":target,"item_id":item.item_id,
                    "producer_to_flush_upper_bound_us":upper,
                    "clock_bound_available":upper.is_some(),
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
