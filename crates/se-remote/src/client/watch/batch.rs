//! Join ordered ready pages without consuming a page that cannot be returned.
use super::*;

pub(super) fn boundary(page: &RemoteWatchBatch) -> bool {
    page.reset_required
        || page
            .records
            .iter()
            .any(|r| matches!(r, RemoteWatchRecord::Gap { .. }))
        || !matches!(
            page.omitted_records,
            Omission::None
                | Omission::Unknown {
                    reason: OmissionReason::Budget
                }
        )
}

pub(super) fn append(
    page: &mut RemoteWatchBatch,
    next: &mut RemoteWatchBatch,
    budget: u32,
) -> Result<bool> {
    // A different observation epoch or a discontinuity needs its own page.
    // Keep the earliest clock sample for the broker's age calibration.
    let same_clock = match (&page.observation_clock, &next.observation_clock) {
        (None, None) => true,
        (Some(a), Some(b)) => a.epoch == b.epoch,
        _ => false,
    };
    if boundary(next) || !same_clock {
        incomplete(page, OmissionReason::SourceIncomplete);
        return Ok(false);
    }
    let records = page.records.len();
    let cursors = page.cursors.clone();
    let complete = page.complete;
    let omitted = page.omitted_records.clone();
    page.records.append(&mut next.records);
    for cursor in &next.cursors {
        if let Some(saved) = page
            .cursors
            .iter_mut()
            .find(|saved| saved.target == cursor.target)
        {
            *saved = cursor.clone();
        } else {
            page.cursors.push(cursor.clone());
        }
    }
    page.complete = next.complete;
    page.omitted_records = next.omitted_records.clone();
    // Match the producer's allowance for the broker's timing fields and the
    // incomplete marker. Never advance a cursor across an unreturned record.
    let measured = page
        .records
        .iter()
        .filter(|r| {
            matches!(
                r,
                RemoteWatchRecord::Provisional {
                    observation: Some(_),
                    ..
                }
            )
        })
        .count();
    let size = wire::encode(page, Phase::Authenticated)?.len() + 96 + measured * 16;
    if size <= budget as usize {
        return Ok(true);
    }
    next.records = page.records.split_off(records);
    page.cursors = cursors;
    page.complete = complete;
    page.omitted_records = omitted;
    incomplete(page, OmissionReason::Budget);
    Ok(false)
}

fn incomplete(page: &mut RemoteWatchBatch, reason: OmissionReason) {
    page.complete = false;
    if matches!(page.omitted_records, Omission::None) {
        page.omitted_records = Omission::Unknown { reason };
    }
}
