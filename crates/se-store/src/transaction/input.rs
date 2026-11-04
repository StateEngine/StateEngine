//! Queue-resident bytes and materialized transaction bytes are distinct limits.
use super::*;
use std::cell::Cell;
pub(crate) fn batch_sizes(batch: &AtomicBatch) -> StoreResult<(usize, usize)> {
    let mut resident = 0usize;
    let mut materialized = 0usize;
    for event in &batch.events {
        let inline = Cell::new(0usize);
        let staged = Cell::new(0usize);
        let metadata = descriptor(&event.body, |text| {
            match text {
                InputText::Inline(text) => inline.set(inline.get().saturating_add(text.len())),
                InputText::Staged(text) => staged.set(staged.get().saturating_add(text.byte_length() as usize)),
            }
            Ok(String::new())
        })?.len() + 512;
        resident = resident.saturating_add(metadata).saturating_add(inline.get());
        materialized = materialized.saturating_add(metadata).saturating_add(inline.get()).saturating_add(staged.get());
    }
    if batch.events.is_empty() || batch.events.len() > 64 || materialized > 2 * 1024 * 1024 {
        return Err(fail(StoreErrorCode::BodyTooLarge, "batch exceeds 64 events or 2 MiB materialized bytes"));
    }
    Ok((resident, materialized))
}
