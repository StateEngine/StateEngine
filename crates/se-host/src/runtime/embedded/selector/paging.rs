use super::*;
use crate::linked::ToLinked;
use se_types::Page as StorePage;
use std::num::NonZeroU32;

pub(super) fn usage() -> Box<api::ApiError> {
    error(
        api::ApiFailure::Usage,
        "selector-invalid-page",
        "Selectors require 1..=100 rows, 1..=65536 bytes and a cursor of at most 256 UTF-8 bytes.",
    )
}
pub(super) fn validate(page: &api::PageRequest) -> Result<()> {
    if !(1..=100).contains(&page.limit)
        || !(1..=65536).contains(&page.max_bytes)
        || page.after.as_ref().is_some_and(|v| v.0.len() > 256)
    {
        Err(usage())
    } else {
        Ok(())
    }
}
pub(super) fn budget(
    page: &api::PageRequest,
    limit: u32,
    deadline: &crate::client::lease::Deadline,
) -> Result<se_store::ReadBudget> {
    Ok(se_store::ReadBudget {
        page: se_types::PageRequest {
            after: page
                .after
                .clone()
                .map(se_types::Cursor::from_linked)
                .transpose()
                .map_err(|_| usage())?,
            limit: NonZeroU32::new(limit).ok_or_else(usage)?,
            // The store accounts immutable event metadata; the adapter accounts
            // the smaller selector rows separately, without truncating text.
            max_bytes: NonZeroU32::MIN.saturating_add(2 * 1024 * 1024 - 1),
        },
        deadline: deadline
            .remaining()
            .map_err(bridge_error)?
            .min(Duration::from_secs(5)),
    })
}
/// Byte accounting is the compact JSON of display fields (native path encoded
/// losslessly). It includes escaped text rather than counting Unicode scalars.
pub(super) fn cost(value: serde_json::Value) -> Result<u64> {
    serde_json::to_vec(&value)
        .map(|v| v.len() as u64)
        .map_err(|_| invalid())
}
pub(super) fn finish<T>(
    source: &StorePage<se_store::ProjectionRecord>,
    items: Vec<T>,
    bytes: u64,
    request: &api::PageRequest,
) -> Result<api::Read<api::Page<T>>> {
    let mut window = crate::linked::window(source.window()).map_err(bridge_error)?;
    window.limit = request.limit;
    window.max_bytes = request.max_bytes;
    window.bytes = bytes;
    if source
        .window()
        .fields()
        .is_some_and(|w| w.limit.get() < request.limit)
        && !window.complete
    {
        window.stop_reason = api::StopReason::ByteLimit;
        window.omitted_after = api::Omission::Unknown {
            reason: api::OmissionReason::Budget,
        };
    }
    Ok(api::Read::Present {
        value: api::Page {
            items,
            next: source.next().map(ToLinked::to_linked),
            window,
        },
    })
}
