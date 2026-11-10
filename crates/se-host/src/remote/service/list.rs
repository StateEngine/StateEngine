//! Bounded metadata pages; cursor positions are authorized targets, not floor counts.
use super::*;
use se_types::{
    Omission, OmissionReason, Page, Sequence, Source, StopReason, Window, WindowFields,
};
use std::num::NonZeroU32;
pub(super) fn page(
    service: &Service,
    request: &view_request::ViewRequest,
    input: &RemoteList,
) -> Result<RemoteListResult> {
    let after: Option<RemoteTarget> = input
        .cursor
        .as_ref()
        .map(|cursor| service.cursors.decoded(request, None, "list", cursor))
        .transpose()?;
    let mut views = service.store.target_page(
        request,
        after.as_ref(),
        input.limit + 1,
        std::time::Instant::now() + Duration::from_secs(10),
    )?;
    views.sort_by(|a, b| a.target.cmp(&b.target));
    let mut views: Vec<_> = views
        .into_iter()
        .filter(|view| after.as_ref().is_none_or(|after| view.target > *after))
        .collect();
    let count = views.len();
    views.truncate(usize::from(input.limit));
    loop {
        let remaining = count - views.len();
        let next = if remaining > 0 {
            Some(
                service.cursors.json(
                    request,
                    None,
                    "list",
                    &views
                        .last()
                        .ok_or_else(|| {
                            SeError::too_large(
                                "remote metadata row",
                                input.budget as usize,
                                input.budget as usize + 1,
                            )
                        })?
                        .target,
                )?,
            )
        } else {
            None
        };
        let omitted = if remaining == 0 {
            Omission::None
        } else {
            Omission::Unknown {
                reason: if views.len() == usize::from(input.limit) {
                    OmissionReason::Limit
                } else {
                    OmissionReason::Budget
                },
            }
        };
        let window = Window::new(WindowFields {
            source: Source::Store {
                store: service.store.info.id.clone(),
                project: None,
            },
            from: Sequence::new(0)?,
            to: Sequence::new(views.len() as u64)?,
            start_cursor: input.cursor.clone(),
            end_cursor: next.clone(),
            returned: views.len() as u64,
            limit: NonZeroU32::new(u32::from(input.limit))
                .ok_or_else(|| SeError::invalid("metadata limit", "nonzero"))?,
            bytes: 0,
            max_bytes: NonZeroU32::new(input.budget)
                .ok_or_else(|| SeError::invalid("metadata budget", "nonzero"))?,
            omitted_before: Omission::None,
            omitted_after: omitted,
            unreadable: 0,
            stop_reason: if remaining == 0 {
                StopReason::Exhausted
            } else if views.len() == usize::from(input.limit) {
                StopReason::ItemLimit
            } else {
                StopReason::ByteLimit
            },
        })?;
        let result = RemoteListResult {
            schema: RemoteListResult::SCHEMA.into(),
            body: RemoteListBody {
                agents: Page::new(views.clone(), window, next)?,
            },
        };
        let bytes = wire::encode(&result, wire::Phase::Authenticated)?.len();
        if bytes <= input.budget as usize {
            return Ok(result);
        }
        if views.is_empty() {
            return Err(SeError::too_large(
                "remote metadata page",
                input.budget as usize,
                bytes,
            ));
        }
        views.pop();
    }
}
