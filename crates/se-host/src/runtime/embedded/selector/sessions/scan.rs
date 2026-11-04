//! Bounded native observations, preserving every source-loss signal.
use super::*;
const HOST_PAGES: usize = 64;
const SNAPSHOT_BYTES: u64 = 1024 * 1024;
pub(super) async fn sessions(
    deadline: &crate::client::lease::Deadline,
    options: &api::CallOptions,
    selected: api::ProjectId,
    epoch: api::HostEpoch,
    services: std::sync::Arc<dyn api::HostServices>,
) -> Result<Observation> {
    let mut rows = Vec::new();
    let mut source_cursor = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut reason = None;
    let mut unreadable = 0;
    let mut retained_bytes = 0;
    for index in 0..HOST_PAGES {
        let request = api::PageRequest {
            after: source_cursor.clone(),
            limit: 100,
            max_bytes: 65536,
        };
        let call = services.active_sessions(
            &epoch,
            request,
            api::ServiceOptions {
                generation: options.generation,
                timeout: deadline.remaining().map_err(bridge_error)?,
                cancellation: options.cancellation.clone(),
            },
        );
        let observation = crate::runtime::pool::within(deadline, call)
            .await
            .map_err(bridge_error)?;
        let observed = match observation {
            Ok(api::Read::Present { value }) => value,
            Ok(api::Read::Unreadable { .. }) => {
                unreadable += 1;
                remember(&mut reason, api::OmissionReason::Unreadable);
                break;
            }
            Err(e) if e.kind == api::ApiFailure::Conflict => return Err(stale()),
            Err(e) if e.kind == api::ApiFailure::Unreadable => {
                unreadable += 1;
                remember(&mut reason, api::OmissionReason::Unreadable);
                break;
            }
            Err(e) if e.kind == api::ApiFailure::Cancelled => {
                return Err(error(
                    api::ApiFailure::Cancelled,
                    "selector-cancelled",
                    "The selector read was cancelled.",
                ));
            }
            Ok(api::Read::Absent { .. } | api::Read::Unknown { .. }) | Err(_) => {
                remember(&mut reason, api::OmissionReason::SourceIncomplete);
                break;
            }
        };
        if observed.items.len() > 100
            || observed.window.bytes > 65536
            || observed.window.returned != observed.items.len() as u64
            || !matches!(&observed.window.source, api::Source::Host { epoch: source } if source == &epoch)
        {
            return Err(invalid());
        }
        let mut host_bytes = 0;
        for row in observed.items {
            validate(&row)?;
            if row.target.epoch != epoch {
                return Err(invalid());
            }
            let cost = cost(&row)?;
            host_bytes += cost;
            if host_bytes > 65536 {
                return Err(invalid());
            }
            if row.target.binding.project == selected {
                if !seen.insert(key(&row)) {
                    return Err(invalid());
                }
                retained_bytes += cost;
                if retained_bytes > SNAPSHOT_BYTES {
                    remember(&mut reason, api::OmissionReason::Budget);
                    break;
                }
                rows.push(row);
            }
        }
        unreadable += observed.window.unreadable;
        if observed.window.unreadable > 0 {
            remember(&mut reason, api::OmissionReason::Unreadable);
        }
        // Limit/Budget omissions with a continuation are ordinary paging.
        // Source loss survives even when a later page exhausts its own rows.
        for omission in [
            &observed.window.omitted_before,
            &observed.window.omitted_after,
        ] {
            match omission {
                api::Omission::Known { reason: issue, .. }
                | api::Omission::Unknown { reason: issue }
                    if matches!(
                        issue,
                        api::OmissionReason::Unreadable | api::OmissionReason::SourceIncomplete
                    ) =>
                {
                    remember(&mut reason, *issue)
                }
                _ => (),
            }
        }
        if retained_bytes > SNAPSHOT_BYTES {
            break;
        }
        match observed.next {
            Some(next) if next.0.len() <= 256 && Some(&next) != source_cursor.as_ref() => {
                source_cursor = Some(next)
            }
            Some(_) => return Err(invalid()),
            None => {
                if !observed.window.complete {
                    reason.get_or_insert(api::OmissionReason::SourceIncomplete);
                }
                break;
            }
        }
        if index + 1 == HOST_PAGES {
            remember(&mut reason, api::OmissionReason::Budget);
        }
    }
    Ok(Observation {
        rows,
        epoch,
        reason,
        unreadable,
    })
}
