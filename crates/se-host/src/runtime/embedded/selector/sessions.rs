use super::*;
use sha2::{Digest, Sha256};

const HOST_PAGES: usize = 64;
const SNAPSHOT_BYTES: u64 = 1024 * 1024;

impl EmbeddedHost {
    pub(in super::super) async fn selector_sessions(
        &self,
        selected: api::ProjectId,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> Result<api::Read<api::Page<api::ActiveSession>>> {
        paging::validate(&page)?;
        id(&selected.0)?;
        let selected_id =
            se_types::ProjectId::from_linked(selected.clone()).map_err(|_| invalid())?;
        let (router, deadline, _cancel) = self.selector_ready(&options).await?;
        let catalog = store::read(
            &router,
            binding::owner_scope(&router, selected_id.clone()),
            &deadline,
            move |read| {
                Ok((|| -> Result<_> {
                    if !project(read, &selected_id)? {
                        return Ok(None);
                    }
                    let info = read.info();
                    Ok(Some((
                        info.id.as_str().to_owned(),
                        info.incarnation,
                        read.selector_revision().map_err(store_error)?,
                    )))
                })())
            },
        )
        .await
        .map_err(bridge_error)??;
        let Some(catalog) = catalog else {
            return Ok(unknown());
        };
        let (epoch, services) = self
            .native
            .lock()
            .map_err(|_| invalid())?
            .clone()
            .ok_or_else(|| {
                error(
                    api::ApiFailure::Unavailable,
                    "selector-host-unavailable",
                    "No native host session service is registered.",
                )
            })?;
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
            let observation = super::super::super::pool::within(&deadline, call)
                .await
                .map_err(bridge_error)?;
            let observed = match observation {
                Ok(api::Read::Present { value }) => value,
                Ok(api::Read::Unreadable { .. }) => {
                    unreadable += 1;
                    reason = Some(api::OmissionReason::Unreadable);
                    break;
                }
                Err(e) if e.kind == api::ApiFailure::Conflict => return Err(stale()),
                Err(e) if e.kind == api::ApiFailure::Unreadable => {
                    unreadable += 1;
                    reason = Some(api::OmissionReason::Unreadable);
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
                    reason = Some(api::OmissionReason::SourceIncomplete);
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
                        reason = Some(api::OmissionReason::Budget);
                        break;
                    }
                    rows.push(row);
                }
            }
            if reason.is_some() {
                break;
            }
            unreadable += observed.window.unreadable;
            if observed.window.unreadable > 0
                || !matches!(observed.window.omitted_before, api::Omission::None)
            {
                reason = Some(api::OmissionReason::Unreadable);
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
                reason = Some(api::OmissionReason::Budget);
            }
        }
        rows.sort_by_key(key);
        let mut digest = Sha256::new();
        digest.update(
            serde_json::to_vec(&serde_json::json!([
                "selector-sessions-v1",
                catalog,
                options.generation.0,
                selected.0,
                epoch_value(&epoch)?,
                omission_tag(reason),
                unreadable
            ]))
            .map_err(|_| invalid())?,
        );
        for row in &rows {
            digest.update(serde_json::to_vec(&row_value(row)?).map_err(|_| invalid())?);
        }
        let fingerprint = format!("{:x}", digest.finalize());
        let offset = decode(&page, &fingerprint)?;
        if offset > rows.len() {
            return Err(stale());
        }
        let mut bytes = 0;
        let mut items = Vec::new();
        let mut stop = api::StopReason::Exhausted;
        for row in rows.iter().skip(offset) {
            if items.len() >= page.limit as usize {
                stop = api::StopReason::ItemLimit;
                break;
            }
            let cost = cost(row)?;
            if bytes + cost > u64::from(page.max_bytes) {
                if items.is_empty() {
                    return Err(error(
                        api::ApiFailure::Incomplete,
                        "selector-row-too-large",
                        "The first session row exceeds max_bytes; increase the byte budget.",
                    ));
                }
                stop = api::StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            items.push(row.clone());
        }
        let end = offset + items.len();
        let more = end < rows.len();
        let cursor = api::Cursor(format!("s1.{end}.{fingerprint}"));
        let incomplete = reason.is_some();
        let omitted_after = if let Some(reason) = reason {
            api::Omission::Unknown { reason }
        } else if more {
            api::Omission::Known {
                count: (rows.len() - end) as u64,
                reason: if stop == api::StopReason::ByteLimit {
                    api::OmissionReason::Budget
                } else {
                    api::OmissionReason::Limit
                },
            }
        } else {
            api::Omission::None
        };
        if !more && incomplete {
            stop = if reason == Some(api::OmissionReason::Unreadable) {
                api::StopReason::Unreadable
            } else {
                api::StopReason::Unsupported
            };
        }
        Ok(api::Read::Present {
            value: api::Page {
                window: api::Window {
                    source: api::Source::Host { epoch },
                    start_cursor: page.after,
                    end_cursor: Some(cursor.clone()),
                    returned: items.len() as u64,
                    limit: page.limit,
                    bytes,
                    max_bytes: page.max_bytes,
                    omitted_before: api::Omission::None,
                    omitted_after,
                    unreadable,
                    stop_reason: stop,
                    complete: !more && !incomplete,
                },
                items,
                next: more.then_some(cursor),
            },
        })
    }
}
// Every row has the single registered epoch, checked above. Thus sorting
// (agent, session, host session) is exactly the requested order with that
// constant epoch component between session and host session.
fn key(row: &api::ActiveSession) -> (String, String, String) {
    (
        row.target.binding.agent.0.clone(),
        row.target.binding.session.0.clone(),
        row.target.session.0.clone(),
    )
}
fn omission_tag(reason: Option<api::OmissionReason>) -> &'static str {
    match reason {
        None => "none",
        Some(api::OmissionReason::Limit) => "limit",
        Some(api::OmissionReason::Budget) => "budget",
        Some(api::OmissionReason::Unreadable) => "unreadable",
        Some(api::OmissionReason::SourceIncomplete) => "source-incomplete",
    }
}
fn epoch_value(epoch: &api::HostEpoch) -> Result<serde_json::Value> {
    let started = match epoch.owner.started {
        api::StartIdentity::Linux { start_ticks } => serde_json::json!({"linux":start_ticks}),
        api::StartIdentity::Windows { creation_filetime } => {
            serde_json::json!({"windows":creation_filetime})
        }
        api::StartIdentity::Macos {
            start_seconds,
            start_micros,
        } => serde_json::json!({"macos":[start_seconds,start_micros]}),
    };
    let executable =
        se_types::NativePath::from_local(epoch.owner.executable.clone()).map_err(|_| invalid())?;
    Ok(
        serde_json::json!({"owner":{"machine":epoch.owner.machine,"boot":epoch.owner.boot,"pid":epoch.owner.pid,"started":started,"executable":executable,"argv_sha256":epoch.owner.argv_sha256.0},"generation":epoch.generation.0}),
    )
}
fn row_value(row: &api::ActiveSession) -> Result<serde_json::Value> {
    let activity = match row.activity {
        api::SessionActivity::Idle => "idle",
        api::SessionActivity::Executing => "executing",
        api::SessionActivity::Interrupting => "interrupting",
    };
    Ok(
        serde_json::json!({"target":{"epoch":epoch_value(&row.target.epoch)?,"session":row.target.session.0,"binding":{"project":row.target.binding.project.0,"agent":row.target.binding.agent.0,"session":row.target.binding.session.0},"binding_fingerprint":row.target.binding_fingerprint.0},"activity":activity}),
    )
}
fn validate(row: &api::ActiveSession) -> Result<()> {
    for value in [
        &row.target.binding.project.0,
        &row.target.binding.agent.0,
        &row.target.binding.session.0,
        &row.target.session.0,
        &row.target.epoch.owner.machine,
        &row.target.epoch.owner.boot,
    ] {
        id(value)?;
    }
    if row
        .target
        .epoch
        .owner
        .executable
        .as_os_str()
        .as_encoded_bytes()
        .len()
        > 32768
    {
        return Err(invalid());
    }
    Ok(())
}
fn cost(row: &api::ActiveSession) -> Result<u64> {
    paging::cost(row_value(row)?)
}
fn decode(page: &api::PageRequest, digest: &str) -> Result<usize> {
    let Some(cursor) = &page.after else {
        return Ok(0);
    };
    let parts = cursor.0.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "s1" {
        return Err(paging::usage());
    }
    if parts[2] != digest {
        return Err(stale());
    }
    parts[1].parse().map_err(|_| paging::usage())
}
