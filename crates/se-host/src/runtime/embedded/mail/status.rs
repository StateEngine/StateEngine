//! Read-only native eligibility/status for issued bindings, with bounded pages.
use super::*;
use sha2::{Digest, Sha256};

fn inventory_prefix(generation: api::Generation, bindings: &[binding::Binding]) -> String {
    let mut digest = Sha256::new();
    for binding in bindings {
        for value in [
            &binding.identity.project.0,
            &binding.identity.agent.0,
            &binding.identity.session.0,
        ] {
            digest.update((value.len() as u64).to_le_bytes());
            digest.update(value.as_bytes());
        }
    }
    format!(
        "native-adoptions:{}:{}:",
        generation.0,
        se_types::hex_lower(&digest.finalize())
    )
}

#[allow(
    clippy::result_large_err,
    reason = "The linked API defines the public ApiError representation; retain its typed error channel."
)]
fn parse_adoption_cursor(
    after: Option<&api::Cursor>,
    prefix: &str,
    len: usize,
) -> api::Result<usize> {
    match after {
        Some(cursor) => cursor
            .0
            .strip_prefix(prefix)
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|index| *index <= len)
            .ok_or_else(|| {
                support::refused(
                    "adoption cursor",
                    "the same generation and unchanged issued binding inventory",
                )
            }),
        None => Ok(0),
    }
}

fn adoption_omission(
    exhausted: bool,
    complete: bool,
    unreadable: u64,
    remaining: u64,
    stop: api::StopReason,
) -> api::Omission {
    if unreadable > 0 {
        if exhausted {
            api::Omission::Known {
                count: unreadable,
                reason: api::OmissionReason::Unreadable,
            }
        } else {
            api::Omission::Unknown {
                reason: api::OmissionReason::Unreadable,
            }
        }
    } else if complete {
        api::Omission::None
    } else {
        api::Omission::Known {
            count: remaining,
            reason: if stop == api::StopReason::ItemLimit {
                api::OmissionReason::Limit
            } else {
                api::OmissionReason::Budget
            },
        }
    }
}

struct AdoptionPageSummary {
    epoch: api::HostEpoch,
    request: api::PageRequest,
    prefix: String,
    end: usize,
    total: usize,
    bytes: u64,
    unreadable: u64,
    stop: api::StopReason,
    items: Vec<api::Adoption>,
}

fn build_adoption_page(summary: AdoptionPageSummary) -> api::Page<api::Adoption> {
    let exhausted = summary.end == summary.total;
    let complete = exhausted && summary.unreadable == 0;
    let cursor = api::Cursor(format!("{}{}", summary.prefix, summary.end));
    api::Page {
        window: api::Window {
            source: api::Source::Host {
                epoch: summary.epoch,
            },
            start_cursor: summary.request.after,
            end_cursor: Some(cursor.clone()),
            returned: summary.items.len() as u64,
            limit: summary.request.limit,
            bytes: summary.bytes,
            max_bytes: summary.request.max_bytes,
            omitted_before: api::Omission::None,
            omitted_after: adoption_omission(
                exhausted,
                complete,
                summary.unreadable,
                (summary.total - summary.end) as u64,
                summary.stop,
            ),
            unreadable: summary.unreadable,
            stop_reason: summary.stop,
            complete,
        },
        items: summary.items,
        next: if exhausted { None } else { Some(cursor) },
    }
}

impl Generation {
    async fn resolve_adoption_state(
        &self,
        services: &Arc<dyn api::HostServices>,
        entry: Option<(&api::HostSessionTarget, Option<&api::ApiError>)>,
        options: &api::CallOptions,
        deadline: &crate::client::lease::Deadline,
    ) -> api::Result<api::AdoptionState> {
        let Some((target, last_error)) = entry else {
            return Ok(api::AdoptionState::Pending);
        };
        let state = match services
            .binding_state(target, self.service_options(options, deadline)?)
            .await
        {
            Ok(api::Read::Present { value }) => match value.status {
                api::TargetStatus::Eligible => {
                    if let Some(error) = last_error {
                        api::AdoptionState::Unreadable(error.clone())
                    } else {
                        api::AdoptionState::Reattached
                    }
                }
                api::TargetStatus::Held => api::AdoptionState::Held,
                api::TargetStatus::Revoked => api::AdoptionState::Revoked,
            },
            Ok(api::Read::Absent { .. }) => api::AdoptionState::Absent,
            Ok(other) => api::AdoptionState::Unreadable(read_error("native adoption", other)),
            Err(error) => api::AdoptionState::Unreadable(error),
        };
        Ok(state)
    }

    pub(in crate::runtime::embedded) async fn native_adoptions(
        &self,
        request: api::PageRequest,
        options: api::CallOptions,
    ) -> api::Result<api::Page<api::Adoption>> {
        if !self.negotiated.features.contains(&api::Feature::NativeMail) {
            return Err(support::unavailable("NativeMail was not negotiated"));
        }
        let (_router, deadline, _cancel) = self
            .ready(&options)
            .await
            .map_err(|e| support::api_error(&e))?;
        if !(1..=self.negotiated.limits.page_items.get().min(100)).contains(&request.limit)
            || !(1..=self.negotiated.limits.payload_bytes.get().min(65536))
                .contains(&request.max_bytes)
        {
            return Err(support::refused(
                "adoption page",
                "1..100 items and 1..65536 bytes",
            ));
        }
        let bindings = self
            .bindings
            .inventory()
            .map_err(|e| support::api_error(&e))?;
        let entries = self
            .mail
            .entries
            .lock()
            .map_err(|_| support::api_error(&registry_error()))?
            .clone();
        let prefix = inventory_prefix(options.generation, &bindings);
        let after = parse_adoption_cursor(request.after.as_ref(), &prefix, bindings.len())?;
        let (epoch, services) = self.services()?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut unreadable = 0;
        let mut end = after;
        let mut stop = api::StopReason::Exhausted;
        for binding in bindings.iter().skip(after) {
            deadline.remaining().map_err(|e| support::api_error(&e))?;
            if items.len() == request.limit as usize {
                stop = api::StopReason::ItemLimit;
                break;
            }
            let entry = entries
                .get(&binding.identity.session.0)
                .map(|entry| (&entry.target, entry.error.as_ref()));
            let state = self
                .resolve_adoption_state(&services, entry, &options, &deadline)
                .await?;
            let row = api::Adoption {
                identity: binding.identity.clone(),
                binding_revision: revision(),
                state,
            };
            // Conservative bound for escaped display data, including a native
            // refusal's remedy. No record bodies or protected grants occur here.
            let cost = (format!("{row:?}").len() as u64)
                .saturating_mul(6)
                .saturating_add(128);
            if bytes + cost > u64::from(request.max_bytes) {
                if items.is_empty() {
                    return Err(support::refused(
                        "adoption bytes",
                        &format!("at least {cost} bytes for the first complete row"),
                    ));
                }
                stop = api::StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            if matches!(row.state, api::AdoptionState::Unreadable(_)) {
                unreadable += 1;
            }
            end += 1;
            items.push(row);
        }
        deadline.remaining().map_err(|e| support::api_error(&e))?;
        Ok(build_adoption_page(AdoptionPageSummary {
            epoch,
            request,
            prefix,
            end,
            total: bindings.len(),
            bytes,
            unreadable,
            stop,
            items,
        }))
    }
}
