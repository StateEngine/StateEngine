//! Read-only native eligibility/status for issued bindings, with bounded pages.
use super::*;
use sha2::{Digest, Sha256};

impl Generation {
    pub(in crate::runtime::embedded) async fn native_adoptions(
        &self,
        request: api::PageRequest,
        options: api::CallOptions,
    ) -> api::Result<api::Page<api::Adoption>> {
        let (_router, deadline, _cancel) = self
            .ready(&options)
            .await
            .map_err(|e| support::api_error(&e))?;
        if !(1..=100).contains(&request.limit) || !(1..=65536).contains(&request.max_bytes) {
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
        let mut digest = Sha256::new();
        for binding in &bindings {
            for value in [
                &binding.identity.project.0,
                &binding.identity.agent.0,
                &binding.identity.session.0,
            ] {
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value.as_bytes());
            }
        }
        let prefix = format!(
            "native-adoptions:{}:{}:",
            options.generation.0,
            se_types::hex_lower(&digest.finalize())
        );
        let after = match &request.after {
            Some(cursor) => cursor
                .0
                .strip_prefix(&prefix)
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|index| *index <= bindings.len())
                .ok_or_else(|| {
                    support::refused(
                        "adoption cursor",
                        "the same generation and unchanged issued binding inventory",
                    )
                })?,
            None => 0,
        };
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
            let state = if let Some(entry) = entries.get(&binding.identity.session.0) {
                match services
                    .binding_state(&entry.target, self.service_options(&options, &deadline)?)
                    .await
                {
                    Ok(api::Read::Present { value }) => match value.status {
                        api::TargetStatus::Eligible => {
                            if let Some(error) = &entry.error {
                                api::AdoptionState::Unreadable(error.clone())
                            } else {
                                api::AdoptionState::Reattached
                            }
                        }
                        api::TargetStatus::Held => api::AdoptionState::Held,
                        api::TargetStatus::Revoked => api::AdoptionState::Revoked,
                    },
                    Ok(api::Read::Absent { .. }) => api::AdoptionState::Absent,
                    Ok(other) => {
                        api::AdoptionState::Unreadable(read_error("native adoption", other))
                    }
                    Err(error) => api::AdoptionState::Unreadable(error),
                }
            } else {
                api::AdoptionState::Pending
            };
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
        let exhausted = end == bindings.len();
        let complete = exhausted && unreadable == 0;
        let cursor = api::Cursor(format!("{prefix}{end}"));
        Ok(api::Page {
            window: api::Window {
                source: api::Source::Host { epoch },
                start_cursor: request.after,
                end_cursor: Some(cursor.clone()),
                returned: items.len() as u64,
                limit: request.limit,
                bytes,
                max_bytes: request.max_bytes,
                omitted_before: api::Omission::None,
                omitted_after: if unreadable > 0 {
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
                        count: (bindings.len() - end) as u64,
                        reason: if stop == api::StopReason::ItemLimit {
                            api::OmissionReason::Limit
                        } else {
                            api::OmissionReason::Budget
                        },
                    }
                },
                unreadable,
                stop_reason: stop,
                complete,
            },
            items,
            next: if exhausted { None } else { Some(cursor) },
        })
    }
}
