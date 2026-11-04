//! Synchronous host diagnostic pages, including unrelated projects and failures.
#![allow(dead_code, reason = "Shared callback signature fixture")]
use secode_stateengine_api as api;
use std::sync::{Arc, atomic::AtomicBool};
pub struct Services {
    pub project: api::ProjectId,
    pub unavailable: Arc<AtomicBool>,
    pub source_incomplete: Arc<AtomicBool>,
    pub scan_cap: Arc<AtomicBool>,
}
fn services_refused() -> api::ApiError {
    api::ApiError {
        kind: api::ApiFailure::Unavailable,
        code: "fixture-unavailable".into(),
        message: "native host unavailable".into(),
        remedy: api::ApiRemedy {
            text: "retry".into(),
            command: None,
        },
        retry: api::ApiRetry::AfterRefresh,
    }
}
impl api::HostServices for Services {
    fn hold<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _reason: api::HoldReason,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::HoldReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn interrupt<'a>(
        &'a self,
        _held: &'a api::HoldReceipt,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::InterruptReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn active_session<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<Option<api::ActiveSession>>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a api::HostEpoch,
        page: api::PageRequest,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async move {
            if self.unavailable.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(services_refused());
            }
            if self.scan_cap.load(std::sync::atomic::Ordering::Relaxed) {
                let index = page
                    .after
                    .as_ref()
                    .map_or(0, |v| v.0.parse::<u32>().unwrap_or(0));
                return Ok(api::Read::Present {
                    value: api::Page {
                        items: vec![],
                        next: Some(api::Cursor((index + 1).to_string())),
                        window: api::Window {
                            source: api::Source::Host {
                                epoch: epoch.clone(),
                            },
                            start_cursor: page.after,
                            end_cursor: Some(api::Cursor((index + 1).to_string())),
                            returned: 0,
                            limit: page.limit,
                            bytes: 0,
                            max_bytes: page.max_bytes,
                            omitted_before: api::Omission::None,
                            omitted_after: api::Omission::Unknown {
                                reason: api::OmissionReason::Limit,
                            },
                            unreadable: 0,
                            stop_reason: api::StopReason::ItemLimit,
                            complete: false,
                        },
                    },
                });
            }
            let next = page.after.is_none();
            let specs = if next {
                vec![
                    ("zulu", self.project.clone()),
                    ("foreign", api::ProjectId("other-project".into())),
                ]
            } else {
                vec![("aardvark", self.project.clone())]
            };
            let items = specs
                .into_iter()
                .map(|(agent, project)| {
                    Ok(api::ActiveSession {
                        target: api::HostSessionTarget {
                            epoch: epoch.clone(),
                            session: api::HostSessionId(agent.into()),
                            binding: api::SessionIdentity {
                                project,
                                agent: api::AgentId(
                                    match agent {
                                        "aardvark" => "agt-0000-0000-0000",
                                        "zulu" => "agt-zzzz-zzzz-zzzz",
                                        _ => "agt-ffff-ffff-ffff",
                                    }
                                    .into(),
                                ),
                                session: api::SessionId(
                                    se_types::SessionId::from_parts(
                                        1_700_000_000_000,
                                        [agent.as_bytes()[0]; 10],
                                    )
                                    .map_err(|error| se_host::linked::api_error(&error))?
                                    .as_str()
                                    .into(),
                                ),
                            },
                            binding_fingerprint: api::Sha256([3; 32]),
                        },
                        activity: api::SessionActivity::Idle,
                    })
                })
                .collect::<api::Result<Vec<_>>>()?;
            Ok(api::Read::Present {
                value: api::Page {
                    window: api::Window {
                        source: api::Source::Host {
                            epoch: epoch.clone(),
                        },
                        start_cursor: page.after,
                        end_cursor: Some(api::Cursor("host-1".into())),
                        returned: items.len() as u64,
                        limit: page.limit,
                        bytes: 4096,
                        max_bytes: page.max_bytes,
                        omitted_before: api::Omission::None,
                        omitted_after: if next
                            && self
                                .source_incomplete
                                .load(std::sync::atomic::Ordering::Relaxed)
                        {
                            api::Omission::Unknown {
                                reason: api::OmissionReason::SourceIncomplete,
                            }
                        } else if next {
                            api::Omission::Known {
                                count: 1,
                                reason: api::OmissionReason::Limit,
                            }
                        } else {
                            api::Omission::None
                        },
                        unreadable: 0,
                        stop_reason: if next {
                            api::StopReason::ItemLimit
                        } else {
                            api::StopReason::Exhausted
                        },
                        complete: !next,
                    },
                    items,
                    next: next.then(|| api::Cursor("host-1".into())),
                },
            })
        })
    }
    fn idle<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::SessionActivity>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn binding_state<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn adopt_binding<'a>(
        &'a self,
        _request: api::AdoptBinding,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async { Err(services_refused()) })
    }
    fn update_mail_target<'a>(
        &'a self,
        _transition: api::TargetTransition,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::TargetReceipt> {
        Box::pin(async { Err(services_refused()) })
    }
    fn deliver_notice<'a>(
        &'a self,
        _notice: &'a api::MailNotice,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::NoticeAdmission> {
        Box::pin(async { Err(services_refused()) })
    }
    fn notice_status<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _notice: &'a api::NoticeId,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::NoticeAdmission>> {
        Box::pin(async { Err(services_refused()) })
    }
}
