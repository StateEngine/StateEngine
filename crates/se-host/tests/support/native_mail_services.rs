//! Native queue lives on the callback side of the actual linked Host boundary.
use secode_stateengine_api as api;
use std::sync::Mutex;
pub struct Services(pub Mutex<State>);
pub struct State {
    pub target: Option<api::HostSessionTarget>,
    pub status: api::TargetStatus,
    pub calls: usize,
    pub observations: usize,
    pub admissions: Vec<api::Admission>,
    pub messages: Vec<Vec<api::MessageId>>,
    pub lose_reply: bool,
}
impl Services {
    pub fn new() -> Self {
        Self(Mutex::new(State {
            target: None,
            status: api::TargetStatus::Eligible,
            calls: 0,
            observations: 0,
            admissions: vec![],
            messages: vec![],
            lose_reply: true,
        }))
    }
}
fn services_refused() -> api::ApiError {
    api::ApiError {
        kind: api::ApiFailure::Unknown,
        code: "fixture-lost-reply".into(),
        message: "native callback has no reply".into(),
        remedy: api::ApiRemedy {
            text: "query the original notice".into(),
            command: None,
        },
        retry: api::ApiRetry::AfterRefresh,
    }
}
fn event() -> api::HostEventRef {
    api::HostEventRef {
        id: api::HostEventId("native-event-1".into()),
        sequence: std::num::NonZeroU64::MIN,
    }
}
impl api::HostServices for Services {
    fn hold<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        _reason: api::HoldReason,
        key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::HoldReceipt> {
        Box::pin(async move {
            let mut s = self.0.lock().map_err(|_| services_refused())?;
            if s.target.as_ref() != Some(target) {
                return Err(services_refused());
            }
            if s.status != api::TargetStatus::Revoked {
                s.status = api::TargetStatus::Held;
            }
            Ok(api::HoldReceipt {
                target: target.clone(),
                committed: event(),
                retained_pending: s.admissions.len() as u64,
                idempotency_key: key,
            })
        })
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
        _epoch: &'a api::HostEpoch,
        _page: api::PageRequest,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async { Err(services_refused()) })
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
        target: &'a api::HostSessionTarget,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async move {
            let mut s = self.0.lock().map_err(|_| services_refused())?;
            s.observations += 1;
            if s.target.as_ref() != Some(target) {
                return Ok(api::Read::Absent {
                    checked: "not selected".into(),
                });
            }
            Ok(api::Read::Present {
                value: api::BindingObservation {
                    target: target.clone(),
                    status: s.status.clone(),
                    last_transition: event(),
                    activity: api::Read::Present {
                        value: api::SessionActivity::Idle,
                    },
                },
            })
        })
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
        transition: api::TargetTransition,
        _key: api::IdempotencyKey,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::TargetReceipt> {
        Box::pin(async move {
            let mut s = self.0.lock().map_err(|_| services_refused())?;
            let (target, status) = match transition {
                api::TargetTransition::Select { target, .. } => {
                    (target, api::TargetStatus::Eligible)
                }
                api::TargetTransition::Revoke { target } => (target, api::TargetStatus::Revoked),
            };
            s.target = Some(target.clone());
            s.status = status.clone();
            Ok(api::TargetReceipt {
                target,
                status,
                committed: event(),
            })
        })
    }
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a api::MailNotice,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::NoticeAdmission> {
        Box::pin(async move {
            let mut s = self.0.lock().map_err(|_| services_refused())?;
            if s.target.as_ref() != Some(&notice.target) || s.status != api::TargetStatus::Eligible
            {
                return Err(services_refused());
            }
            s.calls += 1;
            let a = api::Admission {
                committed_in: notice.target.epoch.clone(),
                notice: notice.id.clone(),
                target: notice.target.clone(),
                pending: api::HostPendingId("native-pending-1".into()),
                admitted_sequence: std::num::NonZeroU64::MIN,
                dedupe_sha256: notice.dedupe_sha256,
                committed: event(),
            };
            s.admissions.push(a.clone());
            s.messages.push(notice.messages.clone());
            if s.lose_reply {
                s.lose_reply = false;
                return Err(services_refused());
            }
            Ok(api::NoticeAdmission::Admitted(a))
        })
    }
    fn notice_status<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        id: &'a api::NoticeId,
        _options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::NoticeAdmission>> {
        Box::pin(async move {
            let s = self.0.lock().map_err(|_| services_refused())?;
            Ok(match s.admissions.iter().find(|a| &a.notice == id) {
                Some(a) => api::Read::Present {
                    value: api::NoticeAdmission::Replayed(a.clone()),
                },
                None => api::Read::Absent {
                    checked: "native queue has no such notice".into(),
                },
            })
        })
    }
}
