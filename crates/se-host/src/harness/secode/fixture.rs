//! Async public HostServices double; native queue custody stays on this side.
#![allow(
    clippy::unwrap_used,
    reason = "assert fixture setup and poisoned test locks"
)]
use super::*;
use crate::linked::ToLinked;
use std::{future::Future, num::NonZeroU64, pin::Pin, time::Duration};
#[derive(Debug, Default)]
pub(super) struct Cancellation {
    pub(super) flag: AtomicBool,
    pub(super) wake: tokio::sync::Notify,
}
impl api::Cancellation for Cancellation {
    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {
            let mut notified = std::pin::pin!(self.wake.notified());
            notified.as_mut().enable();
            if !self.flag.load(Ordering::Acquire) {
                notified.await;
            }
        })
    }
}
pub(super) fn options() -> api::ServiceOptions {
    api::ServiceOptions {
        generation: api::Generation(7),
        timeout: Duration::from_secs(2),
        cancellation: Arc::new(Cancellation::default()),
    }
}
pub(super) fn target() -> api::HostSessionTarget {
    api::HostSessionTarget {
        epoch: api::HostEpoch {
            owner: api::ProcessInstance {
                machine: "machine-test".into(),
                boot: "boot-test".into(),
                pid: 42,
                #[cfg(windows)]
                started: api::StartIdentity::Windows {
                    creation_filetime: 19,
                },
                #[cfg(unix)]
                started: api::StartIdentity::Linux { start_ticks: 19 },
                #[cfg(windows)]
                executable: r"C:\test\secode.exe".into(),
                #[cfg(unix)]
                executable: "/test/secode".into(),
                argv_sha256: api::Sha256([3; 32]),
            },
            generation: api::HostGeneration(5),
        },
        session: api::HostSessionId("native-session-1".into()),
        binding: api::SessionIdentity {
            project: api::ProjectId("project-test".into()),
            agent: se_types::AgentId::from_parts(1_700_000_000_000, [2; 10])
                .unwrap()
                .to_linked(),
            session: se_types::SessionId::from_parts(1_700_000_000_000, [3; 10])
                .unwrap()
                .to_linked(),
        },
        binding_fingerprint: api::Sha256([4; 32]),
    }
}
pub(super) fn event() -> api::HostEventRef {
    api::HostEventRef {
        id: api::HostEventId("native-event-1".into()),
        sequence: NonZeroU64::MIN,
    }
}
pub(super) fn notice(target: api::HostSessionTarget) -> api::MailNotice {
    api::MailNotice {
        id: api::NoticeId("notice-test".into()),
        target,
        messages: vec![
            se_types::MessageId::from_parts(1_700_000_000_000, [4; 10])
                .unwrap()
                .to_linked(),
        ],
        through: api::Cursor("mail-cursor-original".into()),
        dedupe_sha256: api::Sha256([8; 32]),
    }
}
pub(super) struct Native {
    pub(super) state: Mutex<State>,
    pub(super) committed: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
}
pub(super) struct State {
    pub(super) calls: usize,
    pub(super) admissions: Vec<api::Admission>,
    pub(super) lose_reply: bool,
    pub(super) status: api::TargetStatus,
    pub(super) activity: api::Read<Option<api::ActiveSession>>,
    pub(super) refusal: Option<api::ApiError>,
    pub(super) corrupt: bool,
}
impl Native {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                calls: 0,
                admissions: vec![],
                lose_reply: false,
                status: api::TargetStatus::Eligible,
                activity: api::Read::Present { value: None },
                refusal: None,
                corrupt: false,
            }),
            committed: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
    async fn enter(&self, options: &api::ServiceOptions) {
        tokio::task::yield_now().await;
        assert_eq!(options.generation, api::Generation(7));
        self.state.lock().unwrap().calls += 1;
    }
    fn observation(&self, target: api::HostSessionTarget) -> api::BindingObservation {
        let state = self.state.lock().unwrap();
        api::BindingObservation {
            target,
            status: state.status.clone(),
            last_transition: event(),
            activity: api::Read::Unknown {
                what: "native activity unavailable".into(),
            },
        }
    }
}
impl api::HostServices for Native {
    fn hold<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        _reason: api::HoldReason,
        key: api::IdempotencyKey,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::HoldReceipt> {
        Box::pin(async move {
            self.enter(&options).await;
            self.state.lock().unwrap().status = api::TargetStatus::Held;
            Ok(api::HoldReceipt {
                target: target.clone(),
                committed: event(),
                retained_pending: 3,
                idempotency_key: key,
            })
        })
    }
    fn interrupt<'a>(
        &'a self,
        held: &'a api::HoldReceipt,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::InterruptReceipt> {
        Box::pin(async move {
            self.enter(&options).await;
            Ok(api::InterruptReceipt {
                target: held.target.clone(),
                requested: true,
            })
        })
    }
    fn active_session<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<Option<api::ActiveSession>>> {
        Box::pin(async move {
            self.enter(&options).await;
            Ok(self.state.lock().unwrap().activity.clone())
        })
    }
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a api::HostEpoch,
        page: api::PageRequest,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async move {
            self.enter(&options).await;
            Ok(api::Read::Present {
                value: api::Page {
                    items: vec![],
                    next: None,
                    window: api::Window {
                        source: api::Source::Host {
                            epoch: epoch.clone(),
                        },
                        start_cursor: page.after,
                        end_cursor: None,
                        returned: 0,
                        limit: page.limit,
                        bytes: 0,
                        max_bytes: page.max_bytes,
                        omitted_before: api::Omission::None,
                        omitted_after: api::Omission::Unknown {
                            reason: api::OmissionReason::Unreadable,
                        },
                        unreadable: 1,
                        stop_reason: api::StopReason::Unreadable,
                        complete: false,
                    },
                },
            })
        })
    }
    fn idle<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::SessionActivity>> {
        Box::pin(async move {
            self.enter(&options).await;
            Ok(api::Read::Unreadable {
                source: "native-reader".into(),
                reason: "actual I/O failure".into(),
                error: None,
            })
        })
    }
    fn binding_state<'a>(
        &'a self,
        target: &'a api::HostSessionTarget,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async move {
            self.enter(&options).await;
            Ok(api::Read::Present {
                value: self.observation(target.clone()),
            })
        })
    }
    fn adopt_binding<'a>(
        &'a self,
        request: api::AdoptBinding,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::BindingObservation>> {
        Box::pin(async move {
            self.enter(&options).await;
            let mut target = request.previous;
            target.epoch = request.current_epoch;
            if self.state.lock().unwrap().corrupt {
                target.binding_fingerprint = api::Sha256([99; 32]);
            }
            Ok(api::Read::Present {
                value: self.observation(target),
            })
        })
    }
    fn update_mail_target<'a>(
        &'a self,
        transition: api::TargetTransition,
        _key: api::IdempotencyKey,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::TargetReceipt> {
        Box::pin(async move {
            self.enter(&options).await;
            let mut state = self.state.lock().unwrap();
            let (target, status) = match transition {
                api::TargetTransition::Select { target, superseded } => {
                    if !superseded.is_empty()
                        && (state.status != api::TargetStatus::Held
                            || !matches!(state.activity, api::Read::Present { value: None }))
                    {
                        return Err(validate::error(
                            api::ApiFailure::Refused,
                            "native-takeover-raced",
                            "The human resumed execution before Select.",
                        ));
                    }
                    // Preserve an independent human hold even on a new target.
                    (target, state.status.clone())
                }
                api::TargetTransition::Revoke { target } => (target, api::TargetStatus::Revoked),
            };
            state.status = status.clone();
            Ok(api::TargetReceipt {
                target,
                committed: event(),
                status,
            })
        })
    }
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a api::MailNotice,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::NoticeAdmission> {
        Box::pin(async move {
            self.enter(&options).await;
            let (result, lose) = {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = &state.refusal {
                    return Ok(api::NoticeAdmission::Refused(error.clone()));
                }
                if state.status == api::TargetStatus::Held {
                    return Ok(api::NoticeAdmission::Held(api::HoldReceipt {
                        target: notice.target.clone(),
                        committed: event(),
                        retained_pending: 3,
                        idempotency_key: api::IdempotencyKey("human-hold-original".into()),
                    }));
                }
                let mut value = api::Admission {
                    committed_in: notice.target.epoch.clone(),
                    notice: notice.id.clone(),
                    target: notice.target.clone(),
                    pending: api::HostPendingId("native-pending-original".into()),
                    admitted_sequence: NonZeroU64::MIN,
                    dedupe_sha256: notice.dedupe_sha256,
                    committed: event(),
                };
                if state.corrupt {
                    value.dedupe_sha256 = api::Sha256([99; 32]);
                }
                state.admissions.push(value.clone());
                (api::NoticeAdmission::Admitted(value), state.lose_reply)
            };
            self.committed.notify_one();
            if lose {
                self.release.notified().await;
            }
            Ok(result)
        })
    }
    fn notice_status<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        notice: &'a api::NoticeId,
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::NoticeAdmission>> {
        Box::pin(async move {
            self.enter(&options).await;
            Ok(
                match self
                    .state
                    .lock()
                    .unwrap()
                    .admissions
                    .iter()
                    .find(|value| value.notice == *notice)
                {
                    Some(value) => api::Read::Present {
                        value: api::NoticeAdmission::Replayed(value.clone()),
                    },
                    None => api::Read::Absent {
                        checked: "exact original notice identity was absent in the native queue"
                            .into(),
                    },
                },
            )
        })
    }
}
pub(super) fn adapter(native: Arc<Native>) -> (SecodeAdapter, Arc<AtomicBool>) {
    let fence = Arc::new(AtomicBool::new(false));
    (
        SecodeAdapter::new(target().epoch, api::Generation(7), native, fence.clone()).unwrap(),
        fence,
    )
}
