#![allow(
    clippy::unwrap_used,
    reason = "test assertions retain the failing native operation"
)]
use super::{fixture::*, *};
use api::HostServices;
use std::time::Duration;

#[test]
fn lost_reply_queries_original_admission_without_resending_or_marking_read() {
    run(async {
        let native = Native::new();
        native.state.lock().unwrap().lose_reply = true;
        let (adapter, _) = adapter(native.clone());
        let notice = notice(target());
        let mut call = options();
        call.timeout = Duration::from_millis(20);
        let failure = adapter.deliver_notice(&notice, call).await.err().unwrap();
        assert_eq!(failure.kind, api::ApiFailure::Unknown);
        let original = native.state.lock().unwrap().admissions[0].clone();
        let result = adapter
            .notice_status(&notice.target, &notice.id, options())
            .await
            .unwrap();
        assert_eq!(
            result,
            api::Read::Present {
                value: api::NoticeAdmission::Replayed(original)
            }
        );
        assert_eq!(native.state.lock().unwrap().admissions.len(), 1);
        assert_eq!(native.state.lock().unwrap().calls, 2);
    });
}
#[test]
fn cancellation_and_poison_after_native_commit_leave_the_original_effect_queryable() {
    run(async {
        for poison in [false, true] {
            let native = Native::new();
            native.state.lock().unwrap().lose_reply = true;
            let (adapter, fence) = adapter(native.clone());
            let notice = notice(target());
            let cancellation = Arc::new(Cancellation::default());
            let call = api::ServiceOptions {
                cancellation: cancellation.clone(),
                ..options()
            };
            let invoke = adapter.deliver_notice(&notice, call);
            let trigger = async {
                tokio::time::timeout(Duration::from_secs(1), native.committed.notified())
                    .await
                    .unwrap();
                if poison {
                    fence.store(true, Ordering::Release);
                    native.release.notify_one();
                } else {
                    cancellation.flag.store(true, Ordering::Release);
                    cancellation.wake.notify_waiters();
                }
            };
            let (result, ()) = futures_util::future::join(invoke, trigger).await;
            assert_eq!(
                result.err().unwrap().kind,
                if poison {
                    api::ApiFailure::GenerationPoisoned
                } else {
                    api::ApiFailure::Unknown
                }
            );
            assert_eq!(native.state.lock().unwrap().admissions.len(), 1);
            if poison {
                assert_eq!(
                    adapter
                        .notice_status(&notice.target, &notice.id, options())
                        .await
                        .err()
                        .unwrap()
                        .kind,
                    api::ApiFailure::GenerationPoisoned
                );
            } else {
                assert!(matches!(
                    adapter
                        .notice_status(&notice.target, &notice.id, options())
                        .await
                        .unwrap(),
                    api::Read::Present {
                        value: api::NoticeAdmission::Replayed(_)
                    }
                ));
            }
        }
    });
}
#[test]
fn invalid_and_stale_requests_never_reach_native_callbacks() {
    run(async {
        let native = Native::new();
        let (adapter, fence) = adapter(native.clone());
        let mut target = target();
        let cancelled = Arc::new(Cancellation::default());
        cancelled.flag.store(true, Ordering::Release);
        assert!(
            adapter
                .idle(
                    &target,
                    api::ServiceOptions {
                        cancellation: cancelled,
                        ..options()
                    }
                )
                .await
                .is_err()
        );
        let mut wrong = options();
        wrong.generation = api::Generation(8);
        assert!(adapter.idle(&target, wrong).await.is_err());
        target.epoch.owner.pid = 0;
        assert!(adapter.idle(&target, options()).await.is_err());
        target = fixture::target();
        target.binding.agent = api::AgentId("--token=PRIVATE".into());
        assert!(adapter.idle(&target, options()).await.is_err());
        target = fixture::target();
        target.epoch.generation = api::HostGeneration(6);
        assert!(adapter.idle(&target, options()).await.is_err());
        let mut empty = notice(fixture::target());
        empty.messages.clear();
        assert!(adapter.deliver_notice(&empty, options()).await.is_err());
        let mut duplicate = notice(fixture::target());
        duplicate.messages.push(duplicate.messages[0].clone());
        assert!(adapter.deliver_notice(&duplicate, options()).await.is_err());
        let mut excess = notice(fixture::target());
        excess.messages = (0..33)
            .map(|i| api::MessageId(format!("msg-{i:08x}")))
            .collect();
        assert!(adapter.deliver_notice(&excess, options()).await.is_err());
        let mut wide = notice(fixture::target());
        wide.messages = (0..32)
            .map(|i| api::MessageId(format!("msg-{i:0500x}")))
            .collect();
        wide.dedupe_sha256 = crate::linked::native_notice_digest(&wide).unwrap();
        assert!(adapter.deliver_notice(&wide, options()).await.is_err());
        let mut oversize = notice(fixture::target());
        oversize.target.epoch.owner.executable =
            std::path::PathBuf::from(format!("/{}", "x".repeat(12000)));
        assert!(adapter.deliver_notice(&oversize, options()).await.is_err());
        fence.store(true, Ordering::Release);
        assert!(adapter.idle(&fixture::target(), options()).await.is_err());
        assert_eq!(native.state.lock().unwrap().calls, 0);
    });
}
#[test]
fn uncertainty_and_original_provider_refusals_survive_both_read_directions() {
    run(async {
        let native = Native::new();
        let (adapter, _) = adapter(native.clone());
        let target = target();
        assert_eq!(
            adapter.idle(&target, options()).await.unwrap(),
            api::Read::Unreadable {
                source: "native-reader".into(),
                reason: "actual I/O failure".into(),
                error: None
            }
        );
        for read in [
            api::Read::Absent {
                checked: "exact absence".into(),
            },
            api::Read::Unknown {
                what: "not observed".into(),
            },
            api::Read::Unreadable {
                source: "queue".into(),
                reason: "disk failure".into(),
                error: Some(validate::uncertain()),
            },
            api::Read::Present { value: None },
        ] {
            native.state.lock().unwrap().activity = read.clone();
            assert_eq!(
                adapter.active_session(&target, options()).await.unwrap(),
                read
            );
        }
        let page = adapter
            .active_sessions(
                &target.epoch,
                api::PageRequest {
                    after: None,
                    limit: 10,
                    max_bytes: 4096,
                },
                options(),
            )
            .await
            .unwrap();
        assert!(matches!(
            page,
            api::Read::Present {
                value: api::Page {
                    window: api::Window {
                        complete: false,
                        unreadable: 1,
                        ..
                    },
                    ..
                }
            }
        ));
        let refusal = validate::error(
            api::ApiFailure::Refused,
            "independent-human-hold",
            "Human stopped this session; it remains held.",
        );
        native.state.lock().unwrap().refusal = Some(refusal.clone());
        assert_eq!(
            adapter
                .deliver_notice(&notice(target), options())
                .await
                .unwrap(),
            api::NoticeAdmission::Refused(refusal)
        );
        assert!(native.state.lock().unwrap().admissions.is_empty());
    });
}
#[test]
fn human_hold_and_takeover_race_are_native_facts_not_interrupt_acknowledgements() {
    run(async {
        let native = Native::new();
        let (adapter, _) = adapter(native.clone());
        let target = target();
        let held = adapter
            .hold(
                &target,
                api::HoldReason::HumanStop,
                api::IdempotencyKey("human-hold-original".into()),
                options(),
            )
            .await
            .unwrap();
        let interrupt = adapter.interrupt(&held, options()).await.unwrap();
        assert!(interrupt.requested);
        assert_eq!(
            adapter.active_session(&target, options()).await.unwrap(),
            api::Read::Present { value: None }
        );
        // Real execution can race after the point read; Select must still refuse.
        native.state.lock().unwrap().activity = api::Read::Present {
            value: Some(api::ActiveSession {
                target: target.clone(),
                activity: api::SessionActivity::Executing,
            }),
        };
        let transition = api::TargetTransition::Select {
            target: target.clone(),
            superseded: vec![target.clone()],
        };
        assert_eq!(
            adapter
                .update_mail_target(
                    transition.clone(),
                    api::IdempotencyKey("select-original".into()),
                    options()
                )
                .await
                .err()
                .unwrap()
                .code,
            "native-takeover-raced"
        );
        assert!(
            matches!(adapter.deliver_notice(&notice(target.clone()),options()).await.unwrap(),api::NoticeAdmission::Held(value) if value==held)
        );
        assert_eq!(native.state.lock().unwrap().status, api::TargetStatus::Held);
        native.state.lock().unwrap().activity = api::Read::Present { value: None };
        let selected = adapter
            .update_mail_target(
                transition,
                api::IdempotencyKey("select-original".into()),
                options(),
            )
            .await
            .unwrap();
        assert_eq!(selected.status, api::TargetStatus::Held);
        let revoked = adapter
            .update_mail_target(
                api::TargetTransition::Revoke { target },
                api::IdempotencyKey("revoke-original".into()),
                options(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status, api::TargetStatus::Revoked);
        assert!(native.state.lock().unwrap().admissions.is_empty());
    });
}
#[test]
fn adopted_status_retains_original_epoch_event_sequence_and_digest() {
    run(async {
        let native = Native::new();
        let (old, _) = adapter(native.clone());
        let original = notice(target());
        old.deliver_notice(&original, options()).await.unwrap();
        let committed = native.state.lock().unwrap().admissions[0].clone();
        let mut current = target();
        current.epoch.generation = api::HostGeneration(6);
        let next = SecodeAdapter::new(
            current.epoch.clone(),
            api::Generation(7),
            native.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(
            next.notice_status(&current, &original.id, options())
                .await
                .is_err()
        );
        next.adopt_binding(
            api::AdoptBinding {
                previous: original.target.clone(),
                current_epoch: current.epoch.clone(),
                idempotency_key: api::IdempotencyKey("adopt-original".into()),
            },
            options(),
        )
        .await
        .unwrap();
        assert_eq!(
            next.notice_status(&current, &original.id, options())
                .await
                .unwrap(),
            api::Read::Present {
                value: api::NoticeAdmission::Replayed(committed)
            }
        );
        assert_eq!(native.state.lock().unwrap().admissions.len(), 1);
    });
}
#[test]
fn changed_fingerprints_and_notice_digests_are_rejected() {
    run(async {
        let native = Native::new();
        let (adapter, _) = adapter(native.clone());
        native.state.lock().unwrap().corrupt = true;
        assert!(
            adapter
                .deliver_notice(&notice(target()), options())
                .await
                .is_err()
        );
        let mut current = target();
        current.epoch.generation = api::HostGeneration(6);
        let next = SecodeAdapter::new(
            current.epoch.clone(),
            api::Generation(7),
            native,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(
            next.adopt_binding(
                api::AdoptBinding {
                    previous: target(),
                    current_epoch: current.epoch.clone(),
                    idempotency_key: api::IdempotencyKey("adopt-original".into())
                },
                options()
            )
            .await
            .is_err()
        );
        assert!(
            next.notice_status(&current, &api::NoticeId("notice-test".into()), options())
                .await
                .is_err()
        );
    });
}
#[test]
fn process_epochs_use_the_shared_lossless_native_validator() {
    let original = target().epoch;
    let checked = se_types::HostEpoch::from_linked(original.clone()).unwrap();
    assert_eq!(crate::linked::host_epoch(&checked).unwrap(), original);
    let mut bad = original.clone();
    bad.generation = api::HostGeneration(0);
    assert!(se_types::HostEpoch::from_linked(bad).is_err());
    let mut bad = original.clone();
    bad.generation = api::HostGeneration(u64::MAX);
    assert!(se_types::HostEpoch::from_linked(bad).is_err());
    let mut bad = original;
    bad.owner.started = api::StartIdentity::Macos {
        start_seconds: 0,
        start_micros: 1_000_000,
    };
    assert!(se_types::HostEpoch::from_linked(bad).is_err());
}

fn run(call: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(call);
}

#[test]
fn native_epoch_paths_preserve_non_unicode_units() {
    let mut original = target().epoch;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        original.owner.executable =
            std::ffi::OsString::from_vec(b"/native/\xff-secode".to_vec()).into();
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        original.owner.executable =
            std::ffi::OsString::from_wide(&[67, 58, 92, 0xd800, 92, 115, 101]).into();
    }
    let checked = se_types::HostEpoch::from_linked(original.clone()).unwrap();
    assert_eq!(crate::linked::host_epoch(&checked).unwrap(), original);
}

#[test]
fn native_notice_digest_has_an_independent_vector_and_excludes_transient_epochs() {
    let mut notice = notice(target());
    let original = crate::linked::native_notice_digest(&notice).unwrap();
    // Independently encoded with Python's compact UTF-8 JSON and hashlib.
    assert_eq!(
        se_types::hex_lower(&original.0),
        "adee2c7621cf64c19af47e40ab8a9329b35f24cf0a9d5e8216938408eaed3d8a"
    );
    notice.target.epoch.generation = api::HostGeneration(999);
    notice.target.epoch.owner.pid = 99;
    assert_eq!(
        crate::linked::native_notice_digest(&notice).unwrap(),
        original
    );
    notice.messages.push(api::MessageId("msg-01234567".into()));
    let ordered = crate::linked::native_notice_digest(&notice).unwrap();
    notice.messages.reverse();
    assert_ne!(
        crate::linked::native_notice_digest(&notice).unwrap(),
        ordered
    );
    notice.messages.pop();
    notice.through = api::Cursor("different-cut".into());
    assert_ne!(
        crate::linked::native_notice_digest(&notice).unwrap(),
        original
    );
}
