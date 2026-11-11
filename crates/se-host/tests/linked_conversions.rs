//! Protects: W3 linked conversions preserve identity, receipt uncertainty and
//! source accounting without granting authority or inventing an unsupported view.
#![cfg(feature = "secode")]
use se_host::linked::{self, FromLinked, ToLinked};
use se_types as core;
use secode_stateengine_api as api;
use serde_json::json;
use std::{
    cell::Cell,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
type Check = Result<(), Box<dyn std::error::Error>>;

fn event(n: u8) -> core::Result<core::EventId> {
    core::EventId::from_parts(1_700_000_000_000 + u64::from(n), [n; 10])
}
fn issue() -> core::ErrorBody {
    core::ErrorBody::new(core::Detail::SessionRequired(
        core::details::SessionRequired {
            op: "judge.call".into(),
        },
    ))
}
fn epoch() -> core::Result<core::HostEpoch> {
    Ok(core::HostEpoch {
        owner: core::ProcessInstance::from_observation(core::ProcessFields {
            machine: core::MachineId::new("judge-machine")?,
            boot: core::BootId::new("judge-boot")?,
            pid: NonZeroU32::new(17).ok_or_else(|| core::SeError::invalid("pid", "nonzero"))?,
            #[cfg(windows)]
            started: core::StartIdentity::Windows {
                creation_filetime: NonZeroU64::new(19)
                    .ok_or_else(|| core::SeError::invalid("start", "nonzero"))?,
            },
            #[cfg(not(windows))]
            started: core::StartIdentity::Linux { start_ticks: 19 },
            executable: core::NativePath::from_local(
                std::env::current_exe()
                    .map_err(|_| core::SeError::invalid("executable", "a native test image"))?,
            )?,
            argv_sha256: core::Sha256::from_bytes([23; 32]),
        })?,
        generation: core::HostGeneration::new(7)?,
    })
}

/// Protects: every exported ID pair validates incoming data and preserves its exact kind and bytes.
#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn linked_ids_round_trip_and_refuse_malformed_inputs() -> Check {
    macro_rules! persistent {
        ($($name:ident),+) => {$(
            let id = core::$name::from_parts(1_700_000_000_000, [3; 10])?;
            assert_eq!(id.to_linked().0, id.as_str());
            assert_eq!(core::$name::from_linked(id.to_linked())?, id);
            for bad in ["", "\0", "selp-unissued-bearer", "prj_invalid-uuid"] {
                assert!(core::$name::from_linked(api::$name(bad.into())).is_err(), "{} accepted malformed input", stringify!($name));
            }
        )+};
    }
    persistent!(ProjectId, AgentId, SessionId, MessageId, EventId, StoreId);
    macro_rules! opaque {
        ($($name:ident),+) => {$(
            let id = core::$name::new("opaque:exact-marker")?;
            assert_eq!(id.to_linked().0, id.as_str());
            assert_eq!(core::$name::from_linked(id.to_linked())?, id);
            for bad in ["", "bad identity", "\0"] {
                assert!(core::$name::from_linked(api::$name(bad.into())).is_err(), "{} accepted an invalid opaque value", stringify!($name));
            }
        )+};
    }
    opaque!(
        HostSessionId,
        HostEventId,
        HostPendingId,
        ProviderSessionId,
        IdempotencyKey,
        NoticeId,
        Cursor
    );
    let historical = core::ProjectId::from_linked(api::ProjectId("imported-project".into()))?;
    assert_eq!(historical.to_linked().0, "imported-project");
    Ok(())
}

/// Protects: Pending keeps optional event identity; committed/replayed effects never lose their original commit.
#[test]
fn linked_receipts_preserve_pending_and_all_effect_arms() -> Check {
    let cx = core::RenderCx::default();
    for (reason, expected) in [
        (core::PendingReason::Queued, api::PendingReason::Queued),
        (
            core::PendingReason::AwaitingWitness,
            api::PendingReason::AwaitingWitness,
        ),
        (
            core::PendingReason::Recovering,
            api::PendingReason::Recovering,
        ),
    ] {
        for known in [false, true] {
            let id = known.then(|| event(1)).transpose()?;
            let output: api::Receipt<u32> = linked::receipt(
                core::Receipt::<u32>::Pending {
                    cause: reason,
                    event_id: id.clone(),
                    idempotency_key: core::IdempotencyKey::new("pending-key")?,
                },
                &cx,
                |_| Err(core::SeError::invalid("map", "never called for pending")),
            )?;
            assert_eq!(
                output,
                api::Receipt::Pending {
                    cause: expected,
                    event_id: id.map(|id| api::EventId(id.as_str().into())),
                    idempotency_key: api::IdempotencyKey("pending-key".into())
                }
            );
        }
    }
    let witness = core::EventRef {
        id: event(2)?,
        position: core::Cursor::new("witness-position")?,
    };
    let effects = [
        core::EffectStatus::NotRequired,
        core::EffectStatus::Pending,
        core::EffectStatus::Witnessed {
            witness: witness.clone(),
        },
        core::EffectStatus::Failed {
            error: Box::new(issue()),
        },
    ];
    for (index, effect) in effects.into_iter().enumerate() {
        for replayed in [false, true] {
            let id = event(1)?;
            let commit = core::Commit {
                event_id: id.clone(),
                position: core::Cursor::new("commit-position")?,
                idempotency_key: core::IdempotencyKey::new("original-key")?,
                value: 41u32,
                effects: effect.clone(),
            };
            let calls = Cell::new(0);
            let input = if replayed {
                core::Receipt::Replayed { original: commit }
            } else {
                core::Receipt::Committed { commit }
            };
            let output = linked::receipt(input, &cx, |value| {
                calls.set(calls.get() + 1);
                Ok(value + 1)
            })?;
            let commit = match output {
                api::Receipt::Committed { commit } if !replayed => commit,
                api::Receipt::Replayed { original } if replayed => original,
                other => panic!("receipt changed its state: {other:?}"),
            };
            assert_eq!(calls.get(), 1);
            assert_eq!(commit.event.id.0, id.as_str());
            assert_eq!(commit.event.position.0, "commit-position");
            assert_eq!(commit.idempotency_key.0, "original-key");
            assert_eq!(commit.value, 42);
            match (index, commit.effects) {
                (0, api::EffectStatus::NotRequired) | (1, api::EffectStatus::Pending) => (),
                (2, api::EffectStatus::Witnessed { witness: actual }) => {
                    assert_eq!(actual.id.0, witness.id.as_str());
                    assert_eq!(actual.position.0, witness.position.as_str());
                }
                (3, api::EffectStatus::Failed { error }) => {
                    assert_eq!(error.kind, api::ApiFailure::Unauthorized);
                    assert_eq!(error.code, "session-required");
                }
                (_, actual) => panic!("effect arm changed: {actual:?}"),
            }
        }
    }
    let refused: api::Receipt<u32> = linked::receipt(
        core::Receipt::<u32>::Refused {
            error: Box::new(issue()),
        },
        &cx,
        |_| Err(core::SeError::invalid("map", "never called for refusal")),
    )?;
    assert!(matches!(refused, api::Receipt::Refused { error } if error.code == "session-required"));
    Ok(())
}

/// Protects: absent, unreadable, unknown and present remain distinct on the public linked boundary.
#[test]
fn linked_reads_keep_each_measured_state_and_mapping_failure() -> Check {
    let cx = core::RenderCx::default();
    assert_eq!(
        linked::read(
            core::Read::Present { value: 41 },
            &cx,
            |value| Ok(value + 1)
        )?,
        api::Read::Present { value: 42 }
    );
    let cases = [
        (
            core::Read::Absent {
                checked: "outside readback found no row".into(),
            },
            api::Read::Absent {
                checked: "outside readback found no row".into(),
            },
        ),
        (
            core::Read::Unknown {
                what: "process unreadable".into(),
            },
            api::Read::Unknown {
                what: "process unreadable".into(),
            },
        ),
        (
            core::Read::Unreadable {
                source: "store".into(),
                reason: "denied".into(),
                error: None,
            },
            api::Read::Unreadable {
                source: "store".into(),
                reason: "denied".into(),
                error: None,
            },
        ),
    ];
    for (input, expected) in cases {
        let actual: api::Read<u32> = linked::read(input, &cx, |_: u32| {
            Err(core::SeError::invalid("map", "only for present"))
        })?;
        assert_eq!(actual, expected);
    }
    let unreadable: api::Read<u32> = linked::read(
        core::Read::<u32>::Unreadable {
            source: "pin".into(),
            reason: "unsafe".into(),
            error: Some(Box::new(issue())),
        },
        &cx,
        Ok,
    )?;
    assert!(
        matches!(unreadable, api::Read::Unreadable { source, reason, error: Some(error) }
        if source == "pin" && reason == "unsafe" && error.code == "session-required")
    );
    assert!(
        linked::read(core::Read::Present { value: 7u32 }, &cx, |_: u32| Err::<
            u32,
            _,
        >(
            core::SeError::invalid("map", "deliberate failure")
        ))
        .is_err()
    );
    Ok(())
}

fn fields(
    source: core::Source,
    stop_reason: core::StopReason,
    omission: core::Omission,
) -> core::Result<core::WindowFields> {
    Ok(core::WindowFields {
        source,
        from: core::Sequence::new(0)?,
        to: core::Sequence::new(3)?,
        start_cursor: Some(core::Cursor::new("start")?),
        end_cursor: Some(core::Cursor::new("end")?),
        returned: 1,
        limit: NonZeroU32::new(2).ok_or_else(|| core::SeError::invalid("limit", "nonzero"))?,
        bytes: 12,
        max_bytes: NonZeroU32::new(64)
            .ok_or_else(|| core::SeError::invalid("budget", "nonzero"))?,
        omitted_before: core::Omission::None,
        omitted_after: omission,
        unreadable: 0,
        stop_reason,
    })
}

/// Protects: linked windows require producer accounting; wire-only and Atlas views refuse honestly.
#[test]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn linked_windows_and_pages_retain_source_bounds_and_refuse_unsupported() -> Check {
    let store = core::StoreId::from_parts(1_700_000_000_000, [3; 10])?;
    let project = core::ProjectId::from_parts(1_700_000_000_000, [4; 10])?;
    let host = epoch()?;
    let linked_host = linked::host_epoch(&host)?;
    assert_eq!(linked_host.generation.0, 7);
    assert_eq!(linked_host.owner.pid, 17);
    assert_eq!(linked_host.owner.machine, "judge-machine");
    assert_eq!(linked_host.owner.boot, "judge-boot");
    assert_eq!(linked_host.owner.argv_sha256.0, [23; 32]);
    #[cfg(windows)]
    assert_eq!(
        linked_host.owner.started,
        api::StartIdentity::Windows {
            creation_filetime: 19
        }
    );
    #[cfg(not(windows))]
    assert_eq!(
        linked_host.owner.started,
        api::StartIdentity::Linux { start_ticks: 19 }
    );
    assert_eq!(
        linked_host.owner.executable,
        host.owner.fields().executable.to_local()?
    );
    for (started, expected) in [
        (
            core::StartIdentity::Windows {
                creation_filetime: NonZeroU64::new(29).ok_or("zero birth")?,
            },
            api::StartIdentity::Windows {
                creation_filetime: 29,
            },
        ),
        (
            core::StartIdentity::Linux { start_ticks: 31 },
            api::StartIdentity::Linux { start_ticks: 31 },
        ),
        (
            core::StartIdentity::Macos {
                start_seconds: 37,
                start_micros: 41,
            },
            api::StartIdentity::Macos {
                start_seconds: 37,
                start_micros: 41,
            },
        ),
    ] {
        let mut fields = host.owner.fields().clone();
        let windows = matches!(started, core::StartIdentity::Windows { .. });
        fields.executable = core::NativePath::from_encoded(if windows {
            core::PathEncoding::WindowsUtf16(r"C:\judge\vendor.exe".encode_utf16().collect())
        } else {
            core::PathEncoding::UnixBytes(b"/judge/vendor".to_vec())
        })?;
        fields.started = started;
        let measured = core::HostEpoch {
            owner: core::ProcessInstance::from_observation(fields)?,
            generation: host.generation,
        };
        if windows == cfg!(windows) {
            assert_eq!(linked::host_epoch(&measured)?.owner.started, expected);
        } else {
            assert!(
                linked::host_epoch(&measured).is_err(),
                "foreign native path silently converted"
            );
        }
    }
    let sources = [
        (
            core::Source::Store {
                store: store.clone(),
                project: None,
            },
            api::Source::Store {
                store: api::StoreId(store.as_str().into()),
                project: None,
            },
        ),
        (
            core::Source::Store {
                store: store.clone(),
                project: Some(project.clone()),
            },
            api::Source::Store {
                store: api::StoreId(store.as_str().into()),
                project: Some(api::ProjectId(project.as_str().into())),
            },
        ),
        (
            core::Source::Host { epoch: host },
            api::Source::Host { epoch: linked_host },
        ),
        (
            core::Source::Configuration {
                location: "explicit config".into(),
            },
            api::Source::Configuration {
                location: "explicit config".into(),
            },
        ),
    ];
    for (source, expected) in sources {
        assert_eq!(linked::source(&source)?, expected);
        let window = core::Window::new(fields(
            source.clone(),
            core::StopReason::Exhausted,
            core::Omission::None,
        )?)?;
        let converted = linked::window(&window)?;
        assert_eq!(converted.source, expected);
        assert_eq!(
            (
                converted.returned,
                converted.limit,
                converted.bytes,
                converted.max_bytes,
                converted.unreadable
            ),
            (1, 2, 12, 64, 0)
        );
        assert_eq!(converted.start_cursor, Some(api::Cursor("start".into())));
        assert_eq!(converted.end_cursor, Some(api::Cursor("end".into())));
        assert!(converted.complete);
        let wire: core::Window = serde_json::from_value(serde_json::to_value(&window)?)?;
        assert!(
            linked::window(&wire).is_err(),
            "wire aggregates invented producer accounting"
        );
        let page = core::Page::new(vec![41u32], window, None)?;
        let translated = linked::page(&page, |value| Ok(value + 1))?;
        assert_eq!(translated.items, [42]);
        assert_eq!(translated.next, None);
        assert!(
            linked::page(&page, |_| Err::<u32, _>(core::SeError::invalid(
                "page item",
                "deliberate failure"
            )))
            .is_err()
        );
    }
    for (reason, expected) in [
        (core::OmissionReason::Limit, api::OmissionReason::Limit),
        (core::OmissionReason::Budget, api::OmissionReason::Budget),
        (
            core::OmissionReason::Unreadable,
            api::OmissionReason::Unreadable,
        ),
        (
            core::OmissionReason::SourceIncomplete,
            api::OmissionReason::SourceIncomplete,
        ),
    ] {
        for known in [false, true] {
            let omission = if known {
                core::Omission::Known {
                    count: NonZeroU64::new(2).ok_or("zero omission")?,
                    reason,
                }
            } else {
                core::Omission::Unknown { reason }
            };
            let source = core::Source::Configuration {
                location: "finite source".into(),
            };
            let window = core::Window::new(fields(source, core::StopReason::ItemLimit, omission)?)?;
            let converted = linked::window(&window)?;
            assert!(!converted.complete);
            assert_eq!(
                converted.omitted_after,
                if known {
                    api::Omission::Known {
                        count: 2,
                        reason: expected,
                    }
                } else {
                    api::Omission::Unknown { reason: expected }
                }
            );
            let page = core::Page::new(vec![1u32], window, Some(core::Cursor::new("end")?))?;
            assert_eq!(
                linked::page(&page, |value| Ok(*value))?.next,
                Some(api::Cursor("end".into()))
            );
        }
    }
    for (reason, expected) in [
        (core::StopReason::Exhausted, api::StopReason::Exhausted),
        (core::StopReason::ItemLimit, api::StopReason::ItemLimit),
        (core::StopReason::ByteLimit, api::StopReason::ByteLimit),
        (core::StopReason::Unreadable, api::StopReason::Unreadable),
        (core::StopReason::Cancelled, api::StopReason::Cancelled),
        (core::StopReason::Deadline, api::StopReason::Deadline),
        (core::StopReason::Unsupported, api::StopReason::Unsupported),
    ] {
        let omission = if reason == core::StopReason::Exhausted {
            core::Omission::None
        } else {
            core::Omission::Unknown {
                reason: core::OmissionReason::SourceIncomplete,
            }
        };
        let window = core::Window::new(fields(
            core::Source::Configuration {
                location: "stop reason".into(),
            },
            reason,
            omission,
        )?)?;
        assert_eq!(linked::window(&window)?.stop_reason, expected);
    }
    let mut partial = fields(
        core::Source::Configuration {
            location: "partial earlier range".into(),
        },
        core::StopReason::Unreadable,
        core::Omission::None,
    )?;
    partial.unreadable = 3;
    partial.omitted_before = core::Omission::Known {
        count: NonZeroU64::new(2).ok_or("zero earlier omission")?,
        reason: core::OmissionReason::Limit,
    };
    let partial = linked::window(&core::Window::new(partial)?)?;
    assert_eq!(
        partial.unreadable, 3,
        "unreadable source count was discarded"
    );
    assert_eq!(
        partial.omitted_before,
        api::Omission::Known {
            count: 2,
            reason: api::OmissionReason::Limit,
        },
        "earlier omission was discarded"
    );
    assert_eq!(partial.omitted_after, api::Omission::None);
    assert!(!partial.complete);
    let atlas = core::Source::Atlas {
        project,
        root: core::AtlasRootId::from_parts(1_700_000_000_000, [5; 10])?,
        epoch: None,
    };
    assert!(linked::source(&atlas).is_err());
    assert!(
        linked::window(&core::Window::new(fields(
            atlas,
            core::StopReason::Exhausted,
            core::Omission::None
        )?)?)
        .is_err()
    );
    Ok(())
}

/// Protects: every ErrorBody class and Retry arm stays typed; literal CLI remedy arguments survive conversion.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn linked_errors_preserve_classes_retries_and_literal_remedies() -> Check {
    let cx = core::RenderCx::default();
    let cases = [
        (
            "usage-unknown-command",
            json!({"got":"x","suggestion":null}),
            api::ApiFailure::Usage,
        ),
        (
            "api-version-unsupported",
            json!({"client":"1","host":"2"}),
            api::ApiFailure::Refused,
        ),
        (
            "session-required",
            json!({"op":"x"}),
            api::ApiFailure::Unauthorized,
        ),
        (
            "target-unknown",
            json!({"subject":"x","reason":"absent","next_step":"read"}),
            api::ApiFailure::Unknown,
        ),
        (
            "source-unreadable",
            json!({"subject":"x","reason":"denied","next_step":"repair"}),
            api::ApiFailure::Unreadable,
        ),
        (
            "idempotency-key-reused",
            json!({"key":"original","original_event":event(1)?}),
            api::ApiFailure::Conflict,
        ),
        (
            "runtime-start-pending",
            json!({"waited_ms":1}),
            api::ApiFailure::Incomplete,
        ),
        (
            "deadline-exceeded",
            json!({"op":"x","deadline_ms":1}),
            api::ApiFailure::Unavailable,
        ),
        (
            "internal",
            json!({"report_id":"judge-report","location":"conversion"}),
            api::ApiFailure::Internal,
        ),
        ("cancelled", json!({"op":"x"}), api::ApiFailure::Cancelled),
    ];
    for (code, detail, expected) in cases {
        let body: core::ErrorBody = serde_json::from_value(json!({"code":code,"detail":detail}))?;
        let output = linked::error_body(&body, &cx)?;
        assert_eq!(output.kind, expected);
        assert_eq!(output.code, code);
        assert_eq!(output.message, body.message());
        assert!(!output.remedy.text.is_empty());
    }
    for (retry, expected) in [
        (core::Retry::Never, api::ApiRetry::Never),
        (core::Retry::AfterReread, api::ApiRetry::AfterRefresh),
        (core::Retry::WhenRuntimeReady, api::ApiRetry::AfterRefresh),
        (
            core::Retry::After(Duration::from_millis(23)),
            api::ApiRetry::AfterMillis(23),
        ),
    ] {
        assert_eq!(
            linked::error_body(&issue().with_retry(retry), &cx)?.retry,
            expected
        );
    }
    assert!(
        linked::error_body(&issue().with_retry(core::Retry::After(Duration::MAX)), &cx).is_err()
    );
    struct Commands(Option<core::Cmd>);
    impl core::RemedyCommands for Commands {
        fn for_error(&self, _: &core::ErrorBody) -> core::Result<Option<core::Cmd>> {
            Ok(self.0.clone())
        }
    }
    let argv = vec![
        "msg".to_owned(),
        "send".into(),
        "literal space ' $name ;".into(),
    ];
    let commands = Commands(Some(core::Cmd::Se {
        argv: serde_json::from_value(json!(argv))?,
    }));
    let context = core::RenderCx {
        commands: Some(&commands),
        ..Default::default()
    };
    let output = linked::error_body(&issue(), &context)?;
    assert_eq!(output.remedy.command, Some(api::ApiCommand::Manual));
    let (_, arguments) = output
        .remedy
        .text
        .rsplit_once("Run se with these literal arguments: ")
        .ok_or("CLI remedy arguments were dropped")?;
    assert_eq!(serde_json::from_str::<Vec<String>>(arguments)?, argv);
    let commands = Commands(Some(core::Cmd::Tool {
        name: "stateengine_status".into(),
        args: json!({"bounded":true}),
    }));
    let context = core::RenderCx {
        commands: Some(&commands),
        ..Default::default()
    };
    assert_eq!(
        linked::error_body(&issue(), &context)?.remedy.command,
        Some(api::ApiCommand::Tool {
            name: "stateengine_status".into(),
            args: json!({"bounded":true})
        })
    );
    for command in [None, Some(core::Cmd::Manual)] {
        let commands = Commands(command.clone());
        let context = core::RenderCx {
            commands: Some(&commands),
            ..Default::default()
        };
        assert_eq!(
            linked::error_body(&issue(), &context)?.remedy.command,
            command.map(|_| api::ApiCommand::Manual)
        );
    }
    Ok(())
}
