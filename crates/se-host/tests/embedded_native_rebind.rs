//! API 2 restart -> native reattach -> same-identity grant reissuance.
//! Run with an explicitly owned initialized home, helper and init JSON.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/native_mail_services.rs"]
mod native;
#[path = "support/shutdown_linked_fixture.rs"]
mod support;
use api::HostServices;
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc, time::Duration};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn result<T>(value: api::Result<T>) -> Check<T> {
    value.map_err(|e| format!("{e:?}").into())
}
fn input(name: &str) -> Check<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os(name).ok_or_else(|| format!("missing fixture input {name}"))?,
    ))
}
fn page() -> api::PageRequest {
    api::PageRequest {
        after: None,
        limit: 10,
        max_bytes: 65536,
    }
}
fn refused<T>(reply: api::Result<T>, reason: &str) -> Check {
    let error = reply
        .err()
        .ok_or("a refused rebind unexpectedly succeeded")?;
    assert!(
        format!("{error:?}").contains(reason),
        "wrong refusal: {error:?}"
    );
    Ok(())
}

#[test]
#[ignore = "requires SE_NATIVE_MAIL_HOME,SE_NATIVE_MAIL_SE,SE_NATIVE_MAIL_INIT_JSON owned fixture"]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn restart_reattach_rebind_preserves_identity_and_holds_without_replacement() -> Check {
    let home = input("SE_NATIVE_MAIL_HOME")?;
    let image = input("SE_NATIVE_MAIL_SE")?;
    let init: serde_json::Value =
        serde_json::from_slice(&std::fs::read(input("SE_NATIVE_MAIL_INIT_JSON")?)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let api::Read::Present { value: mut opened } = result(
            factory
                .open(
                    api::HostConfig {
                        state_home: home.clone(),
                        helper_executable: image,
                        linux_delegation: api::LinuxDelegation::CurrentScope,
                        api: api::API_VERSION,
                        kind: api::HostKind::EmbeddedSecode,
                        features: vec![api::Feature::LocalListener, api::Feature::NativeMail],
                        limits: api::Limits {
                            page_items: std::num::NonZeroU32::MIN.saturating_add(99),
                            payload_bytes: std::num::NonZeroU32::MIN.saturating_add(262143),
                            notice_ids: std::num::NonZeroU32::MIN,
                        },
                    },
                    api::OpenOptions {
                        expected_generation: None,
                        timeout: Duration::from_secs(30),
                        cancellation: Arc::new(support::NoopCancellation),
                    },
                )
                .await,
        )?
        else {
            return Err("fixture not initialized".into());
        };
        let native = Arc::new(native::Services::new());
        let mut options =
            support::call_options(opened.negotiated.generation, Duration::from_secs(30));
        let epoch = support::build_epoch(options.generation.0, &home)?;
        result(
            opened
                .host
                .activate(
                    api::HostIntegration::Secode {
                        epoch: epoch.clone(),
                        services: native.clone(),
                    },
                    options.clone(),
                )
                .await,
        )?;
        let authority = api::BindingAuthority::Owner(api::OwnerAuthority);
        let mut request = api::BindingRequest {
            project: api::ProjectId(
                init["project"]["id"]
                    .as_str()
                    .ok_or("project missing")?
                    .into(),
            ),
            agent: api::AgentId(init["agent"]["id"].as_str().ok_or("agent missing")?.into()),
            harness: api::Harness::Secode,
            model: api::ModelIdentity {
                provider: "fixture".into(),
                model: "fixture".into(),
            },
            conversation: api::ProviderSessionId("restart-same-conversation".into()),
            target: None,
            expected_binding_revision: None,
            capture_consent: true,
            idempotency_key: api::IdempotencyKey("restart-original-bind".into()),
        };
        let mut issued = result(
            opened
                .host
                .bind_session(&authority, request.clone(), options.clone())
                .await,
        )?;
        let original = issued.identity.clone();
        let original_receipt = match &issued.receipt {
            api::Receipt::Committed { commit } => commit.clone(),
            _ => return Err("fresh bind did not commit".into()),
        };
        let mut target = api::HostSessionTarget {
            epoch,
            session: api::HostSessionId("restart-native-session".into()),
            binding: original.clone(),
            binding_fingerprint: api::Sha256([6; 32]),
        };
        result(
            native
                .update_mail_target(
                    api::TargetTransition::Select {
                        target: target.clone(),
                        superseded: vec![],
                    },
                    api::IdempotencyKey("restart-select".into()),
                    api::ServiceOptions {
                        generation: options.generation,
                        timeout: options.timeout,
                        cancellation: options.cancellation.clone(),
                    },
                )
                .await,
        )?;
        for (index, status) in [api::TargetStatus::Eligible, api::TargetStatus::Held]
            .into_iter()
            .enumerate()
        {
            native.0.lock().map_err(|_| "fixture lock")?.status = status.clone();
            let old_grant = issued.session;
            let drain = result(opened.host.drain(options.clone()).await)?;
            let api::Read::Present { value: next } = result(
                factory
                    .restart(
                        api::RestartReason::Drained { receipt: drain },
                        api::IdempotencyKey(format!("restart-{index}")),
                        options.clone(),
                    )
                    .await,
            )?
            else {
                return Err("restart not present".into());
            };
            opened = next;
            options = support::call_options(opened.negotiated.generation, Duration::from_secs(30));
            let epoch = support::build_epoch(options.generation.0, &home)?;
            result(
                opened
                    .host
                    .activate(
                        api::HostIntegration::Secode {
                            epoch: epoch.clone(),
                            services: native.clone(),
                        },
                        options.clone(),
                    )
                    .await,
            )?;
            request.target = Some(target.clone());
            request.expected_binding_revision = Some(issued.binding_revision);
            request.idempotency_key = api::IdempotencyKey(format!("restart-rebind-{index}"));
            refused(
                opened
                    .host
                    .bind_session(&authority, request.clone(), options.clone())
                    .await,
                "epoch",
            )?;
            let api::Read::Present { value: adoption } = result(
                native
                    .adopt_binding(
                        api::AdoptBinding {
                            previous: target.clone(),
                            current_epoch: epoch,
                            idempotency_key: api::IdempotencyKey(format!("reattach-{index}")),
                        },
                        api::ServiceOptions {
                            generation: options.generation,
                            timeout: options.timeout,
                            cancellation: options.cancellation.clone(),
                        },
                    )
                    .await,
            )?
            else {
                return Err("native reattach absent".into());
            };
            assert_eq!(adoption.status, status);
            target = adoption.target;
            request.target = Some(target.clone());
            let mut incomplete = request.clone();
            incomplete.expected_binding_revision = None;
            refused(
                opened
                    .host
                    .bind_session(&authority, incomplete, options.clone())
                    .await,
                "both",
            )?;
            let mut foreign = request.clone();
            foreign.target.as_mut().ok_or("target")?.binding.agent = api::AgentId("foreign".into());
            refused(
                opened
                    .host
                    .bind_session(&authority, foreign, options.clone())
                    .await,
                "foreign",
            )?;
            let mut stale = request.clone();
            stale.expected_binding_revision = Some(api::Revision(std::num::NonZeroU64::MIN));
            refused(
                opened
                    .host
                    .bind_session(&authority, stale, options.clone())
                    .await,
                "stale",
            )?;
            let mut foreign = request.clone();
            foreign.conversation.0.push_str("-foreign");
            refused(
                opened
                    .host
                    .bind_session(&authority, foreign, options.clone())
                    .await,
                "foreign",
            )?;
            let mut foreign = request.clone();
            foreign.target.as_mut().ok_or("target")?.binding_fingerprint = api::Sha256([9; 32]);
            refused(
                opened
                    .host
                    .bind_session(&authority, foreign, options.clone())
                    .await,
                "absent",
            )?;
            issued = result(
                opened
                    .host
                    .bind_session(&authority, request.clone(), options.clone())
                    .await,
            )?;
            assert_eq!(issued.identity, original);
            assert_eq!(issued.generation, options.generation);
            assert_eq!(
                issued.binding_revision,
                request.expected_binding_revision.ok_or("revision")?
            );
            assert_eq!(
                issued.receipt,
                api::Receipt::Replayed {
                    original: original_receipt.clone()
                }
            );
            let retry = result(
                opened
                    .host
                    .bind_session(&authority, request.clone(), options.clone())
                    .await,
            )?;
            assert_eq!(retry.identity, original);
            let continuity = api::ContinuityRequest {
                page: page(),
                acknowledge_packet: None,
            };
            assert!(
                opened
                    .host
                    .continuity(&old_grant, continuity.clone(), options.clone())
                    .await
                    .is_err()
            );
            let context = result(
                opened
                    .host
                    .continuity(&issued.session, continuity, options.clone())
                    .await,
            )?;
            assert_eq!(context.identity, original);
            assert_eq!(context.conversation, request.conversation);
            let text = "same conversation after restart";
            let captured = result(
                opened
                    .host
                    .capture_turn(
                        &issued.session,
                        api::CapturedTurn {
                            conversation: request.conversation.clone(),
                            vendor_turn: format!("restart-turn-{index}"),
                            vendor_event: None,
                            machine_id: None,
                            source_ref: None,
                            source_cli: "secode".into(),
                            nesting: None,
                            role: api::TurnRole::Assistant,
                            occurred_at: api::UnixMicros(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)?
                                    .as_micros()
                                    .try_into()?,
                            ),
                            content: api::BoundedText {
                                text: text.into(),
                                utf8_bytes: text.len() as u64,
                                complete: true,
                                omitted_bytes: Some(0),
                            },
                            source_sha256: api::Sha256(Sha256::digest(text.as_bytes()).into()),
                            idempotency_key: api::IdempotencyKey(format!(
                                "restart-capture-{index}"
                            )),
                        },
                        options.clone(),
                    )
                    .await,
            )?;
            assert!(matches!(captured, api::Receipt::Committed { .. }));
            let rows = result(
                opened
                    .host
                    .adoption_status(&api::OwnerAuthority, page(), options.clone())
                    .await,
            )?;
            assert_eq!(rows.items.len(), 1);
            assert_eq!(
                rows.items[0].state,
                if status == api::TargetStatus::Held {
                    api::AdoptionState::Held
                } else {
                    api::AdoptionState::Reattached
                }
            );
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.status,
                status,
                "rebind changed native hold state"
            );
        }
        native.0.lock().map_err(|_| "fixture lock")?.status = api::TargetStatus::Revoked;
        refused(
            opened
                .host
                .bind_session(&authority, request.clone(), options.clone())
                .await,
            "revoked",
        )?;
        result(
            opened
                .host
                .revoke_session(
                    &api::Authority::Owner(api::OwnerAuthority),
                    api::RevokeRequest {
                        session: original.session,
                        reason: api::EndReason::UserStopped,
                        key: api::IdempotencyKey("restart-engine-revoke".into()),
                    },
                    options.clone(),
                )
                .await,
        )?;
        refused(
            opened
                .host
                .bind_session(&authority, request, options.clone())
                .await,
            "revoked",
        )?;
        let drain = result(opened.host.drain(options.clone()).await)?;
        result(opened.host.close(drain, options).await)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    assert!(!home.join("endpoint.json").exists());
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.join("runtime.lock"))?;
    lock.try_lock()?;
    Ok(())
}
