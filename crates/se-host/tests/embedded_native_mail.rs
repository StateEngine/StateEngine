//! Public linked-host mail consumer. Reuses a private, closed initialized home;
//! never runs init/install, launches a provider, or substitutes for SE Code's
//! actual queue qualification. SE_NATIVE_MAIL_{HOME,OWNER,INIT_JSON,SE} pin inputs.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/native_mail_services.rs"]
mod native;
#[path = "support/shutdown_linked_fixture.rs"]
mod support;
use api::HostServices;
use futures_util::FutureExt;
use secode_stateengine_api as api;
use std::{
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn result<T>(value: api::Result<T>) -> Check<T> {
    value.map_err(|e| format!("{e:?}").into())
}
fn input(name: &str) -> Check<PathBuf> {
    Ok(PathBuf::from(std::env::var_os(name).ok_or_else(|| {
        format!("{name} must pin the owned fixture; no case ran")
    })?))
}
fn page() -> api::PageRequest {
    api::PageRequest {
        after: None,
        limit: 10,
        max_bytes: 65536,
    }
}

#[test]
#[ignore = "requires an explicitly owned initialized fixture and native helper"]
fn native_mail_reconciles_commit_wakes_lost_replies_and_holds_without_read_marks() -> Check {
    let home = input("SE_NATIVE_MAIL_HOME")?;
    let owner = input("SE_NATIVE_MAIL_OWNER")?;
    let image = input("SE_NATIVE_MAIL_SE")?;
    let baseline = counts(&home)?;
    let init: serde_json::Value =
        serde_json::from_slice(&std::fs::read(input("SE_NATIVE_MAIL_INIT_JSON")?)?)?;
    let project = api::ProjectId(
        init["project"]["id"]
            .as_str()
            .ok_or("project missing")?
            .into(),
    );
    let agent = api::AgentId(init["agent"]["id"].as_str().ok_or("agent missing")?.into());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let opened = result(
            factory
                .open(
                    api::HostConfig {
                        state_home: home.clone(),
                        helper_executable: image.clone(),
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
                        timeout: Duration::from_secs(20),
                        cancellation: Arc::new(support::NoopCancellation),
                    },
                )
                .await,
        )?;
        let api::Read::Present { value: opened } = opened else {
            return Err("fixture not initialized".into());
        };
        assert!(
            opened
                .negotiated
                .features
                .contains(&api::Feature::NativeMail)
        );
        let options = support::call_options(opened.negotiated.generation, Duration::from_secs(20));
        let epoch = support::build_epoch(options.generation.0, &home)?;
        let native = Arc::new(native::Services::new());
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
        let outcome = std::panic::AssertUnwindSafe(async {
            let issued = result(
                opened
                    .host
                    .bind_session(
                        &api::BindingAuthority::Owner(api::OwnerAuthority),
                        api::BindingRequest {
                            project: project.clone(),
                            agent: agent.clone(),
                            harness: api::Harness::Secode,
                            model: api::ModelIdentity {
                                provider: "fixture".into(),
                                model: "fixture".into(),
                            },
                            conversation: api::ProviderSessionId("native-mail-conversation".into()),
                            target: None,
                            expected_binding_revision: None,
                            capture_consent: false,
                            idempotency_key: api::IdempotencyKey("native-mail-bind".into()),
                        },
                        options.clone(),
                    )
                    .await,
            )?;
            let pending = result(
                opened
                    .host
                    .adoption_status(&api::OwnerAuthority, page(), options.clone())
                    .await,
            )?;
            assert_eq!(pending.items.len(), 1);
            assert_eq!(pending.items[0].state, api::AdoptionState::Pending);
            let target = api::HostSessionTarget {
                epoch,
                session: api::HostSessionId("native-mail-target".into()),
                binding: issued.identity,
                binding_fingerprint: api::Sha256([6; 32]),
            };
            let service_options = api::ServiceOptions {
                generation: options.generation,
                timeout: Duration::from_secs(5),
                cancellation: options.cancellation.clone(),
            };
            result(
                native
                    .update_mail_target(
                        api::TargetTransition::Select {
                            target: target.clone(),
                            superseded: vec![],
                        },
                        api::IdempotencyKey("native-select".into()),
                        service_options,
                    )
                    .await,
            )?;
            result(
                opened
                    .host
                    .native_state_changed(&target, options.clone())
                    .await,
            )?;
            // Let the initial debt sweep finish before a new real commit tests
            // the retained completion observer's native recipient wake.
            tokio::time::sleep(Duration::from_millis(100)).await;
            send(
                &home,
                &owner,
                &image,
                &project,
                &agent,
                "native-quiet-note",
                true,
            )
            .await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.attempts,
                0,
                "quiet mail entered native delivery"
            );
            native.0.lock().map_err(|_| "fixture lock")?.status = api::TargetStatus::Held;
            let before = native.0.lock().map_err(|_| "fixture lock")?.observations;
            send(
                &home,
                &owner,
                &image,
                &project,
                &agent,
                "native-mail-send-1",
                false,
            )
            .await?;
            let until = Instant::now() + Duration::from_secs(8);
            loop {
                if native.0.lock().map_err(|_| "fixture lock")?.observations > before {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "held recipient did not receive a commit wake"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(native.0.lock().map_err(|_| "fixture lock")?.calls, 0);
            native.0.lock().map_err(|_| "fixture lock")?.status = api::TargetStatus::Eligible;
            send(
                &home,
                &owner,
                &image,
                &project,
                &agent,
                "native-mail-send-2",
                false,
            )
            .await?;
            let until = Instant::now() + Duration::from_secs(8);
            while native.0.lock().map_err(|_| "fixture lock")?.attempts == 0 {
                assert!(
                    Instant::now() < until,
                    "first native delivery was not attempted"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // The callback attempt precedes its durable outcome and the
            // worker's published error. Synchronize on the public completed
            // failure, rather than the fixture's entry counter.
            let until = Instant::now() + Duration::from_secs(8);
            loop {
                let failed = result(
                    opened
                        .host
                        .adoption_status(&api::OwnerAuthority, page(), options.clone())
                        .await,
                )?;
                if matches!(failed.items[0].state, api::AdoptionState::Unreadable(_)) {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "transient failure was hidden during backoff: {failed:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // No new mail or native_state_changed nudge follows this failure.
            let until = Instant::now() + Duration::from_secs(8);
            loop {
                if native.0.lock().map_err(|_| "fixture lock")?.calls == 1 {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "native delivery did not recover without new mail"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // The second attempt committed, then lost its reply. Automatic
            // backoff must query that original ID, never deliver it twice.
            let until = Instant::now() + Duration::from_secs(8);
            loop {
                let status = result(
                    opened
                        .host
                        .adoption_status(&api::OwnerAuthority, page(), options.clone())
                        .await,
                )?;
                if status.items[0].state == api::AdoptionState::Reattached {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "original native admission was not reconciled: {status:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.calls,
                1,
                "lost reply duplicated input"
            );
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.attempts,
                2,
                "retry bypassed original-ID reconciliation"
            );
            let before = native.0.lock().map_err(|_| "fixture lock")?.observations;
            result(
                opened
                    .host
                    .native_state_changed(&target, options.clone())
                    .await,
            )?;
            let until = Instant::now() + Duration::from_secs(8);
            while native.0.lock().map_err(|_| "fixture lock")?.observations < before + 2 {
                assert!(
                    Instant::now() < until,
                    "repeated admission was not reconciled"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            native.0.lock().map_err(|_| "fixture lock")?.status = api::TargetStatus::Held;
            result(
                opened
                    .host
                    .native_state_changed(&target, options.clone())
                    .await,
            )?;
            let status = result(
                opened
                    .host
                    .adoption_status(&api::OwnerAuthority, page(), options.clone())
                    .await,
            )?;
            assert_eq!(status.items[0].state, api::AdoptionState::Held);
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.status,
                api::TargetStatus::Held,
                "mail cleared a native hold"
            );
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.messages[0].len(),
                1,
                "negotiated notice cap was ignored"
            );
            let mut wrong = target.clone();
            wrong.binding_fingerprint = api::Sha256([9; 32]);
            assert!(
                opened
                    .host
                    .native_state_changed(&wrong, options.clone())
                    .await
                    .is_err()
            );
            let mut stale = options.clone();
            stale.generation = api::Generation(options.generation.0 + 1);
            assert!(
                opened
                    .host
                    .native_state_changed(&target, stale)
                    .await
                    .is_err()
            );
            result(
                opened
                    .host
                    .revoke_session(
                        &api::Authority::Owner(api::OwnerAuthority),
                        api::RevokeRequest {
                            session: target.binding.session.clone(),
                            reason: api::EndReason::UserStopped,
                            key: api::IdempotencyKey("native-revoke".into()),
                        },
                        options.clone(),
                    )
                    .await,
            )?;
            assert_eq!(
                native.0.lock().map_err(|_| "fixture lock")?.status,
                api::TargetStatus::Revoked,
                "engine grant was revoked before its native queue target"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .catch_unwind()
        .await;
        let drained = result(opened.host.drain(options.clone()).await)?;
        assert!(
            drained.writer_flushed && drained.unresolved_effects == 0,
            "native worker did not close: {drained:?}"
        );
        result(opened.host.close(drained, options).await)?;
        match outcome {
            Ok(result) => result,
            Err(_) => {
                Err("native consumer assertion failed; linked host drained and closed".into())
            }
        }
    })?;
    assert!(!home.join("endpoint.json").exists());
    let outside=Command::new("python3").args(["-c","import sqlite3,sys,json; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); print(json.dumps(dict(c.execute(\"select kind,count(*) from events where kind in ('effect.requested','effect.offered','message.read','message.delivered') group by kind\"))))"])
        .arg(home.join("state.db")).output()?;
    assert!(outside.status.success());
    let counts: serde_json::Value = serde_json::from_slice(&outside.stdout)?;
    assert_eq!(
        counts["effect.offered"], 3,
        "native held, unknown and admitted observations were duplicated or lost"
    );
    assert!(
        counts.get("message.read") == baseline.get("message.read")
            && counts.get("message.delivered") == baseline.get("message.delivered"),
        "queue admission became recipient delivery/read"
    );
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.join("runtime.lock"))?;
    lock.try_lock()?;
    Ok(())
}
fn counts(home: &std::path::Path) -> Check<serde_json::Value> {
    let outside=Command::new("python3").args(["-c","import sqlite3,sys,json; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); print(json.dumps(dict(c.execute(\"select kind,count(*) from events where kind in ('effect.requested','effect.offered','message.read','message.delivered') group by kind\"))))"])
        .arg(home.join("state.db")).output()?;
    if !outside.status.success() {
        return Err(String::from_utf8_lossy(&outside.stderr).to_string().into());
    }
    Ok(serde_json::from_slice(&outside.stdout)?)
}

async fn send(
    home: &std::path::Path,
    owner: &std::path::Path,
    image: &std::path::Path,
    project: &api::ProjectId,
    agent: &api::AgentId,
    key: &str,
    quiet: bool,
) -> Check {
    let (home, owner, image, project, agent, key) = (
        home.to_path_buf(),
        owner.to_path_buf(),
        image.to_path_buf(),
        project.0.clone(),
        agent.0.clone(),
        key.to_owned(),
    );
    let sent = tokio::task::spawn_blocking(move || {
        let mut command = Command::new(image);
        command
            .arg("--home")
            .arg(home)
            .args([
                "--project",
                &project,
                "--key",
                &key,
                "msg",
                "send",
                &agent,
                "native mail body is never in the queue notice",
                "--json",
            ])
            .args(if quiet { vec!["--no-wake"] } else { vec![] })
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &owner)
            .env("USERPROFILE", owner)
            .output()
    })
    .await??;
    if !sent.status.success() {
        return Err(format!(
            "message send failed: {} {}",
            String::from_utf8_lossy(&sent.stdout),
            String::from_utf8_lossy(&sent.stderr)
        )
        .into());
    }
    Ok(())
}
