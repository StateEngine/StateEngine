//! Public activation and lifecycle fencing with an async protocol fixture; no native queue claim.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/shutdown_linked_fixture.rs"]
mod support;
use secode_stateengine_api as api;
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::*;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Native {
    mode: AtomicU8,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
fn services_refused() -> api::ApiError {
    api::ApiError {
        kind: api::ApiFailure::NotIncluded,
        code: "judge-unused-native-method".into(),
        message: "This public wiring consumer exercises native session pages only.".into(),
        remedy: api::ApiRemedy {
            text: "Use the real SE Code queue for delivery qualification.".into(),
            command: None,
        },
        retry: api::ApiRetry::Never,
    }
}
impl api::HostServices for Native {
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
        options: api::ServiceOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async move {
            assert_eq!(options.generation.0, epoch.generation.0);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mode = self.mode.load(Ordering::SeqCst);
            if mode == 2 {
                self.entered.notify_one();
                self.release.notified().await;
            }
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
                        limit: if mode == 1 {
                            page.limit - 1
                        } else {
                            page.limit
                        },
                        max_bytes: page.max_bytes,
                        bytes: 0,
                        omitted_before: api::Omission::None,
                        omitted_after: api::Omission::None,
                        unreadable: 0,
                        stop_reason: api::StopReason::Exhausted,
                        complete: true,
                    },
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

/// The epoch of this exact judge process at `generation`, observed through the
/// same public native facts the embedded host verifies against.
fn actual<T>(value: api::Result<T>) -> Check<T> {
    value.map_err(|e| format!("{e:?}").into())
}
fn present<T>(value: api::Read<T>) -> Check<T> {
    match value {
        api::Read::Present { value } => Ok(value),
        _ => Err("public read was not Present".into()),
    }
}
#[test]
fn activated_native_callbacks_are_validated_and_fenced_during_an_inflight_read() -> Check {
    let root = PathBuf::from(std::env::var_os("JUDGE_H13_ROOT").ok_or("root missing")?);
    let image = PathBuf::from(std::env::var_os("JUDGE_H13_SE").ok_or("image missing")?);
    std::fs::create_dir(&root)?;
    for leaf in ["owner", "repo"] {
        std::fs::create_dir(root.join(leaf))?;
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.join("owner"), std::fs::Permissions::from_mode(0o700))?;
    let home = root.join("state");
    let initialized = Command::new(&image)
        .args(["--json", "--home"])
        .arg(&home)
        .args(["init", "--repo"])
        .arg(root.join("repo"))
        .args([
            "--name",
            "Native callback judge",
            "--agent",
            "Judge",
            "--provider",
            "claude",
            "--model",
            "claude-sonnet-5-5",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH absent")?)
        .env("HOME", root.join("owner"))
        .env("USERPROFILE", root.join("owner"))
        .output()?;
    std::fs::write(root.join("init.stdout"), &initialized.stdout)?;
    std::fs::write(root.join("init.stderr"), &initialized.stderr)?;
    assert!(initialized.status.success(), "native init failed");
    let initialized: serde_json::Value = serde_json::from_slice(&initialized.stdout)?;
    let project = api::ProjectId(
        initialized["project"]["id"]
            .as_str()
            .ok_or("project ID absent")?
            .into(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let config = api::HostConfig { state_home: home.clone(), helper_executable: image, linux_delegation: api::LinuxDelegation::CurrentScope, api: api::API_VERSION, kind: api::HostKind::EmbeddedSecode, features: vec![api::Feature::LocalListener], limits: api::Limits { page_items: std::num::NonZeroU32::new(100).ok_or("page limit")?, payload_bytes: std::num::NonZeroU32::new(262144).ok_or("bytes limit")?, notice_ids: std::num::NonZeroU32::new(32).ok_or("notice limit")? } };
        let opened = present(actual(factory.open(config, api::OpenOptions { expected_generation: None, timeout: Duration::from_secs(30), cancellation: Arc::new(NoopCancellation) }).await)?)?;
        assert!(!opened.negotiated.features.contains(&api::Feature::NativeMail));
        let opts = call_options(opened.negotiated.generation, Duration::from_secs(30));
        let native = Arc::new(Native { mode: AtomicU8::new(0), calls: AtomicUsize::new(0), entered: tokio::sync::Notify::new(), release: tokio::sync::Notify::new() });
        actual(opened.host.activate(api::HostIntegration::Secode { epoch: build_epoch(opened.negotiated.generation.0, &home)?, services: native.clone() }, opts.clone()).await)?;
        let page = api::PageRequest { after: None, limit: 10, max_bytes: 8192 };
        let normal = present(actual(opened.host.project_active_sessions(&api::OwnerAuthority, project.clone(), page.clone(), opts.clone()).await)?)?;
        assert!(normal.window.complete); assert_eq!(normal.window.unreadable, 0);
        native.mode.store(1, Ordering::SeqCst);
        let drift = present(actual(opened.host.project_active_sessions(&api::OwnerAuthority, project.clone(), page.clone(), opts.clone()).await)?)?;
        assert!(!drift.window.complete); assert_eq!(drift.window.unreadable, 1);
        println!("ok - public activation wraps callbacks and preserves a malformed page as unreadable");
        native.mode.store(2, Ordering::SeqCst);
        let read = opened.host.project_active_sessions(&api::OwnerAuthority, project.clone(), page.clone(), opts.clone());
        let poison = async {
            tokio::time::timeout(Duration::from_secs(5), native.entered.notified()).await?;
            actual(opened.host.poison(api::FaultReport { incident: "judge-native-inflight".into() }, opts.clone()).await)?;
            native.release.notify_one(); Ok::<(), Box<dyn std::error::Error>>(())
        };
        let (observed, poisoned) = futures_util::future::join(read, poison).await; poisoned?;
        let observed = present(actual(observed)?)?;
        assert!(!observed.window.complete, "fenced callback fabricated complete empty data");
        assert!(matches!(observed.window.omitted_after, api::Omission::Unknown { reason: api::OmissionReason::SourceIncomplete }));
        assert_eq!(opened.host.health(), api::GenerationHealth::Poisoned);
        assert_eq!(native.calls.load(Ordering::SeqCst), 3);
        assert!(opened.host.project_active_sessions(&api::OwnerAuthority, project, page, opts.clone()).await.is_err());
        assert_eq!(native.calls.load(Ordering::SeqCst), 3);
        println!("ok - public poison fences the in-flight callback and old handle without rebinding native state");
        let drained = actual(opened.host.drain(opts.clone()).await)?;
        assert!(drained.writer_flushed); actual(opened.host.close(drained, opts).await)?;
        assert!(!home.join("endpoint.json").exists());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
