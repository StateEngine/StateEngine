//! Author development consumer: a real embedded host over CLI-created state.
#![cfg(feature = "secode")]
#[path = "support/selector_services.rs"]
mod services;
#[path = "support/shutdown_linked_fixture.rs"]
mod support;
use secode_stateengine_api as api;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use support::*;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn result<T>(value: api::Result<T>) -> Check<T> {
    value.map_err(|e| format!("{e:?}").into())
}
fn present<T>(value: api::Read<T>) -> Check<T> {
    match value {
        api::Read::Present { value } => Ok(value),
        _ => Err("selector not present".into()),
    }
}
fn page(limit: u32) -> api::PageRequest {
    api::PageRequest {
        limit,
        max_bytes: 65536,
        after: None,
    }
}
fn cli(image: &Path, root: &Path, args: &[&str]) -> Check<String> {
    let out = Command::new(image)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH missing")?)
        .env("HOME", root)
        .env("USERPROFILE", root)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "CLI failed: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?)
}
#[test]
fn owner_selectors_read_real_catalogs_and_project_filtered_host_pages() -> Check {
    let image = PathBuf::from(
        std::env::var_os("SE_SELECTOR_SE").ok_or("SE_SELECTOR_SE must name the candidate CLI")?,
    );
    let root = std::env::temp_dir().join(format!("sel-{}", std::process::id()));
    fs::create_dir(&root)?;
    let home = root.join("state");
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    let initialized = cli(
        &image,
        &root,
        &[
            "init",
            "--home",
            home.to_str().ok_or("home encoding")?,
            "--repo",
            repo.to_str().ok_or("repo encoding")?,
            "--name",
            "Selector project",
            "--agent",
            "Selector agent",
            "--provider",
            "claude",
            "--model",
            "claude-sonnet-5-5",
            "--json",
        ],
    )?;
    let initialized: serde_json::Value = serde_json::from_str(&initialized)?;
    let selected = api::ProjectId(
        initialized["project"]["id"]
            .as_str()
            .ok_or("initialized project ID")?
            .into(),
    );
    cli(
        &image,
        &root,
        &[
            "--home",
            home.to_str().ok_or("home encoding")?,
            "--project",
            &selected.0,
            "--key",
            "selector-second-agent",
            "agent",
            "add",
            "Second selector agent",
        ],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let config = api::HostConfig {
            state_home: home.clone(),
            helper_executable: image.clone(),
            linux_delegation: api::LinuxDelegation::CurrentScope,
            api: api::API_VERSION,
            kind: api::HostKind::EmbeddedSecode,
            features: vec![api::Feature::LocalListener],
            limits: api::Limits {
                page_items: std::num::NonZeroU32::MIN.saturating_add(99),
                payload_bytes: std::num::NonZeroU32::MIN.saturating_add(262143),
                notice_ids: std::num::NonZeroU32::MIN.saturating_add(99),
            },
        };
        let opened = present(result(
            factory
                .open(
                    config,
                    api::OpenOptions {
                        expected_generation: None,
                        timeout: Duration::from_secs(30),
                        cancellation: Arc::new(NoopCancellation),
                    },
                )
                .await,
        )?)?;
        let options = call_options(opened.negotiated.generation, Duration::from_secs(30));
        let epoch = build_epoch(opened.negotiated.generation.0, &home)?;
        let project = selected.clone();
        let unavailable = Arc::new(AtomicBool::new(false));
        let source_incomplete = Arc::new(AtomicBool::new(false));
        result(
            opened
                .host
                .activate(
                    api::HostIntegration::Secode {
                        epoch,
                        services: Arc::new(services::Services {
                            project: project.clone(),
                            unavailable: unavailable.clone(),
                            source_incomplete: source_incomplete.clone(),
                        }),
                    },
                    options.clone(),
                )
                .await,
        )?;
        let projects = present(result(
            opened
                .host
                .list_projects(&api::OwnerAuthority, page(100), options.clone())
                .await,
        )?)?;
        assert!(projects.window.complete);
        assert_eq!(projects.items.len(), 1);
        assert_eq!(projects.items[0].id, project);
        assert_eq!(projects.items[0].root, repo);
        let agents = present(result(
            opened
                .host
                .list_agents(
                    &api::OwnerAuthority,
                    project.clone(),
                    page(100),
                    options.clone(),
                )
                .await,
        )?)?;
        assert!(agents.window.complete);
        assert_eq!(agents.items.len(), 2);
        assert_eq!(agents.items[0].name, "Selector agent");
        assert_eq!(agents.items[0].project, project);
        assert_eq!(agents.items[0].revision.0.get(), 1);
        let one = present(result(
            opened
                .host
                .list_agents(
                    &api::OwnerAuthority,
                    project.clone(),
                    page(1),
                    options.clone(),
                )
                .await,
        )?)?;
        let tight = present(result(
            opened
                .host
                .list_agents(
                    &api::OwnerAuthority,
                    project.clone(),
                    api::PageRequest {
                        max_bytes: one.window.bytes as u32,
                        ..page(100)
                    },
                    options.clone(),
                )
                .await,
        )?)?;
        assert_eq!(tight.items.len(), 1);
        assert_eq!(tight.window.stop_reason, api::StopReason::ByteLimit);
        assert!(tight.window.bytes <= u64::from(tight.window.max_bytes));
        let tail = present(result(
            opened
                .host
                .list_agents(
                    &api::OwnerAuthority,
                    project.clone(),
                    api::PageRequest {
                        after: tight.next,
                        ..page(100)
                    },
                    options.clone(),
                )
                .await,
        )?)?;
        assert_eq!(tail.items.len(), 1);
        assert_eq!(tail.items[0].name, "Second selector agent");
        assert!(tail.window.complete);
        let tiny = opened
            .host
            .list_agents(
                &api::OwnerAuthority,
                project.clone(),
                api::PageRequest {
                    max_bytes: 1,
                    ..page(100)
                },
                options.clone(),
            )
            .await
            .err()
            .ok_or("first row exceeded budget silently")?;
        assert_eq!(tiny.kind, api::ApiFailure::Incomplete);
        assert_eq!(tiny.code, "selector-row-too-large");

        for request in [
            page(0),
            page(101),
            api::PageRequest {
                max_bytes: 0,
                ..page(1)
            },
            api::PageRequest {
                max_bytes: 65537,
                ..page(1)
            },
            api::PageRequest {
                after: Some(api::Cursor("x".repeat(257))),
                ..page(1)
            },
        ] {
            let error = opened
                .host
                .list_projects(&api::OwnerAuthority, request, options.clone())
                .await
                .err()
                .ok_or("invalid page accepted")?;
            assert_eq!(error.kind, api::ApiFailure::Usage);
            assert_eq!(error.code, "selector-invalid-page");
        }
        let unknown = result(
            opened
                .host
                .list_agents(
                    &api::OwnerAuthority,
                    api::ProjectId("prj_018bcfe5-6800-7000-8000-000000000099".into()),
                    page(10),
                    options.clone(),
                )
                .await,
        )?;
        assert!(matches!(unknown, api::Read::Unknown { .. }));
        let first = present(result(
            opened
                .host
                .project_active_sessions(
                    &api::OwnerAuthority,
                    project.clone(),
                    page(1),
                    options.clone(),
                )
                .await,
        )?)?;
        assert_eq!(first.items[0].target.binding.agent.0, "aardvark");
        assert!(!first.window.complete);
        let next = first.next.ok_or("session continuation absent")?;
        let second = present(result(
            opened
                .host
                .project_active_sessions(
                    &api::OwnerAuthority,
                    project.clone(),
                    api::PageRequest {
                        after: Some(next.clone()),
                        ..page(1)
                    },
                    options.clone(),
                )
                .await,
        )?)?;
        assert_eq!(second.items[0].target.binding.agent.0, "zulu");
        assert!(second.window.complete);
        assert!(
            second
                .items
                .iter()
                .all(|r| r.target.binding.project == project)
        );
        // Independent 5p counterexample (7d2291d): an earlier native
        // SourceIncomplete omission must survive a later exhausted page.
        source_incomplete.store(true, Ordering::Relaxed);
        let partial_first = present(result(
            opened
                .host
                .project_active_sessions(
                    &api::OwnerAuthority,
                    project.clone(),
                    page(1),
                    options.clone(),
                )
                .await,
        )?)?;
        let partial_last = present(result(
            opened
                .host
                .project_active_sessions(
                    &api::OwnerAuthority,
                    project.clone(),
                    api::PageRequest {
                        after: partial_first.next,
                        ..page(1)
                    },
                    options.clone(),
                )
                .await,
        )?)?;
        assert_eq!(partial_last.items[0].target.binding.agent.0, "zulu");
        assert!(
            !partial_last.window.complete,
            "source-incomplete omission vanished after the final native page"
        );
        assert!(matches!(
            partial_last.window.omitted_after,
            api::Omission::Unknown {
                reason: api::OmissionReason::SourceIncomplete
            }
        ));
        source_incomplete.store(false, Ordering::Relaxed);
        unavailable.store(true, Ordering::Relaxed);
        let stale = opened
            .host
            .project_active_sessions(
                &api::OwnerAuthority,
                project.clone(),
                api::PageRequest {
                    after: Some(next),
                    ..page(1)
                },
                options.clone(),
            )
            .await
            .err()
            .ok_or("changed host snapshot did not stale cursor")?;
        assert_eq!(stale.kind, api::ApiFailure::Conflict);
        assert_eq!(stale.retry, api::ApiRetry::AfterRefresh);
        let partial = present(result(
            opened
                .host
                .project_active_sessions(&api::OwnerAuthority, project, page(100), options.clone())
                .await,
        )?)?;
        assert!(partial.items.is_empty());
        assert!(!partial.window.complete);
        assert!(matches!(
            partial.window.omitted_after,
            api::Omission::Unknown {
                reason: api::OmissionReason::SourceIncomplete
            }
        ));
        let drained = result(opened.host.drain(options.clone()).await)?;
        assert!(drained.writer_flushed);
        result(opened.host.close(drained, options).await)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    fs::remove_dir_all(&root)?;
    Ok(())
}
