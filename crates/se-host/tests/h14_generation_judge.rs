//! Public linked generation checks; native SE Code services remain a separate witness.
#![cfg(all(feature = "secode", target_os = "linux"))]
#[path = "support/shutdown_linked_fixture.rs"]
mod support;
use secode_stateengine_api as api;
use std::{future::Future, path::Path, pin::Pin, process::Command, sync::Arc, time::Duration};
use support::*;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct FailedRoute;
impl api::Cancellation for FailedRoute {
    fn is_cancelled(&self) -> bool {
        panic!("independent public route fault")
    }
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}
fn lock(home: &Path, held: bool) -> Check {
    let status = Command::new("python3")
        .args(["-c", "import fcntl,sys; f=open(sys.argv[1],'r+b')\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(3)\nsys.exit(0)"])
        .arg(home.join("runtime.lock")).status()?;
    assert_eq!(status.code(), Some(if held { 3 } else { 0 }));
    Ok(())
}
fn present<T>(read: api::Read<T>) -> Check<T> {
    match read {
        api::Read::Present { value } => Ok(value),
        _ => Err("expected an actual present public result".into()),
    }
}
#[test]
fn restart_replay_cannot_rebind_old_handles_or_change_its_original_identity() -> Check {
    let root = std::path::PathBuf::from(std::env::var_os("JUDGE_H14_ROOT").ok_or("root missing")?);
    let image = std::path::PathBuf::from(std::env::var_os("JUDGE_H14_SE").ok_or("image missing")?);
    std::fs::create_dir(&root)?;
    for leaf in ["repo", "owner"] {
        std::fs::create_dir(root.join(leaf))?;
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.join("owner"), std::fs::Permissions::from_mode(0o700))?;
    let home = root.join("state");
    let init = Command::new(&image)
        .args(["--json", "--home"])
        .arg(&home)
        .args(["init", "--repo"])
        .arg(root.join("repo"))
        .args([
            "--name",
            "Independent generation judge",
            "--agent",
            "Judge",
            "--provider",
            "claude",
            "--model",
            "claude-sonnet-5-5",
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH missing")?)
        .env("HOME", root.join("owner"))
        .env("USERPROFILE", root.join("owner"))
        .output()?;
    std::fs::write(root.join("init.stdout"), &init.stdout)?;
    std::fs::write(root.join("init.stderr"), &init.stderr)?;
    assert!(init.status.success(), "native init failed");
    let config = api::HostConfig {
        state_home: home.clone(),
        helper_executable: image,
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let factory = se_host::embedded_factory(runtime.handle().clone());
        let opened = present(factory.open(config, api::OpenOptions { expected_generation: None,
            timeout: Duration::from_secs(30), cancellation: Arc::new(NoopCancellation) }).await.map_err(|error| format!("{error:?}"))?)?;
        let g1 = opened.negotiated.generation;
        let opts1 = call_options(g1, Duration::from_secs(30));
        opened.host.activate(api::HostIntegration::Secode { epoch: build_epoch(g1.0, &home)?, services: Arc::new(SilentServices) }, opts1.clone()).await.map_err(|error| format!("{error:?}"))?;
        lock(&home, true)?;
        let page = api::PageRequest { after: None, limit: 10, max_bytes: 8192 };
        let projects = present(opened.host.list_projects(&api::OwnerAuthority, page.clone(), opts1.clone()).await.map_err(|error| format!("{error:?}"))?)?;
        let project = projects.items.first().ok_or("project absent")?.id.clone();
        for _ in 0..3 {
            let mut fault = opts1.clone(); fault.cancellation = Arc::new(FailedRoute);
            let error = opened.host.list_projects(&api::OwnerAuthority, page.clone(), fault).await.err().ok_or("fault accepted")?;
            assert_eq!(error.kind, api::ApiFailure::EnginePanicked);
        }
        assert!(opened.host.list_projects(&api::OwnerAuthority, page.clone(), opts1.clone()).await.err().ok_or("exhausted route accepted")?.message.contains("three restarts"));
        let agents = present(opened.host.list_agents(&api::OwnerAuthority, project, page.clone(), opts1.clone()).await.map_err(|error| format!("{error:?}"))?)?;
        assert_eq!(agents.items.len(), 1, "unrelated public route was lost");
        assert_eq!(opened.host.health(), api::GenerationHealth::Ready);
        println!("ok - exhausted read route preserves unrelated real-store reads and owner lease");

        opened.host.poison(api::FaultReport { incident: "original-incident".into() }, opts1.clone()).await.map_err(|error| format!("{error:?}"))?;
        let reason1 = api::RestartReason::Poisoned { incident: "original-incident".into() };
        let key1 = api::IdempotencyKey("restart-original".into());
        let second = present(factory.restart(reason1.clone(), key1.clone(), opts1.clone()).await.map_err(|error| format!("{error:?}"))?)?;
        assert_eq!(second.negotiated.generation.0, g1.0 + 1);
        assert_eq!(opened.host.health(), api::GenerationHealth::Closed);
        lock(&home, false)?;
        assert!(factory.restart(api::RestartReason::Poisoned { incident: "changed-incident".into() }, key1.clone(), opts1.clone()).await.is_err());
        assert!(factory.restart(reason1.clone(), api::IdempotencyKey("different-key".into()), opts1.clone()).await.is_err());
        assert!(factory.restart(reason1.clone(), key1.clone(), call_options(second.negotiated.generation, Duration::from_secs(5))).await.is_err());
        lock(&home, false)?;
        println!("ok - original restart key, source generation and incident cannot be substituted");

        let opts2 = call_options(second.negotiated.generation, Duration::from_secs(30));
        second.host.activate(api::HostIntegration::Secode { epoch: build_epoch(second.negotiated.generation.0, &home)?, services: Arc::new(SilentServices) }, opts2.clone()).await.map_err(|error| format!("{error:?}"))?;
        lock(&home, true)?;
        let replay = present(factory.restart(reason1.clone(), key1.clone(), opts1.clone()).await.map_err(|error| format!("{error:?}"))?)?;
        assert_eq!(replay.negotiated.generation, second.negotiated.generation);
        assert_eq!(replay.host.health(), api::GenerationHealth::Ready);
        let receipt = second.host.drain(opts2.clone()).await.map_err(|error| format!("{error:?}"))?;
        assert!(receipt.writer_flushed && receipt.pending_notices == 0 && receipt.unresolved_effects == 0);
        second.host.close(receipt.clone(), opts2.clone()).await.map_err(|error| format!("{error:?}"))?;
        lock(&home, false)?;
        let third = present(factory.restart(api::RestartReason::Drained { receipt }, api::IdempotencyKey("restart-third".into()), opts2.clone()).await.map_err(|error| format!("{error:?}"))?)?;
        assert_eq!(third.negotiated.generation.0, g1.0 + 2);
        let ancient = present(factory.restart(reason1, key1, opts1.clone()).await.map_err(|error| format!("{error:?}"))?)?;
        assert_eq!(ancient.negotiated.generation, second.negotiated.generation);
        assert_eq!(ancient.host.health(), api::GenerationHealth::Closed);
        assert!(opened.host.list_projects(&api::OwnerAuthority, page.clone(), opts1).await.is_err());
        assert!(ancient.host.list_projects(&api::OwnerAuthority, page, opts2).await.is_err());
        assert_eq!(third.host.health(), api::GenerationHealth::Prepared);
        let opts3 = call_options(third.negotiated.generation, Duration::from_secs(30));
        let empty = third.host.drain(opts3.clone()).await.map_err(|error| format!("{error:?}"))?;
        assert!(!empty.writer_flushed);
        third.host.close(empty, opts3).await.map_err(|error| format!("{error:?}"))?;
        lock(&home, false)?;
        assert!(!home.join("endpoint.json").exists());
        println!("ok - replay after a later generation returns the immutable closed original, without opening another writer");
        std::fs::write(root.join("passed"), "three independent public contracts passed; outside lease and endpoint closure witnessed")?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
