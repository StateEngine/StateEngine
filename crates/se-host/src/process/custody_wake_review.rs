//! Reviewer-owned release-wake schedules. Native exit witnesses are typed
//! fixtures here; public native lifecycle qualification is a separate consumer.
use super::*;
use crate::process::{owned::LifecycleMetadata, owned::Work, supervisor::Job};
use std::{future::Future, sync::Mutex, task::Poll};
#[path = "../../tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

type Check = std::result::Result<(), Box<dyn std::error::Error>>;

fn work(f: &Fixture) -> std::result::Result<Work, Box<dyn std::error::Error>> {
    let meta = LifecycleMetadata {
        project: se_types::Named {
            id: f.project.clone(),
            name: "Fixture".into(),
        },
        agent: se_types::Named {
            id: f.a.clone(),
            name: "Fixture".into(),
        },
        owner: f.owner.clone(),
        session: session::session()?,
        lifecycle: se_types::LifecycleId::from_parts(
            1_700_000_000_000 + fixture::serial(),
            [71; 10],
        )?,
        request: se_types::IdempotencyKey::new("release-wake")?,
        conversation: se_types::Read::Absent {
            checked: "no provider in the scheduling fixture".into(),
        },
        model: None,
        provider: se_store::Provider::Claude,
        capture: false,
        attended: false,
    };
    let mut work = Work::recovered(meta, f.owner_project());
    work.session_retired = true;
    work.process_retired = true;
    work.native_already_reconciled = true;
    work.capture_flushed = true;
    work.cleanup_files_known = true;
    Ok(work)
}

fn witness(work: &Work, coordinator: &LaunchCoordinator) -> se_proc::StopWitness {
    #[cfg(windows)]
    let scope = se_proc::ScopeIdentity::WindowsJob {
        host: coordinator.host,
        name: "scheduling-fixture".into(),
    };
    #[cfg(target_os = "linux")]
    let scope = se_proc::ScopeIdentity::LinuxPrepared { nonce: [71; 16] };
    #[cfg(target_os = "macos")]
    let scope = se_proc::ScopeIdentity::MacOsPrepared { nonce: [71; 16] };
    let _ = coordinator;
    se_proc::StopWitness {
        lifecycle: work.meta.lifecycle.clone(),
        root: se_proc::RootWitness::NoChildCreated,
        scope: scope.clone(),
        scope_exit: se_proc::ScopeObservation {
            scope,
            remaining: se_proc::RemainingScope {
                population: se_proc::Population::Empty,
                known_live: vec![],
                extent: se_proc::EnumerationExtent::Complete,
                observed_at_unix_ns: 1,
            },
            exit_basis: Some(se_proc::ScopeExitBasis::ObservedEmpty),
        },
        observed_at_unix_ns: 1,
        guarantee: se_proc::ContainmentGuarantee::KernelScope {
            explicit_breakaway: false,
        },
    }
}

async fn pending(future: std::pin::Pin<&mut impl Future<Output = ()>>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "unrelated lifecycle received a wake"
        );
        Poll::Ready(())
    })
    .await;
}

fn job(work: Work) -> Arc<Job> {
    Arc::new(Job {
        intent: [0; 32],
        target: (work.meta.project.id.clone(), work.meta.agent.id.clone()),
        session: work.meta.session.clone(),
        lifecycle: work.meta.lifecycle.clone(),
        plan: None,
        takeover: None,
        wake: work.wake.clone(),
        state: tokio::sync::Mutex::new(work),
        ready: tokio::sync::watch::channel(None).0,
        settled: std::sync::atomic::AtomicBool::new(true),
        mail_pending: std::sync::atomic::AtomicBool::new(false),
        capture_pending: std::sync::atomic::AtomicBool::new(false),
        task: Mutex::new(None),
        fault: Mutex::new(None),
    })
}

async fn finish_schedules(coordinator: &Arc<LaunchCoordinator>, f: &Fixture) -> Check {
    let mut observed = Vec::new();
    for registered in [true, false] {
        let mut old = work(f)?;
        let wake = old.wake.clone();
        let mut waiting = std::pin::pin!(super::monitor_wake(&wake.event, None));
        if registered {
            pending(waiting.as_mut()).await;
        }
        let proof = witness(&old, coordinator);
        coordinator.finish(&mut old, proof, &bound()?).await?;
        assert!(old.released && old.process.is_none());
        let woke = tokio::time::timeout(Duration::from_millis(100), waiting)
            .await
            .is_ok();
        println!("wake-control registered={registered} woke={woke}");
        observed.push(woke);
        // Even a spare notify_one permit belongs only to the old released Work.
        let fresh = work(f)?;
        assert!(!Arc::ptr_eq(&old.wake, &fresh.wake));
        let mut fresh_wait = std::pin::pin!(super::monitor_wake(&fresh.wake.event, None));
        pending(fresh_wait.as_mut()).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), coordinator.monitor(job(old)))
                .await
                .is_ok()
        );
        pending(fresh_wait.as_mut()).await;
    }
    if !observed.into_iter().all(|woke| woke) {
        return Err("successful finish did not wake every monitor schedule".into());
    }
    Ok(())
}

fn run_schedules(explicit_release: bool) -> Check {
    let initialized = crate::initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut host = crate::HostedRuntime::prepare(
            initialized,
            start(&f)?,
            runtime.handle().clone(),
            &bound()?,
        )
        .await?;
        configure_private_listener(&mut host)?;
        let (coordinator, reconciliation) = LaunchCoordinator::install(
            &mut host,
            crate::ProcessOptions {
                helper_executable: se_types::NativePath::from_local(std::env::current_exe()?)?,
                linux_delegation: se_proc::LinuxDelegation::CurrentScope,
                maximum_sessions: 2,
            },
            &bound()?,
        )
        .await?;
        assert!(reconciliation.unproved.is_empty());
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let client = async {
            let result = if explicit_release {
                release_schedules(&coordinator, &f).await
            } else {
                finish_schedules(&coordinator, &f).await
            };
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        assert!(
            report.transport_closed
                && report.endpoint_retired
                && report.pending.is_empty()
                && report.errors.is_empty(),
            "fixture host shutdown: {:?} {:?}",
            report.pending,
            report.errors
        );
        result
    })
}

// This typed uncontained reservation carries no native signalling authority.
// Windows jobs cannot be explicitly released; the shared release state machine
// is exercised with the same encoded reservation on every platform.
async fn unresolved_reservation(
    coordinator: &Arc<LaunchCoordinator>,
    f: &Fixture,
    work: &Work,
) -> Check {
    use se_proc::{
        Checkpoint, CheckpointKind, CheckpointPrincipal, LaunchReservation, ReservationParent,
        RootPublication,
    };
    use se_store::{
        Actor, ContainmentFact, EventBody, NativeCustody, ProcessIdentityRecord, ProcessState,
        RecordedIdentity, RootIdentityState, WriterClient,
    };
    let mut owner = coordinator.owner.clone();
    owner.boot = se_proc::BootIdentity::Linux { boot_id: [73; 16] };
    owner.start = se_proc::StartIdentity::Linux { start_ticks: 1 };
    let reservation = LaunchReservation {
        format_version: 1,
        lifecycle: work.meta.lifecycle.clone(),
        host: coordinator.host,
        owner,
        generation: coordinator.options.epoch.generation,
        scope_nonce: [71; 16],
        parent: ReservationParent::LinuxTracked,
        created_at_unix_ns: 1,
    };
    let checkpoint = Checkpoint {
        format_version: 1,
        lifecycle: work.meta.lifecycle.clone(),
        principal: CheckpointPrincipal::Agent(f.a.clone()),
        session: Some(work.meta.session.clone()),
        root_identity: RootPublication::NoChildCreated,
        checkpoint: CheckpointKind::Reservation(reservation),
    };
    let identity = ProcessIdentityRecord {
        record: work.meta.lifecycle.clone(),
        principal: Actor::Agent(f.a.clone()),
        session: Some(work.meta.session.clone()),
        root_identity: RootIdentityState::NoChildCreated,
        instance: RecordedIdentity::Absent {
            reason: "typed reservation has no native root".into(),
        },
        custody: NativeCustody {
            format_version: 1,
            record: se_proc::encode_checkpoint(&checkpoint)?,
        },
        containment: ContainmentFact::Uncontained {
            cause: se_store::ContainmentCause::NoDelegation,
            observed_at_us: 1,
            probe: None,
        },
    };
    let receipt = coordinator
        .store
        .writer
        .submit(f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "release-wake-{}",
                fixture::serial()
            ))?),
            vec![
                session::prepared(f, &work.meta.session, &f.a),
                EventBody::ProcessRegistered {
                    identity: Box::new(identity.clone()),
                    initial: ProcessState::Starting,
                },
            ],
        )?)?
        .await?;
    let transition = |revision, from, to| -> std::result::Result<_, Box<dyn std::error::Error>> {
        Ok(EventBody::ProcessTransition {
            process: identity.record.clone(),
            identity: Box::new(identity.clone()),
            expected: fixture::revision(revision)?,
            from,
            to,
            observation: receipt.primary_event.clone(),
            outcome: "typed release scheduling fixture".into(),
            containment: identity.containment.clone(),
        })
    };
    coordinator
        .store
        .writer
        .submit(f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "release-wake-{}",
                fixture::serial()
            ))?),
            vec![
                transition(1, ProcessState::Starting, ProcessState::StopRequested)?,
                transition(2, ProcessState::StopRequested, ProcessState::StopUnproved)?,
            ],
        )?)?
        .await?;
    Ok(())
}

fn release_row(work: &Work) -> se_core::ops::agent_stop::AgentStopResult {
    use se_core::ops::agent_stop::*;
    AgentStopResult {
        target: StopTarget {
            project: work.meta.project.clone(),
            agent: work.meta.agent.clone(),
            session_id: Some(work.meta.session.clone()),
            launch_id: None,
            provider: se_types::Provider::Claude,
            process: None,
        },
        result: "unwitnessed".into(),
        event_id: None,
        method: None,
        witness: StopWitness {
            state: "unwitnessed".into(),
            method: None,
            observed_at: None,
            detail: None,
        },
        population: "unknown".into(),
        population_reason: None,
        ownership_release: None,
        remaining: vec![],
        enumeration: "unavailable".into(),
        capture: StopCapture {
            flushed: false,
            last_event_id: None,
        },
        resume: StopResume {
            state: "unavailable".into(),
            reason: None,
            conversation_id: None,
            provider: se_types::Provider::Claude,
            model: None,
            command: String::new(),
            argv: vec![],
        },
    }
}

async fn release_schedules(coordinator: &Arc<LaunchCoordinator>, f: &Fixture) -> Check {
    let mut observed = Vec::new();
    for registered in [true, false] {
        let mut old = work(f)?;
        unresolved_reservation(coordinator, f, &old).await?;
        let wake = old.wake.clone();
        let mut waiting = std::pin::pin!(super::monitor_wake(&wake.event, None));
        if registered {
            pending(waiting.as_mut()).await;
        }
        let mut row = release_row(&old);
        coordinator
            .release_target(&mut old, &mut row, &bound()?)
            .await?;
        assert!(old.released && old.process.is_none());
        assert_eq!(row.result, "ownership-released");
        assert_eq!(row.witness.state, "unwitnessed");
        assert_eq!(row.population, "unknown");
        assert!(row.ownership_release.is_some());
        let woke = tokio::time::timeout(Duration::from_millis(100), waiting)
            .await
            .is_ok();
        println!("release-wake-control registered={registered} woke={woke}");
        observed.push(woke);
        let fresh = work(f)?;
        assert!(!Arc::ptr_eq(&old.wake, &fresh.wake));
        let mut fresh_wait = std::pin::pin!(super::monitor_wake(&fresh.wake.event, None));
        pending(fresh_wait.as_mut()).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), coordinator.monitor(job(old)))
                .await
                .is_ok()
        );
        pending(fresh_wait.as_mut()).await;
    }
    if !observed.into_iter().all(|woke| woke) {
        return Err("successful ownership release did not wake every monitor schedule".into());
    }
    Ok(())
}

#[test]
fn completed_custody_wakes_registered_and_late_monitors_without_crossing_lifecycles() -> Check {
    run_schedules(false)
}
#[test]
fn explicit_release_wakes_registered_and_late_monitors_without_claiming_exit() -> Check {
    run_schedules(true)
}
