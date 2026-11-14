//! The owner thread of one embedded generation. HostedRuntime's futures are
//! not Send, so this thread drives prepare, listen, serve and finish with
//! block_on on SE Code's runtime handle, exactly as the standalone child
//! drives its own; it reports readiness once and its shutdown once.
use super::support;
use crate::{HostedRouter, HostedRuntime, LocalStop};
use se_types as core;
use secode_stateengine_api as api;
use std::{path::PathBuf, time::Duration};
use tokio::{runtime::Handle, sync::oneshot};

/// The standalone child's finite shutdown join budget.
pub(super) const SHUTDOWN_BUDGET: Duration = Duration::from_secs(30);

/// References independent of the owner's polled future. A panic cannot drop
/// the lease or collector; only an actual successful owner join clears them.
pub(super) struct RetainedResources {
    _execution: crate::runtime::ExecutionContext,
    _sources: crate::runtime::TranscriptBindings,
    // Field drop order keeps the lease until the writer/native collector and
    // transcript pins above have actually released their references.
    _lease: std::sync::Arc<crate::runtime::HostLease>,
}
pub(super) struct OwnerInputs {
    pub(super) owner: std::sync::Weak<super::Generation>,
    pub(super) runtime: Handle,
    pub(super) home: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(super) helper_executable: PathBuf,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(super) linux_delegation: api::LinuxDelegation,
    pub(super) limits: api::Limits,
    pub(super) generation: api::Generation,
    pub(super) epoch: api::HostEpoch,
    pub(super) timeout: Duration,
    pub(super) resources: std::sync::Arc<std::sync::Mutex<Option<RetainedResources>>>,
    pub(super) poisoned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(super) quarantined: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(super) changed: std::sync::Arc<tokio::sync::Notify>,
    pub(super) router_fence:
        std::sync::Arc<std::sync::OnceLock<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}
pub(super) type Started = core::Result<(HostedRouter, LocalStop)>;
pub(super) type Stopped = core::Result<api::DrainReceipt>;

pub(super) fn owner_thread(
    inputs: OwnerInputs,
) -> (
    oneshot::Receiver<Started>,
    oneshot::Receiver<Stopped>,
    Option<std::thread::JoinHandle<()>>,
) {
    let (ready, ready_rx) = oneshot::channel();
    let (exited, exited_rx) = oneshot::channel();
    let runtime = inputs.runtime.clone();
    let poisoned = inputs.poisoned.clone();
    let quarantined = inputs.quarantined.clone();
    let fence = inputs.router_fence.clone();
    let changed = inputs.changed.clone();
    let generation_owner = inputs.owner.clone();
    let finished_owner = inputs.owner.clone();
    let completion_runtime = inputs.runtime.clone();
    let (completed, completion) = oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("stateengine-embedded-host".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                runtime.block_on(crate::runtime::tasks::caught(
                    run_owner(inputs, ready, exited),
                    true,
                ))
            }));
            if !matches!(outcome, Ok(Ok(()))) {
                if let Some(owner) = generation_owner.upgrade() {
                    owner.poison_now(true);
                }
                poisoned.store(true, std::sync::atomic::Ordering::Release);
                quarantined.store(true, std::sync::atomic::Ordering::Release);
                if let Some(fence) = fence.get() {
                    fence.store(true, std::sync::atomic::Ordering::Release);
                }
                changed.notify_waiters();
                loop {
                    std::thread::park();
                }
            }
            let _ = completed.send(());
        });
    // External `se down` has no public API caller to join the completed owner.
    // Wait for its one completion event, then use the same actual-join barrier
    // as drain/close. No idle polling or additional waiting native thread.
    completion_runtime.spawn(async move {
        if completion.await.is_ok()
            && let Some(owner) = finished_owner.upgrade()
        {
            owner.join_completed_owner().await;
        }
    });
    if spawned.is_err() {
        // Both receivers then report a closed channel: activation fails by name.
    }
    (ready_rx, exited_rx, spawned.ok())
}

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
async fn run_owner(
    inputs: OwnerInputs,
    ready: oneshot::Sender<Started>,
    exited: oneshot::Sender<Stopped>,
) {
    let served_poison = inputs.poisoned.clone();
    let served_changed = inputs.changed.clone();

    let generation = inputs.generation;
    let retained_owner = inputs.owner.clone();
    let (host, listener, stop, router) = match take_ownership(inputs).await {
        Ok(started) => started,
        Err(error) => {
            if let Some(owner) = retained_owner.upgrade()
                && owner
                    .resources
                    .lock()
                    .map_or(true, |resources| resources.is_some())
            {
                owner.poison_now(true);
            }
            let _ = ready.send(Err(error));
            return;
        }
    };
    #[cfg(feature = "remote")]
    let remote_start = match support::deadline(SHUTDOWN_BUDGET) {
        Ok(deadline) => host.restore_remote_listener(&deadline).await,
        Err(error) => Err(error),
    };
    #[cfg(not(feature = "remote"))]
    let remote_start: core::Result<()> = Ok(());
    if remote_start.is_err() {
        stop.request();
    }
    // Undelivered, or delivered but never claimed, the dropped
    // stop ends this generation instead of serving unreachably.
    let mail_owner = retained_owner.clone();
    let mail_state = retained_owner.upgrade().map(|owner| owner.mail.clone());
    let mail_router = router.clone();
    let mail = retained_owner
        .upgrade()
        .filter(|owner| {
            remote_start.is_ok()
                && owner
                    .negotiated
                    .features
                    .contains(&api::Feature::NativeMail)
        })
        .map(|_| tokio::spawn(super::mail::drive(mail_owner, mail_router)));
    let _ = ready.send(remote_start.map(|()| (router, stop)));
    let exit = host.serve(listener).await;
    if let Some(owner) = retained_owner.upgrade() {
        owner
            .native_fence
            .store(true, std::sync::atomic::Ordering::Release);
    }
    if let Some(mail_state) = mail_state {
        mail_state.close();
    }
    if let Some(mail) = mail
        && mail.await.is_err()
    {
        if let Some(owner) = retained_owner.upgrade() {
            owner.poison_now(true);
        }
        let _ = exited.send(Err(se_core::scope::unreadable(
            "native mail worker",
            "its task did not join cleanly; generation resources remain quarantined",
        )));
        let _retained = exit;
        loop {
            std::thread::park();
        }
    }
    if exit
        .runtime
        .execution
        .ownership_fault
        .failed
        .load(std::sync::atomic::Ordering::Acquire)
    {
        served_poison.store(true, std::sync::atomic::Ordering::Release);
        served_changed.notify_waiters();
    }
    let receipt = match support::deadline(SHUTDOWN_BUDGET) {
        Ok(deadline) => {
            let report = exit.finish(&deadline).await;
            // Pending obligations and close errors stay unresolved;
            // the writer counts as flushed only when storage drained.
            let unresolved = (report.pending.len() + report.errors.len()) as u64;
            let receipt = api::DrainReceipt {
                generation,
                pending_notices: 0,
                unresolved_effects: unresolved,
                writer_flushed: matches!(&report.storage, core::Read::Present { value } if value.writer_joined && value.pending.is_empty())
                    && unresolved == 0,
            };
            if !receipt.writer_flushed {
                // A failed embedded drain cannot drop native custody or
                // free its lease while the application keeps running.
                // The returned incomplete receipt requires controlled
                // application restart; this dedicated owner thread parks.
                let _ = exited.send(Ok(receipt));
                let _retained = report;
                loop {
                    std::thread::park();
                }
            }
            // Drop the successfully closed runtime before publishing
            // drain completion; the external CLI checks the actual lock.
            drop(report);
            receipt
        }
        Err(error) => {
            // Forward the diagnostic through drain's error channel;
            // a library must not print into its embedding application.
            let failure = se_core::scope::unreadable(
                "embedded shutdown budget",
                &format!(
                    "Could not create the shutdown budget: {error}. This runtime retains its writer and lease; preserve the data home and use controlled application restart."
                ),
            );
            let _ = exited.send(Err(failure));
            let _retained = exit;
            loop {
                std::thread::park();
            }
        }
    };
    let _ = exited.send(Ok(receipt));
}

async fn take_ownership(
    inputs: OwnerInputs,
) -> core::Result<(
    HostedRuntime,
    crate::HostedListener,
    LocalStop,
    HostedRouter,
)> {
    require_process_supervision()?;
    let deadline = support::deadline(inputs.timeout)?;
    let poisoned = inputs.poisoned;
    let router_fence = inputs.router_fence;
    let current = support::current_epoch(inputs.epoch.generation.0, &inputs.home)?;
    // The epoch SE Code registered must be this exact process.
    if crate::linked::host_epoch(&current)? != inputs.epoch {
        return Err(core::SeError::invalid(
            "host epoch",
            "this exact SE Code server process and generation",
        ));
    }
    let config = support::load_config(&inputs.home)?;
    let mut host = HostedRuntime::prepare(
        crate::initialize_host_process()?,
        crate::HostStart {
            state_directory: inputs.home,
            epoch: current,
            kind: crate::HostKind::EmbeddedSecode,
            writer: support::writer_options()?,
            limits: support::limits(&inputs.limits, &config)?,
        },
        inputs.runtime.clone(),
        &deadline,
    )
    .await?;
    *inputs.resources.lock().map_err(|_| {
        core::SeError::invalid(
            "retained owner resources",
            "an unpoisoned generation registry",
        )
    })? = Some(RetainedResources {
        _lease: host.lease.clone(),
        _execution: host.execution.clone(),
        _sources: host.sources.clone(),
    });
    // Another owner may have taken the store between open and activate.
    if host.generation().get() != inputs.generation.0 {
        return Err(core::SeError::invalid(
            "host generation",
            "the owner generation this open negotiated; reopen and retry",
        ));
    }
    host.restore_transcripts(&deadline).await?;
    host.configure(config)?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        let linux_delegation = match inputs.linux_delegation {
            api::LinuxDelegation::AutoUserManager => se_proc::LinuxDelegation::AutoUserManager,
            api::LinuxDelegation::CurrentScope => se_proc::LinuxDelegation::CurrentScope,
            api::LinuxDelegation::ExplicitRoot(path) => {
                se_proc::LinuxDelegation::ExplicitRoot(path)
            }
        };
        let (_coordinator, reconciliation) = crate::LaunchCoordinator::install(
            &mut host,
            crate::ProcessOptions {
                helper_executable: core::NativePath::from_local(inputs.helper_executable)?,
                linux_delegation,
                maximum_sessions: crate::ProcessOptions::DEFAULT_MAXIMUM_SESSIONS,
            },
            &deadline,
        )
        .await?;
        for failure in &reconciliation.unproved {
            eprintln!("Agent recovery incomplete; its custody remains fenced: {failure}");
        }
    }
    let stop = host.local_stop();
    #[cfg(feature = "remote")]
    host.prepare_remote_listener(&deadline).await?;
    let listener = host.listen(inputs.runtime, &deadline).await?;
    let router = host.router()?;
    let _ = router_fence.set(std::sync::Arc::clone(&router.fenced));
    if poisoned.load(std::sync::atomic::Ordering::Acquire) {
        router
            .fenced
            .store(true, std::sync::atomic::Ordering::Release);
    }
    Ok((host, listener, stop, router))
}

// Refuse before acquiring a lease, opening a writer or publishing an endpoint.
// Compiling the linked API does not provide native process supervision.
fn require_process_supervision() -> core::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    Err(core::SeError::new(core::Detail::FeatureUnavailable(
        core::details::FeatureUnavailable {
            subject: "embedded host process supervision on macOS".into(),
            reason: "this build implements hosted process supervision only on Linux and Windows".into(),
            next_step: "Use se init, se status and direct saved-state operations on macOS; use a Linux or Windows installation for hosted agent work".into(),
        },
    )))
}
