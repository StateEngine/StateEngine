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
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(30);

pub(super) struct OwnerInputs {
    pub(super) runtime: Handle,
    pub(super) home: PathBuf,
    pub(super) limits: api::Limits,
    pub(super) generation: api::Generation,
    pub(super) epoch: api::HostEpoch,
    pub(super) timeout: Duration,
}
pub(super) type Started = core::Result<(HostedRouter, LocalStop)>;

pub(super) fn owner_thread(
    inputs: OwnerInputs,
) -> (
    oneshot::Receiver<Started>,
    oneshot::Receiver<api::DrainReceipt>,
) {
    let (ready, ready_rx) = oneshot::channel();
    let (exited, exited_rx) = oneshot::channel();
    let runtime = inputs.runtime.clone();
    let spawned = std::thread::Builder::new()
        .name("stateengine-embedded-host".into())
        .spawn(move || {
            runtime.block_on(async move {
                let generation = inputs.generation;
                let (host, listener, stop, router) = match take_ownership(inputs).await {
                    Ok(started) => started,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if let Err(Ok((_router, stop))) = ready.send(Ok((router, stop))) {
                    // Activation stopped waiting: nobody holds this stop, so
                    // end the generation now instead of serving unreachably.
                    stop.request();
                }
                let exit = host.serve(listener).await;
                let receipt = match support::deadline(SHUTDOWN_BUDGET) {
                    Ok(deadline) => {
                        let report = exit.finish(&deadline).await;
                        // Pending obligations and close errors stay unresolved;
                        // the writer counts as flushed only when storage drained.
                        let unresolved = (report.pending.len() + report.errors.len()) as u64;
                        api::DrainReceipt {
                            generation,
                            pending_notices: 0,
                            unresolved_effects: unresolved,
                            writer_flushed: matches!(report.storage, core::Read::Present { .. })
                                && unresolved == 0,
                        }
                    }
                    Err(_) => api::DrainReceipt {
                        generation,
                        pending_notices: 0,
                        unresolved_effects: 1,
                        writer_flushed: false,
                    },
                };
                let _ = exited.send(receipt);
            });
        });
    if spawned.is_err() {
        // Both receivers then report a closed channel: activation fails by name.
    }
    (ready_rx, exited_rx)
}

async fn take_ownership(
    inputs: OwnerInputs,
) -> core::Result<(
    HostedRuntime,
    crate::HostedListener,
    LocalStop,
    HostedRouter,
)> {
    let deadline = support::deadline(inputs.timeout)?;
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
    // Another owner may have taken the store between open and activate.
    if host.generation().get() != inputs.generation.0 {
        return Err(core::SeError::invalid(
            "host generation",
            "the owner generation this open negotiated; reopen and retry",
        ));
    }
    host.restore_transcripts(&deadline).await?;
    host.configure(config)?;
    let stop = host.local_stop();
    let listener = host.listen(inputs.runtime, &deadline).await?;
    let router = host.router()?;
    Ok((host, listener, stop, router))
}
