//! Shared shutdown for standalone children and embedded consumers. Every stage
//! runs even when an earlier stage fails; the returned owner retains custody.
use super::*;
use crate::client::{ClientOptions, endpoint::*, lease::Deadline};
use se_types::{Read, Result, SeError};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
mod agents;
mod facts;

pub struct HostShutdown {
    pub runtime: HostedRuntime,
    pub storage: Read<StorageDrainReport>,
    pub transport_closed: bool,
    pub endpoint_retired: bool,
    pub pending: Vec<String>,
    /// Includes errors retaining native reservations on pending transport close.
    pub errors: Vec<SeError>,
}
impl HostServeExit {
    /// Accepted tasks are already fenced and joined by serve. Drain errors and
    /// a disconnected stop client cannot skip transport or publication cleanup.
    /// Replies precede transport join because their channel is itself an instance.
    pub async fn finish(mut self, drain_deadline: &Deadline) -> HostShutdown {
        // serve has already spent part of this budget joining admitted calls and
        // delivering their replies. A caller may shorten it, never renew it.
        let drain_deadline = self.runtime.shutdown_deadline.as_ref().map_or_else(
            || drain_deadline.clone(),
            |bound| drain_deadline.capped_by(bound),
        );
        #[cfg(windows)]
        let started = std::time::Instant::now();
        #[cfg(windows)]
        trace("storage-drain-start", started, true);
        let mut errors: Vec<_> = self.failure.take().into_iter().collect();
        let mut pending: Vec<_> = errors.iter().map(ToString::to_string).collect();
        let before = match facts::before(&self.runtime, &drain_deadline).await {
            Ok(value) => Some(value),
            Err(error) => {
                pending.push(format!(
                    "Shutdown resume inventory remains unreadable: {error}. Storage drain is withheld; this fenced host retains its writer and lease after retiring the endpoint, so another down cannot retry it. Preserve the data home and repair the original session metadata before controlled application restart/recovery."
                ));
                errors.push(error);
                None
            }
        };
        // Native custody first, while trusted capture is still open for its
        // final capture; an incomplete stop keeps the lease and the writer.
        let custody = self.runtime.execution.custody.get().cloned();
        let custody_complete = match custody {
            None => before
                .as_ref()
                .is_some_and(|value| !value.had_process_records),
            Some(custody) => match custody.shutdown(&drain_deadline).await {
                Ok(report) => {
                    pending.extend(report.pending);
                    report.complete
                }
                Err(error) => {
                    pending.push(format!("Native custody shutdown remains pending: {error}"));
                    errors.push(error);
                    false
                }
            },
        };
        let agents_stopped = if custody_complete {
            match facts::remaining(&self.runtime, &drain_deadline).await {
                Ok(false) => true,
                Ok(true) => {
                    pending.push("Recorded native custody remains unresolved after the shutdown coordinator returned.".into());
                    false
                }
                Err(error) => {
                    pending.push(format!(
                        "Shutdown native inventory remains unreadable: {error}"
                    ));
                    errors.push(error);
                    false
                }
            }
        } else {
            pending.push("Native custody shutdown is incomplete or its observer is unavailable; retain the lease and writer.".into());
            false
        };
        let stops = if let Some(before) = &before {
            agents::observe(&self.runtime, &before.targets, &drain_deadline).await
        } else {
            Vec::new()
        };
        for target in &stops {
            if target.witness.is_none() {
                pending.push(format!(
                    "Agent {} lifecycle {} exit remains unproved: {}. After endpoint retirement this fenced runtime retains the lease; preserve the data home and use controlled application restart/recovery.",
                    target.agent,
                    target.lifecycle,
                    target
                        .reason
                        .as_deref()
                        .unwrap_or("no native exit checkpoint")
                ));
            }
        }
        let drained = if agents_stopped && before.is_some() {
            Some(self.runtime.drain_storage(&drain_deadline).await)
        } else {
            None
        };
        let storage = match drained {
            None => Read::Unreadable {
                source: "host storage drain".into(),
                reason:
                    "native custody shutdown or resume preservation is incomplete; the host retains its lease and writer"
                        .into(),
                error: None,
            },
            Some(result) => match result {
                Ok(report) => {
                    pending.extend(report.pending.iter().cloned());
                    if !matches!(report.backup, Read::Present { .. }) {
                        pending.push("Storage clean-close backup remains pending.".into());
                    }
                    Read::Present { value: report }
                }
                Err(error) => {
                    pending.push(format!("Storage drain remains pending: {error}"));
                    let failure = Read::Unreadable {
                        source: "host storage drain".into(),
                        reason: error.to_string(),
                        error: Some(Box::new(error.body.clone())),
                    };
                    errors.push(error);
                    failure
                }
            },
        };
        #[cfg(windows)]
        trace(
            "storage-drain-return",
            started,
            matches!(&storage, Read::Present { .. }),
        );
        match self.runtime.execution.pending_writes.describe() {
            Ok(identities) => pending.extend(identities),
            Err(error) => {
                pending.push(error.to_string());
                errors.push(error);
            }
        }
        let writer_joined = match &storage {
            Read::Present { value } => value.writer_joined,
            _ => self.runtime.flush.is_some(),
        };
        if let Some(flush) = &self.runtime.flush {
            for identity in &flush.indeterminate {
                pending.push(format!(
                    "Indeterminate original write identity: {identity:?}"
                ));
            }
        }
        let close_request = self.stop.as_ref().map(|stop| {
            (
                stop.request().expected_epoch.clone(),
                stop.request().generation,
                stop.request().key.clone(),
            )
        });
        if let Some(stop) = self.stop.take() {
            let mut achieved = Vec::new();
            if agents_stopped {
                achieved.push(RuntimeStopFact::AgentsStopped);
            }
            if before.is_some() {
                achieved.push(RuntimeStopFact::ResumeSaved);
            }
            if writer_joined {
                achieved.push(RuntimeStopFact::WriterJoined);
            }
            if agents_stopped
                && self.runtime.flush.as_ref().is_some_and(|value| {
                    value.pending_requests == 0 && value.indeterminate.is_empty()
                })
            {
                achieved.extend([
                    RuntimeStopFact::CaptureFlushed,
                    RuntimeStopFact::DebtFlushed,
                ]);
            }
            let reply = RuntimeStopReply {
                epoch: stop.request().expected_epoch.clone(),
                generation: stop.request().generation,
                key: stop.request().key.clone(),
                outcome: RuntimeStopOutcome::Facts {
                    achieved,
                    retained_resume: before.map_or_else(Vec::new, |value| value.resumes),
                    pending: pending.clone(),
                },
            };
            let result = match cleanup_deadline() {
                Ok(bound) => stop.reply(&reply, &bound).await,
                Err(error) => Err(error),
            };
            #[cfg(windows)]
            trace("stop-reply-return", started, result.is_ok());
            if let Err(error) = result {
                pending.push(format!("Stop reply delivery remains unconfirmed: {error}"));
                errors.push(error);
            }
        }
        let pool = self.runtime.blocking_pool();
        let (closed, retired) = self.listener.finish_transport(&pool).await;
        let transport_closed = closed.is_ok();
        let endpoint_retired = retired.is_ok();
        #[cfg(windows)]
        trace(
            "shutdown-return",
            started,
            transport_closed && endpoint_retired,
        );
        for (stage, result) in [
            ("Native transport release", closed),
            ("Endpoint retirement", retired),
        ] {
            if let Err(error) = result {
                pending.push(format!("{stage} remains pending: {error}"));
                errors.push(error);
            }
        }
        if let Some((epoch, generation, key)) = close_request {
            let record = crate::client::closure::RuntimeClosure {
                schema: 1,
                epoch,
                generation,
                key,
                resources_closed: pending.is_empty()
                    && transport_closed
                    && endpoint_retired
                    && writer_joined
                    && agents_stopped,
                stops,
                pending: pending.clone(),
            };
            let lease = self.runtime.lease.clone();
            let result = pool
                .run_owned(&drain_deadline, move || {
                    crate::client::closure::publish(&lease.files, lease.files.0.root(), &record)
                })
                .await;
            if let Err(error) = result {
                pending.push(format!("Protected post-transport close receipt remains unproved: {error}; retain this runtime's lease."));
                errors.push(error);
            }
        }
        HostShutdown {
            runtime: self.runtime,
            storage,
            transport_closed,
            endpoint_retired,
            pending,
            errors,
        }
    }
}
/// Private Windows host diagnostics contain only fixed stages and measured time.
#[cfg(windows)]
pub(crate) fn trace(stage: &str, started: std::time::Instant, succeeded: bool) {
    eprintln!(
        "host shutdown pid={} stage={stage} elapsed_ms={} succeeded={succeeded}",
        std::process::id(),
        started.elapsed().as_millis()
    );
}
/// Cleanup gets its own finite budget after a possibly exhausted drain bound.
/// Stop-client cancellation never cancels ownership cleanup.
pub(crate) fn cleanup_deadline() -> Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
