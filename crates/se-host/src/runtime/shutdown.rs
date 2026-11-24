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
        // Leave part of the original request clock for per-agent facts, the
        // reply and protected close receipt even if native cleanup times out.
        let work_deadline = work_deadline(&drain_deadline);
        let stages = Stages::start();
        let errors: Vec<_> = self.failure.take().into_iter().collect();
        let mut unresolved = Unresolved {
            pending: errors.iter().map(ToString::to_string).collect(),
            errors,
        };
        let remote_closed = self
            .close_remote_transports(&work_deadline, &mut unresolved)
            .await;
        let before = self.resume_inventory(&work_deadline, &mut unresolved).await;
        let agents_stopped = self
            .stop_native(
                before.as_ref(),
                &work_deadline,
                &drain_deadline,
                &mut unresolved,
            )
            .await;
        let stops = self
            .observe_stops(before.as_ref(), &drain_deadline, &mut unresolved)
            .await;
        let gates = agents_stopped && before.is_some() && remote_closed;
        let storage = self
            .drain(agents_stopped, gates, &work_deadline, &mut unresolved)
            .await;
        stages.mark(
            "storage-drain-return",
            matches!(&storage, Read::Present { .. }),
        );
        let writer_joined = self.record_writes(&storage, &mut unresolved);
        let close_request = self.close_request(&mut unresolved);
        if let Some(stop) = self.stop.take()
            && let Some((epoch, generation, key)) = &close_request
        {
            let reply = RuntimeStopReply {
                epoch: epoch.clone(),
                generation: *generation,
                key: key.clone(),
                outcome: RuntimeStopOutcome::Facts {
                    achieved: self.achieved(agents_stopped, before.is_some(), writer_joined),
                    retained_resume: before.map_or_else(Vec::new, |value| value.resumes),
                    pending: unresolved.pending.clone(),
                },
            };
            let result = stop.reply(&reply, &drain_deadline).await;
            stages.mark("stop-reply-return", result.is_ok());
            if let Err(error) = result {
                unresolved.fail(
                    format!("Stop reply delivery remains unconfirmed: {error}"),
                    error,
                );
            }
        }
        let pool = self.runtime.blocking_pool();
        let (transport_closed, endpoint_retired) =
            close_transport(self.listener, &pool, remote_closed, stages, &mut unresolved).await;
        if let Some((epoch, generation, key)) = close_request {
            let record = crate::client::closure::RuntimeClosure {
                schema: 1,
                epoch,
                generation,
                key,
                resources_closed: unresolved.pending.is_empty()
                    && transport_closed
                    && endpoint_retired
                    && writer_joined
                    && agents_stopped,
                stops,
                pending: unresolved.pending.clone(),
            };
            publish_closure(
                &self.runtime,
                &pool,
                &drain_deadline,
                record,
                &mut unresolved,
            )
            .await;
        }
        HostShutdown {
            runtime: self.runtime,
            storage,
            transport_closed,
            endpoint_retired,
            pending: unresolved.pending,
            errors: unresolved.errors,
        }
    }
    /// Remote control, its mail source and forwards each close within the work
    /// clock; any one still open withholds storage drain and transport closure.
    async fn close_remote_transports(&self, work: &Deadline, unresolved: &mut Unresolved) -> bool {
        let waits = &self.runtime.execution.mail_waits;
        #[cfg(feature = "remote")]
        let remote_closed = match waits.remote_control() {
            Some(control) => unresolved.closed(close_remote(work, control.close()).await),
            None => true,
        };
        #[cfg(not(feature = "remote"))]
        let remote_closed = true;
        let source_closed = match waits.remote() {
            Some(broker) => unresolved.closed(close_remote(work, broker.close()).await),
            None => true,
        };
        #[cfg(feature = "remote")]
        let forwards_closed = unresolved.closed(close_remote(work, waits.forwards().close()).await);
        #[cfg(not(feature = "remote"))]
        let forwards_closed = true;
        remote_closed && source_closed && forwards_closed
    }
    async fn resume_inventory(
        &self,
        work: &Deadline,
        unresolved: &mut Unresolved,
    ) -> Option<facts::Before> {
        match facts::before(&self.runtime, work).await {
            Ok(value) => Some(value),
            Err(error) => {
                unresolved.fail(format!(
                    "Shutdown resume inventory remains unreadable: {error}. Storage drain is withheld. Preserve the data home and repair the original session metadata before retrying cleanup. An embedded owner retains its writer and lease; a standalone process may exit with unresolved providers."
                ), error);
                None
            }
        }
    }
    /// Native custody first, while trusted capture is still open for its
    /// final capture; an incomplete stop keeps the lease and the writer.
    async fn stop_native(
        &self,
        before: Option<&facts::Before>,
        work: &Deadline,
        drain: &Deadline,
        unresolved: &mut Unresolved,
    ) -> bool {
        let custody_complete = match self.runtime.execution.custody.get().cloned() {
            None => before.is_some_and(|value| !value.had_process_records),
            Some(custody) => match custody.shutdown(work).await {
                Ok(report) => {
                    unresolved.pending.extend(report.pending);
                    report.complete
                }
                Err(error) => {
                    unresolved.fail(
                        format!("Native custody shutdown remains pending: {error}"),
                        error,
                    );
                    false
                }
            },
        };
        if !custody_complete {
            unresolved.pending.push("Native custody shutdown is incomplete or its observer is unavailable; retain the lease and writer.".into());
            return false;
        }
        match facts::remaining(&self.runtime, drain).await {
            Ok(false) => true,
            Ok(true) => {
                unresolved.pending.push("Recorded native custody remains unresolved after the shutdown coordinator returned.".into());
                false
            }
            Err(error) => {
                unresolved.fail(
                    format!("Shutdown native inventory remains unreadable: {error}"),
                    error,
                );
                false
            }
        }
    }
    /// Each saved lifecycle's own exit fact; an unproved exit stays pending.
    async fn observe_stops(
        &self,
        before: Option<&facts::Before>,
        drain: &Deadline,
        unresolved: &mut Unresolved,
    ) -> Vec<crate::client::closure::AgentClosure> {
        let stops = if let Some(before) = before {
            agents::observe(&self.runtime, &before.targets, drain).await
        } else {
            Vec::new()
        };
        for target in &stops {
            if target.witness.is_none() {
                unresolved.pending.push(format!(
                    "Agent {} lifecycle {} exit remains unproved: {}. Preserve the data home and retry cleanup for this saved agent. If an embedded owner still holds the lease, use controlled application recovery.",
                    target.agent,
                    target.lifecycle,
                    target
                        .reason
                        .as_deref()
                        .unwrap_or("no native exit checkpoint")
                ));
            }
        }
        stops
    }
    /// Join native collectors, then drain storage only when every custody gate holds.
    async fn drain(
        &mut self,
        agents_stopped: bool,
        gates: bool,
        work: &Deadline,
        unresolved: &mut Unresolved,
    ) -> Read<StorageDrainReport> {
        let collector_joined = if agents_stopped {
            match self
                .runtime
                .execution
                .ownership_fault
                .join_native(work)
                .await
            {
                Ok(()) => true,
                Err(error) => {
                    unresolved.fail(
                        format!("Native collector tasks remain unjoined: {error}"),
                        error,
                    );
                    false
                }
            }
        } else {
            false
        };
        let ownership_failed = self
            .runtime
            .execution
            .ownership_fault
            .failed
            .load(std::sync::atomic::Ordering::Acquire);
        if ownership_failed {
            unresolved.pending.push("Writer or shared native collector failed; retain the exact lease, writer and native custody until controlled application restart.".into());
        }
        if !(gates && !ownership_failed && collector_joined) {
            return Read::Unreadable {
                source: "host storage drain".into(),
                reason:
                    "native custody, remote transport closure or resume preservation is incomplete; the host retains its lease and writer"
                        .into(),
                error: None,
            };
        }
        match self.runtime.drain_storage(work).await {
            Ok(report) => {
                unresolved.pending.extend(report.pending.iter().cloned());
                if !matches!(report.backup, Read::Present { .. }) {
                    unresolved
                        .pending
                        .push("Storage clean-close backup remains pending.".into());
                }
                Read::Present { value: report }
            }
            Err(error) => {
                unresolved
                    .pending
                    .push(format!("Storage drain remains pending: {error}"));
                let failure = Read::Unreadable {
                    source: "host storage drain".into(),
                    reason: error.to_string(),
                    error: Some(Box::new(error.body.clone())),
                };
                unresolved.errors.push(error);
                failure
            }
        }
    }
    /// Names every unresolved original write and reports whether the writer joined.
    fn record_writes(
        &self,
        storage: &Read<StorageDrainReport>,
        unresolved: &mut Unresolved,
    ) -> bool {
        match self.runtime.execution.pending_writes.describe() {
            Ok(identities) => unresolved.pending.extend(identities),
            Err(error) => unresolved.fail(error.to_string(), error),
        }
        let writer_joined = match storage {
            Read::Present { value } => value.writer_joined,
            _ => self.runtime.flush.is_some(),
        };
        if let Some(flush) = &self.runtime.flush {
            for identity in &flush.indeterminate {
                unresolved.pending.push(format!(
                    "Indeterminate original write identity: {identity:?}"
                ));
            }
        }
        writer_joined
    }
    fn close_request(
        &self,
        unresolved: &mut Unresolved,
    ) -> Option<(
        se_types::HostEpoch,
        se_types::Generation,
        se_types::IdempotencyKey,
    )> {
        match self.stop.as_ref().map(|stop| stop.request()).transpose() {
            Ok(request) => request.map(|request| {
                (
                    request.expected_epoch.clone(),
                    request.generation,
                    request.key.clone(),
                )
            }),
            Err(error) => {
                unresolved.fail(
                    format!("Stop request metadata remains unavailable: {error}"),
                    error,
                );
                None
            }
        }
    }
    fn achieved(
        &self,
        agents_stopped: bool,
        resume_saved: bool,
        writer_joined: bool,
    ) -> Vec<RuntimeStopFact> {
        let mut achieved = Vec::new();
        if agents_stopped {
            achieved.push(RuntimeStopFact::AgentsStopped);
        }
        if resume_saved {
            achieved.push(RuntimeStopFact::ResumeSaved);
        }
        if writer_joined {
            achieved.push(RuntimeStopFact::WriterJoined);
        }
        if agents_stopped
            && self
                .runtime
                .flush
                .as_ref()
                .is_some_and(|value| value.pending_requests == 0 && value.indeterminate.is_empty())
        {
            achieved.extend([
                RuntimeStopFact::CaptureFlushed,
                RuntimeStopFact::DebtFlushed,
            ]);
        }
        achieved
    }
}
/// What shutdown could not prove. Every unresolved fact keeps its operator
/// note, in order; errors among them also retain native custody.
struct Unresolved {
    pending: Vec<String>,
    errors: Vec<SeError>,
}
impl Unresolved {
    fn fail(&mut self, note: String, error: SeError) {
        self.pending.push(note);
        self.errors.push(error);
    }
    fn closed(&mut self, result: Result<()>) -> bool {
        result
            .map_err(|error| self.fail(error.to_string(), error))
            .is_ok()
    }
}
/// Fixed-stage Windows shutdown diagnostics; elsewhere marking is a no-op.
#[derive(Clone, Copy)]
struct Stages {
    #[cfg(windows)]
    started: std::time::Instant,
}
impl Stages {
    fn start() -> Self {
        let stages = Self {
            #[cfg(windows)]
            started: std::time::Instant::now(),
        };
        stages.mark("storage-drain-start", true);
        stages
    }
    #[cfg_attr(not(windows), allow(clippy::unused_self))]
    fn mark(self, stage: &str, succeeded: bool) {
        #[cfg(windows)]
        trace(stage, self.started, succeeded);
        #[cfg(not(windows))]
        let _ = (stage, succeeded);
    }
}
/// Release native transport and retire the endpoint after the stop reply.
async fn close_transport(
    listener: HostedListener,
    pool: &BlockingPool,
    remote_closed: bool,
    stages: Stages,
    unresolved: &mut Unresolved,
) -> (bool, bool) {
    let (closed, retired) = listener.finish_transport(pool).await;
    let transport_closed = closed.is_ok() && remote_closed;
    let endpoint_retired = retired.is_ok();
    stages.mark("shutdown-return", transport_closed && endpoint_retired);
    for (stage, result) in [
        ("Native transport release", closed),
        ("Endpoint retirement", retired),
    ] {
        if let Err(error) = result {
            unresolved.fail(format!("{stage} remains pending: {error}"), error);
        }
    }
    (transport_closed, endpoint_retired)
}
async fn publish_closure(
    runtime: &HostedRuntime,
    pool: &BlockingPool,
    deadline: &Deadline,
    record: crate::client::closure::RuntimeClosure,
    unresolved: &mut Unresolved,
) {
    let lease = runtime.lease.clone();
    let result = pool
        .run_owned(deadline, move || {
            crate::client::closure::publish(&lease.files, lease.files.0.root(), &record)
        })
        .await;
    if let Err(error) = result {
        unresolved.fail(format!("Protected post-transport close receipt remains unproved: {error}; retain this runtime's lease."), error);
    }
}
async fn close_remote(
    bound: &Deadline,
    close: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    tokio::time::timeout(bound.remaining()?,close).await.map_err(|_|SeError::invalid("remote transport closure","joined native tasks within the original drain clock; retain writer and lease before retrying cleanup"))?
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

/// Cleanup may consume most of the caller's clock, but not its only chance to
/// learn which lifecycle remains unresolved. Never extend an expired bound.
fn work_deadline(bound: &Deadline) -> Deadline {
    match bound.remaining() {
        Ok(remaining) => {
            let reserve = (remaining / 4).min(Duration::from_secs(2));
            bound
                .stage(remaining - reserve)
                .unwrap_or_else(|_| bound.clone())
        }
        Err(_) => bound.clone(),
    }
}
