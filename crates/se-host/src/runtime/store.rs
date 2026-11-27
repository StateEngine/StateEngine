//! Finite planning/submission jobs. A transaction never crosses an await and
//! an accepted FULL commit is observed before the native supervisor proceeds.
use crate::BlockingPool;
use crate::{BlockingClass, client::lease::Deadline};
use se_core::{admission::read_scope, commit::Cx, dispatch::Kernel, store_error::store_error};
use se_store::{Admission, AtomicBatch, CommitReceipt, Snapshot, SqliteSnapshot, WriterClient};
use se_types::{Generation, Read, Result};
use std::sync::Arc;

pub(crate) struct Store {
    pub record_feed: Arc<crate::atlas_runtime::record_fence::RecordFeedFence>,
    pub reader: Arc<se_store::SqliteReader>,
    pub reads: se_store::ReadPhasePool,
    pub writer: se_store::SqliteClient,
    pub pool: BlockingPool,
    pub generation: Generation,
    pub pending: crate::runtime::PendingWrites,
    pub mail_waits: Arc<crate::http::mail::Waits>,
    pub fault: Arc<crate::runtime::tasks::OwnershipFault>,
}
impl Store {
    pub(crate) fn for_execution(context: &crate::runtime::ExecutionContext) -> Self {
        Self {
            record_feed: context.atlas.records.clone(),
            reader: context.reader.clone(),
            reads: context.reads.clone(),
            writer: context.writer.clone(),
            pool: context.blocking.clone(),
            generation: context.generation,
            pending: context.pending_writes.clone(),
            mail_waits: context.mail_waits.clone(),
            fault: context.ownership_fault.clone(),
        }
    }
    pub async fn read<T: Send + 'static>(
        &self,
        admission: Admission,
        deadline: &Deadline,
        work: impl FnOnce(&mut Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let reads = self.reads.clone();
        let generation = self.generation;
        self.pool
            .run(BlockingClass::Foreground, deadline, move || {
                let phase = reads.read_phase().map_err(|e| store_error(&e))?;
                let owner = phase.runtime_owner().map_err(|e| store_error(&e));
                let owner = match owner {
                    Ok(Read::Present { value }) if value.generation == generation => Ok(()),
                    Ok(_) => Err(se_core::scope::unreadable(
                        "process generation",
                        "owner generation differs or is unavailable",
                    )),
                    Err(e) => Err(e),
                };
                if let Err(e) = owner {
                    return crate::runtime::executor::close_read(Err(e), phase.close());
                }
                let mut read = if matches!(admission.actor, se_store::Actor::Remote(_)) {
                    phase.into_remote_launch_snapshot(admission.clone())
                } else {
                    phase.into_snapshot(read_scope(&admission))
                }
                .map_err(|e| store_error(&e))?;
                let result = work(&mut Cx {
                    read: &mut read,
                    admission: &admission,
                });
                crate::runtime::executor::close_read(result, read.close())
            })
            .await
    }
    pub async fn commit(
        &self,
        admission: Admission,
        deadline: &Deadline,
        seed: Option<se_types::EventId>,
        work: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<AtomicBatch> + Send + 'static,
    ) -> Result<CommitReceipt> {
        let batch = self.prepare_batch(admission, deadline, seed, work).await?;
        self.submit_unpermitted(batch, deadline).await
    }
    /// Every submission without a boundary permit refuses events that require one.
    async fn submit_unpermitted(
        &self,
        batch: AtomicBatch,
        deadline: &Deadline,
    ) -> Result<CommitReceipt> {
        if batch.events.iter().any(|event| {
            matches!(
                event.body,
                se_store::EventBody::RemoteLaunchAttributed { .. }
            )
        }) {
            return Err(error(
                "remote launch reservation",
                "the original boundary permit must accompany native C1 submission",
            ));
        }
        self.submit_lifecycle(batch, deadline, None).await
    }
    pub async fn commit_if_needed(
        &self,
        admission: Admission,
        deadline: &Deadline,
        work: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<Option<AtomicBatch>>
        + Send
        + 'static,
    ) -> Result<Option<CommitReceipt>> {
        match self.prepare_batch(admission, deadline, None, work).await? {
            Some(batch) => self.submit_unpermitted(batch, deadline).await.map(Some),
            None => Ok(None),
        }
    }
    /// A remote stop's remote-actor batches enqueue under its original grant
    /// fences, so a revoked pairing admits no new stop; owner cleanup does not.
    pub async fn commit_fenced(
        &self,
        admission: Admission,
        deadline: &Deadline,
        fence: &StopFence,
        work: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<AtomicBatch> + Send + 'static,
    ) -> Result<CommitReceipt> {
        let batch = self.prepare_batch(admission, deadline, None, work).await?;
        #[cfg(feature = "remote")]
        if let Some(permit) = fence
            && matches!(batch.admission.actor, se_store::Actor::Remote(_))
        {
            return self
                .submit_lifecycle(batch, deadline, Some(permit.clone()))
                .await;
        }
        #[cfg(not(feature = "remote"))]
        let _ = fence;
        self.submit_unpermitted(batch, deadline).await
    }
    #[cfg(feature = "remote")]
    pub async fn commit_remote(
        &self,
        admission: Admission,
        deadline: &Deadline,
        seed: Option<se_types::EventId>,
        permit: crate::remote::auth::AdmissionPermit,
        work: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<AtomicBatch> + Send + 'static,
    ) -> Result<CommitReceipt> {
        let batch = self.prepare_batch(admission, deadline, seed, work).await?;
        self.submit_lifecycle(batch, deadline, Some(std::sync::Arc::new(permit)))
            .await
    }
    async fn prepare_batch<T: Send + 'static>(
        &self,
        admission: Admission,
        deadline: &Deadline,
        seed: Option<se_types::EventId>,
        work: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.read(admission, deadline, move |cx| {
            let mut facts = crate::runtime::start::allocate_facts()?;
            if let Some(seed) = seed {
                facts.event = seed;
            }
            work(&Kernel::new(facts)?, cx)
        })
        .await
    }
    async fn submit_lifecycle(
        &self,
        batch: AtomicBatch,
        deadline: &Deadline,
        #[cfg(feature = "remote")] permit: Option<
            std::sync::Arc<crate::remote::auth::AdmissionPermit>,
        >,
        #[cfg(not(feature = "remote"))] _permit: Option<()>,
    ) -> Result<CommitReceipt> {
        let request = batch.request.as_ref().ok_or_else(|| {
            se_core::scope::unreadable(
                "lifecycle commit",
                "a retained phase request key is required",
            )
        })?;
        let identity = crate::runtime::WriteIdentity {
            operation: request.intent.operation,
            natural_key: None,
            key: Some(request.key.clone()),
            natural_events: Vec::new(),
        };
        #[cfg(feature = "remote")]
        if let Some(permit) = permit {
            let fault = self.fault.clone();
            let submitted = identity.clone();
            return self
                .submit_with(batch, identity, deadline, move |writer, batch| {
                    permit.submit_ref(writer, batch, |error| {
                        fault.observe_writer(error);
                        submitted.store_error(error)
                    })
                })
                .await;
        }
        self.submit(batch, identity, deadline).await
    }
    /// Capture uses the store's immutable session/provider/native-turn identity,
    /// with the original event IDs retained across an uncertain submission.
    pub async fn commit_capture(
        &self,
        batch: AtomicBatch,
        deadline: &Deadline,
    ) -> Result<CommitReceipt> {
        let (session, provider, vendor_ref) = match batch.events.first().map(|event| &event.body) {
            Some(se_store::EventBody::SessionTurn {
                session,
                provider,
                vendor_ref,
                ..
            }) if batch.request.is_none() => (session, provider, vendor_ref),
            _ => {
                return Err(error(
                    "capture commit",
                    "a natural session turn batch is required",
                ));
            }
        };
        let identity = crate::runtime::WriteIdentity {
            operation: "hook.claude",
            natural_key: Some(format!(
                "session={session}, provider={provider:?}, turn={vendor_ref}"
            )),
            key: None,
            natural_events: batch
                .events
                .iter()
                .map(|event| event.header.event.clone())
                .collect(),
        };
        self.submit(batch, identity, deadline).await
    }
    /// Submit a batch via the shared retained submission path, separating
    /// durable commit from any secondary observer warning.
    pub(crate) async fn submit_batch_retained(
        &self,
        batch: AtomicBatch,
        identity: crate::runtime::WriteIdentity,
        deadline: &Deadline,
    ) -> Result<super::submit::RetainedCommit> {
        super::submit::enqueue_and_await_retained(
            &self.pool,
            self.writer.clone(),
            self.record_feed.clone(),
            self.pending.clone(),
            Arc::clone(&self.mail_waits),
            self.fault.clone(),
            None,
            batch,
            &identity,
            deadline,
        )
        .await
    }
    async fn submit(
        &self,
        batch: AtomicBatch,
        identity: crate::runtime::WriteIdentity,
        deadline: &Deadline,
    ) -> Result<CommitReceipt> {
        let fault = self.fault.clone();
        let submitted = identity.clone();
        self.submit_with(batch, identity, deadline, move |writer, batch| {
            writer.submit(batch).map_err(|error| {
                fault.observe_writer(&error);
                submitted.store_error(&error)
            })
        })
        .await
    }
    async fn submit_with(
        &self,
        batch: AtomicBatch,
        identity: crate::runtime::WriteIdentity,
        deadline: &Deadline,
        enqueue: impl FnOnce(
            &se_store::SqliteClient,
            AtomicBatch,
        ) -> Result<<se_store::SqliteClient as WriterClient>::Completion>
        + Send
        + 'static,
    ) -> Result<CommitReceipt> {
        let submitted = identity.clone();
        let recipients = crate::runtime::mail::recipients(&batch);
        let revocations = crate::runtime::mail::revocations(&batch);
        let writer = self.writer.clone();
        let pending = self.pending.clone();
        let mail_waits = self.mail_waits.clone();
        let runtime = self.pool.handle();
        let record_feed = self.record_feed.clone();
        let fault = self.fault.clone();
        let completion = self
            .pool
            .run_owned(deadline, move || {
                let record_write = record_feed.before_scoped_write(&batch.admission.scope)?;
                pending.register(&submitted)?;
                mail_waits.fence_remote(&revocations)?;
                match enqueue(&writer, batch) {
                    Ok(completion) => Ok(super::submit::CommitObserver {
                        completion,
                        record_write,
                        fault,
                        pending,
                        submitted,
                        mail_waits,
                        revocations,
                        recipients,
                        custody: None,
                        witness: None,
                    }
                    .spawn(&runtime)),
                    Err(error) => {
                        pending.failed_attempt(&submitted)?;
                        Err(error)
                    }
                }
            })
            .await?;
        // The retained supervisor awaits an accepted transaction even beyond
        // the client's clock. The independent observer also survives a panic
        // or dropped supervisor and keeps uncertain outcomes in PendingWrites.
        let (receipt, settled) = completion
            .await
            .map_err(|cause| identity.wait_error(error("lifecycle completion observer", cause)))?;
        match receipt {
            Ok(receipt) => {
                settled.map_err(|cause| {
                    crate::runtime::CommittedWrite {
                        operation: identity.operation.into(),
                        key: identity.key.clone(),
                        natural_events: identity.natural_events.clone(),
                        committed_events: receipt.events.clone(),
                    }
                    .response_error(cause)
                })?;
                Ok(receipt)
            }
            Err(error) => {
                let error = identity.store_error(&error);
                Err(match settled {
                    Ok(()) => error,
                    Err(cause) => error.with_cause(cause),
                })
            }
        }
    }
}

fn error(subject: &str, cause: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable(subject, &cause.to_string())
}

/// A remote stop's boundary permit, shared by each remote-actor commit of that
/// one stop. Absent for every local or owner-admitted stop.
#[cfg(feature = "remote")]
pub type StopFence = Option<std::sync::Arc<crate::remote::auth::AdmissionPermit>>;
#[cfg(not(feature = "remote"))]
pub type StopFence = Option<NoPermit>;
/// Uninhabited: without the remote feature no stop carries a boundary permit.
/// Clone without Copy keeps the fence handling identical in both builds.
#[cfg(not(feature = "remote"))]
#[derive(Clone)]
pub enum NoPermit {}
