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
                let mut read = phase
                    .into_snapshot(read_scope(&admission))
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
        let batch = self
            .read(admission, deadline, move |cx| {
                let mut facts = crate::runtime::start::allocate_facts()?;
                if let Some(seed) = seed {
                    facts.event = seed;
                }
                work(&Kernel::new(facts)?, cx)
            })
            .await?;
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
    async fn submit(
        &self,
        batch: AtomicBatch,
        identity: crate::runtime::WriteIdentity,
        deadline: &Deadline,
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
                match writer.submit(batch) {
                    Ok(completion) => Ok(runtime.spawn(async move {
                        let receipt = completion.await;
                        if receipt.as_ref().is_err_and(|e| {
                            e.code == se_store::StoreErrorCode::CommitOutcomeUnknown
                        }) {
                            record_write.uncertain();
                        } else {
                            drop(record_write);
                        }
                        if let Err(error) = &receipt {
                            fault.observe_writer(error);
                        }
                        let settled = match &receipt {
                            Ok(_) => pending.resolve(&submitted),
                            Err(error)
                                if error.code == se_store::StoreErrorCode::CommitOutcomeUnknown =>
                            {
                                Ok(())
                            }
                            Err(_) => pending.failed_attempt(&submitted),
                        };
                        let notified = if receipt.is_ok() {
                            mail_waits
                                .remote_fence_committed(&revocations)
                                .and_then(|()| mail_waits.committed(&recipients))
                                .and_then(|()| mail_waits.revoked(&revocations))
                        } else {
                            Ok(())
                        };
                        (receipt, settled.and(notified))
                    })),
                    Err(error) => {
                        fault.observe_writer(&error);
                        pending.failed_attempt(&submitted)?;
                        Err(submitted.store_error(&error))
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
